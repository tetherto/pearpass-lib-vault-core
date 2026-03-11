/** @typedef {import('bare')} */ /* global Bare */
import Autopass from 'autopass'
import b4a from 'b4a'
import fs from 'bare-fs'
import barePath from 'bare-path'
import BlindEncryptionSodium from 'blind-encryption-sodium'
import Corestore from 'corestore'
import sodium from 'sodium-native'

import { getForbiddenRoots } from './getForbiddenRoots'
import { generateTOTP, generateHOTP, parseOtpInput } from './otp/index'
import { PearPassPairer } from './pearpassPairer'
import { RateLimiter } from './rateLimiter'
import { workletLogger } from './utils/workletLogger'
import { OTP_TYPE } from '../constants/otpType'
import { getConfig } from './utils/swarm'
import { validateAndSanitizePath } from './validateAndSanitizePath'
import { defaultMirrorKeys } from '../constants/defaultBlindMirrors'

let STORAGE_PATH = null
let JOB_STORAGE_PATH = null

const JOB_FILE_NAME = 'jobs.enc'
const JOB_FILE_MAGIC = 'PPJQ'
const JOB_FILE_HEADER_SIZE = 16
const JOB_FILE_NONCE_SIZE = sodium.crypto_secretbox_NONCEBYTES

let CORE_STORE_OPTIONS = {
  readOnly: false,
  suspend: true
}

let encryptionInstance
let isEncryptionInitialized = false

let vaultsInstance
let isVaultsInitialized = false

let activeVaultInstance
let isActiveVaultInitialized = false

let listeningVaultId = null
let lastActiveVaultId = null
let lastActiveVaultEncryptionKey = null
let lastOnUpdateCallback = null

const pearpassPairer = new PearPassPairer()
const rateLimiter = new RateLimiter()

/**
 * @param {string} path
 * @returns {Promise<void>}
 * */
export const setStoragePath = async (path) => {
  const sanitizedPath = validateAndSanitizePath(path)

  // Block access to restricted system directories
  const forbiddenRoots = getForbiddenRoots()
  const isWindows = Bare.platform === 'win32'

  for (const root of forbiddenRoots) {
    // Windows paths are case-insensitive
    const normalizedRoot = isWindows ? root.toLowerCase() : root
    const normalizedPath = isWindows
      ? sanitizedPath.toLowerCase()
      : sanitizedPath
    const separator = isWindows ? '\\' : '/'

    if (
      normalizedPath === normalizedRoot ||
      normalizedPath.startsWith(normalizedRoot + separator)
    ) {
      throw new Error('Storage path points to a restricted system directory')
    }
  }

  STORAGE_PATH = sanitizedPath
}

export const setCoreStoreOptions = (coreStoreOptions) => {
  CORE_STORE_OPTIONS = {
    readOnly: false,
    ...coreStoreOptions
  }
}

/**
 * @returns {boolean}
 **/
export const getIsVaultsInitialized = () => isVaultsInitialized

/**
 * @returns {boolean}
 **/
export const getIsEncryptionInitialized = () => isEncryptionInitialized

/**
 * @returns {boolean}
 **/
export const getIsActiveVaultInitialized = () => isActiveVaultInitialized

/**
 * @returns {Autopass}
 */
export const getActiveVaultInstance = () => activeVaultInstance

/**
 * @returns {Autopass}
 **/
export const getVaultsInstance = () => vaultsInstance

/**
 * @returns {Autopass}
 **/
export const getEncryptionInstance = () => encryptionInstance

/**
 * Suspend all running Autopass instances to stop background I/O.
 * @returns {Promise<void>}
 */
export const suspendAllInstances = async () => {
  const tasks = []

  tasks.push(activeVaultInstance?.suspend?.())
  tasks.push(vaultsInstance?.suspend?.())
  tasks.push(encryptionInstance?.suspend?.())

  await Promise.allSettled(tasks)
}

/**
 * Resume all Autopass instances after background.
 * @returns {Promise<void>}
 */
export const resumeAllInstances = async () => {
  const tasks = []

  tasks.push(activeVaultInstance?.resume?.())
  tasks.push(vaultsInstance?.resume?.())
  tasks.push(encryptionInstance?.resume?.())

  await Promise.allSettled(tasks)
}

/**
 * @returns {void}
 */
const clearRestartCache = () => {
  lastActiveVaultId = null
  lastActiveVaultEncryptionKey = null
  lastOnUpdateCallback = null
}

/**
 * @param {{ clearRestartCache?: boolean }} [options]
 * @returns {Promise<void>}
 */
export const closeActiveVaultInstance = async (options) => {
  activeVaultInstance.removeAllListeners()

  await activeVaultInstance.close()

  activeVaultInstance = null
  isActiveVaultInitialized = false
  // reset listener marker so future initListener can rebind
  listeningVaultId = null

  if (options?.clearRestartCache) {
    clearRestartCache()
  }
}

/**
 *
 * @param {Autopass} instance
 * @param {Function} filterFn
 * @returns
 */
export const collectValuesByFilter = async (instance, filterFn) => {
  const stream = await instance.list()
  const results = []

  return new Promise((resolve, reject) => {
    stream.on('data', ({ key, value }) => {
      if (!value) {
        return
      }

      const parsedValue = JSON.parse(value)

      if (!parsedValue) {
        return
      }

      if (!filterFn) {
        results.push(parsedValue)
        return
      }

      if (filterFn(key)) {
        results.push(parsedValue)
      }
    })

    stream.on('end', () => resolve(results))

    stream.on('error', (error) => reject(error))
  })
}

/**
 * @param {string} path
 * @returns {string}
 */
export const buildPath = (path) => {
  if (!STORAGE_PATH) {
    throw new Error('Storage path not set')
  }

  // Join and resolve the path (handles traversal sequences like ..)
  const resolved = barePath.join(STORAGE_PATH, path)

  // Normalize both paths for comparison (handles trailing slashes, etc.)
  const normalizedRoot = barePath.normalize(STORAGE_PATH)
  const normalizedResolved = barePath.normalize(resolved)

  // Ensure the resolved path is within the storage root
  // Allow exact match or subdirectories
  if (
    normalizedResolved !== normalizedRoot &&
    !normalizedResolved.startsWith(normalizedRoot + barePath.sep)
  ) {
    throw new Error('Resolved path escapes storage root')
  }

  return normalizedResolved
}

/**
 * @param {Object} params
 * @param {string} params.path
 * @param {string | undefined} params.encryptionKey
 * @param {string | undefined} params.hashedPassword
 * @returns {Promise<Autopass>}
 */
export const initInstance = async ({ path, hashedPassword, encryptionKey }) => {
  try {
    const fullPath = buildPath(path)

    const store = new Corestore(fullPath, CORE_STORE_OPTIONS)

    if (!store) {
      throw new Error('Error creating store')
    }

    const conf = await getConfig(store)

    const instance = new Autopass(store, {
      encryptionKey: encryptionKey
        ? Buffer.from(encryptionKey, 'base64')
        : undefined,
      blindEncryption: hashedPassword
        ? new BlindEncryptionSodium(b4a.alloc(32, hashedPassword, 'utf-8'))
        : undefined,
      relayThrough: conf.current.blindRelays
    })

    await instance.ready()

    return instance
  } catch (error) {
    throw new Error(`Error initializing instance: ${error.message}`)
  }
}

/**
 * @param {Object} params
 * @param {string} params.path
 * @param {string | undefined} params.encryptionKey
 * @param {string} params.newHashedPassword
 * @param {string} params.currentHashedPassword
 * @returns {Promise<Autopass>}
 */
export const initInstanceWithNewBlindEncryption = async ({
  path,
  encryptionKey,
  newHashedPassword,
  currentHashedPassword
}) => {
  try {
    if (!currentHashedPassword || !newHashedPassword) {
      throw new Error('Old and new hashed passwords are required')
    }

    const fullPath = buildPath(path)

    const store = new Corestore(fullPath, CORE_STORE_OPTIONS)

    if (!store) {
      throw new Error('Error creating store')
    }

    const conf = await getConfig(store)

    const instance = new Autopass(store, {
      encryptionKey: encryptionKey
        ? Buffer.from(encryptionKey, 'base64')
        : undefined,
      blindEncryption: new BlindEncryptionSodium(
        b4a.alloc(32, newHashedPassword, 'utf-8'),
        b4a.alloc(32, currentHashedPassword, 'utf-8')
      ),
      relayThrough: conf.current.blindRelays
    })

    await instance.ready()

    return instance
  } catch (error) {
    throw new Error(
      `Error initializing instance with new blind encryption: ${error.message}`
    )
  }
}

/**
 * @param {Object} params
 * @param {string} params.id
 * @param {string | undefined} params.encryptionKey
 * @returns {Promise<Autopass>}
 */
export const initActiveVaultInstance = async ({ id, encryptionKey }) => {
  isActiveVaultInitialized = false

  const hashedPassword = await getHashedPassword()

  activeVaultInstance = await initInstance({
    path: `vault/${id}`,
    encryptionKey,
    hashedPassword
  })

  isActiveVaultInitialized = true

  // cache last init params for restart
  lastActiveVaultId = id
  lastActiveVaultEncryptionKey = encryptionKey

  if (lastOnUpdateCallback) {
    lastOnUpdateCallback()
  }

  return activeVaultInstance
}

/**
 * @returns {Promise<void>}
 */
export const rateLimitInit = async () => {
  if (!isEncryptionInitialized) {
    return
  }

  await rateLimiter.setStorage({
    get: encryptionGet,
    add: encryptionAdd
  })
}

/**
 * @returns {Promise<void>}
 */
export const rateLimitRecordFailure = async () => {
  await rateLimiter.recordFailure()
}

/**
 * @returns {Promise<{ isLocked: boolean, lockoutRemainingMs: number, remainingAttempts: number }>}
 */
export const getRateLimitStatus = async () => {
  await rateLimitInit()
  return await rateLimiter.getStatus()
}

/**
 * * @returns {Promise<void>}
 */
export const resetRateLimit = async () => {
  await rateLimiter.reset()
}

/**
 * @param {Object} params
 * @param {string | undefined} params.encryptionKey
 * @param {string | undefined} params.hashedPassword
 * @returns {Promise<void>}
 */
export const masterVaultInit = async ({ encryptionKey, hashedPassword }) => {
  isVaultsInitialized = false

  vaultsInstance = await initInstance({
    path: 'vaults',
    encryptionKey,
    hashedPassword
  })

  isVaultsInitialized = true
}

/**
 * @param {Object} params
 * @param {string | undefined} params.encryptionKey
 * @param {string} params.newHashedPassword
 * @param {string} params.currentHashedPassword
 * @returns {Promise<void>}
 */
export const masterVaultInitWithNewBlindEncryption = async ({
  encryptionKey,
  newHashedPassword,
  currentHashedPassword
}) => {
  isVaultsInitialized = false

  vaultsInstance = await initInstanceWithNewBlindEncryption({
    path: 'vaults',
    encryptionKey,
    newHashedPassword,
    currentHashedPassword
  })

  isVaultsInitialized = true
}

/**
 * @returns {Promise<void>}
 */
export const encryptionInit = async () => {
  isEncryptionInitialized = false

  encryptionInstance = await initInstance({
    path: 'encryption'
  })

  isEncryptionInitialized = true
}

/**
 * @param {string} key
 * @returns {Promise<any>}
 */
export const encryptionGet = async (key) => {
  if (!isEncryptionInitialized) {
    throw new Error('Encryption not initialised')
  }

  const res = await encryptionInstance.get(key)
  const { value } = res || {}
  const parsedRes = value ? JSON.parse(value) : null

  return parsedRes
}

/**
 * @param {string} key
 * @param {any} data
 * @returns {Promise<void>}
 */
export const encryptionAdd = async (key, data) => {
  if (!isEncryptionInitialized) {
    throw new Error('Encryption not initialised')
  }

  await encryptionInstance.add(key, JSON.stringify(data))
}

/**
 * @returns {Promise<void>}
 */
export const encryptionClose = async () => {
  await encryptionInstance.close()

  encryptionInstance = null
  isEncryptionInitialized = false
}

/**
 * @returns {Promise<void>}
 */
export const closeVaultsInstance = async () => {
  await vaultsInstance.close()

  vaultsInstance = null
  isVaultsInitialized = false
}

/**
 * @param {string} key
 * @param {any} data
 * @param {Buffer} file
 * @returns {Promise<void>}
 */
export const activeVaultAdd = async (key, data, file, fileName) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }
  try {
    await activeVaultInstance.add(key, JSON.stringify(data), file)
  } catch (error) {
    const err = new Error(error.message)
    if (fileName) {
      err.details = { fileName }
    }
    throw err
  }
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const vaultsGet = async (key) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }

  const res = await vaultsInstance.get(key)

  const { value, file } = res || {}
  const parsedValue = JSON.parse(value)

  if (file) {
    Object.defineProperty(parsedValue, 'file', {
      value: file,
      enumerable: true
    })
  }
  return parsedValue
}

/**
 * @param {string} key
 * @param {any} data
 * @returns {Promise<void>}
 */
export const vaultsAdd = async (key, data) => {
  if (!isVaultsInitialized) {
    throw new Error('Vault not initialised')
  }

  await vaultsInstance.add(key, JSON.stringify(data))
}

/**
 * @param {string} key
 * @returns {Promise<Buffer|null>}
 */
export const activeVaultGetFile = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const res = await activeVaultInstance.get(key)
  return res?.file || null
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const activeVaultRemoveFile = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  await activeVaultInstance.remove(key)
}

/**
 * @param {string} recordId
 * @returns {Promise<void>}
 */
export const vaultRemove = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  await activeVaultInstance.remove(key)
}

/**
 * @returns {Promise<Array<any>>}
 */
export const vaultsList = async (filterKey) => {
  if (!isVaultsInitialized) {
    throw new Error('Vaults not initialised')
  }

  return collectValuesByFilter(
    vaultsInstance,
    filterKey ? (key) => key?.startsWith(filterKey) : undefined
  )
}

/**
 * @returns {Promise<Array<any>>}
 */
export const activeVaultList = async (filterKey) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const results = await collectValuesByFilter(
    activeVaultInstance,
    filterKey ? (key) => key?.startsWith(filterKey) : undefined
  )

  if (filterKey?.startsWith('record/')) {
    return results.map(enrichRecordForClient)
  }

  return results
}

/**
 * @param {string} key
 * @returns {Promise<void>}
 */
export const activeVaultGet = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const res = await activeVaultInstance.get(key)

  if (!res || !res.value) {
    return null
  }

  const { value, file } = res || {}
  const parsedValue = JSON.parse(value)

  if (file) {
    Object.defineProperty(parsedValue, 'file', {
      value: file,
      enumerable: true
    })
  }

  if (key?.startsWith('record/')) {
    return enrichRecordForClient(parsedValue)
  }

  return parsedValue
}

/**
 * @returns {Promise<string>}
 */
export const createInvite = async () => {
  await activeVaultInstance.deleteInvite()
  const inviteCode = await activeVaultInstance.createInvite()

  const response = await activeVaultInstance.get('vault')
  const { value: vault } = response || {}
  if (!vault) {
    throw new Error('Vault not found')
  }

  const parsedVault = JSON.parse(vault)

  const vaultId = parsedVault.id

  return `${vaultId}/${inviteCode}`
}

/**
 * @returns {Promise<void>}
 */
export const deleteInvite = async () => {
  await activeVaultInstance.deleteInvite()

  const response = await activeVaultInstance.get('vault')
  const { value: vault } = response || {}

  if (!vault) {
    throw new Error('Vault not found')
  }
}

/**
 * @param {string} inviteCode
 * @returns {Promise<{ vaultId: string, encryptionKey: string }>}
 */
export const pairActiveVault = async (inviteCode) => {
  const wasActive = isActiveVaultInitialized

  try {
    const [vaultId, inviteKey] = inviteCode.split('/')
    if (isActiveVaultInitialized) {
      await closeActiveVaultInstance()
    }

    const encryptionKey = await pearpassPairer.pairInstance(
      buildPath(`vault/${vaultId}`),
      inviteKey
    )
    return { vaultId, encryptionKey }
  } catch (error) {
    if (wasActive) {
      try {
        await restartActiveVault()
      } catch {
        throw new Error(`Pairing failed: ${error.message}`)
      }
    }
    throw new Error(`Pairing failed: ${error.message}`)
  }
}

export const cancelPairActiveVault = async () => {
  await pearpassPairer.cancelPairing()
}

/**
 * @param {{
 *  vaultId: string
 *   onUpdate: () => void
 * }} options
 */
export const initListener = async ({ vaultId, onUpdate }) => {
  if (vaultId === listeningVaultId) {
    return
  }

  activeVaultInstance.removeAllListeners()

  activeVaultInstance.on('update', () => {
    onUpdate?.()
  })

  listeningVaultId = vaultId
  lastOnUpdateCallback = onUpdate
}

/**
 * @returns {Promise<void>}
 */
export const restartActiveVault = async () => {
  if (!lastActiveVaultId) {
    throw new Error('[restartActiveVault]: No previous active vault to restart')
  }

  if (isActiveVaultInitialized) {
    await closeActiveVaultInstance()
  }

  await initActiveVaultInstance({
    id: lastActiveVaultId,
    encryptionKey: lastActiveVaultEncryptionKey
  })

  if (lastOnUpdateCallback) {
    await initListener({
      vaultId: lastActiveVaultId,
      onUpdate: lastOnUpdateCallback
    })
  }
}

/**
 * @returns {Promise<void>}
 */
export const closeAllInstances = async () => {
  const closeTasks = []

  if (isActiveVaultInitialized) {
    closeTasks.push(closeActiveVaultInstance())
  }

  if (isVaultsInitialized) {
    closeTasks.push(closeVaultsInstance())
  }

  if (isEncryptionInitialized) {
    closeTasks.push(encryptionClose())
  }

  await Promise.all(closeTasks)
  clearRestartCache()
}

/**
 * Blind mirrors management
 */

/**
 * @returns {Promise<Array<{key: string, isDefault: boolean}>>}
 */
export const getBlindMirrors = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('[getBlindMirrors]: Vault not initialised')
  }

  const mirrors = await activeVaultInstance.getMirror()
  const mirrorsArray = Array.isArray(mirrors) ? mirrors : []

  try {
    const metadata = await activeVaultGet('mirror-metadata')

    const isDefault = metadata?.isDefault ?? false

    const enrichedMirrors = mirrorsArray.map((mirror) => ({
      ...mirror,
      isDefault
    }))

    return enrichedMirrors
  } catch (error) {
    throw new Error(
      `[getBlindMirrors]: Failed to get mirror metadata: ${error?.message || 'Unexpected error'}`
    )
  }
}

/**
 * @param {boolean} isDefault
 * @returns {Promise<void>}
 */
const setMirrorMetadata = async (isDefault) => {
  await activeVaultAdd('mirror-metadata', { isDefault })
}

/**
 * @param {Array<string>} mirrors
 * @returns {Promise<void>}
 */
export const addBlindMirrors = async (mirrors) => {
  if (!isActiveVaultInitialized) {
    throw new Error('[addBlindMirrors]: Vault not initialised')
  }

  if (!Array.isArray(mirrors) || mirrors.length === 0) {
    throw new Error('[addBlindMirrors]: No mirrors provided')
  }

  await Promise.all(
    mirrors.map((mirror) => activeVaultInstance.addMirror(mirror))
  )

  await setMirrorMetadata(false)
}

/**
 * @returns {Promise<void>}
 */
export const removeBlindMirror = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('[removeBlindMirror]: Vault not initialised')
  }

  if (!key) {
    throw new Error('[removeBlindMirror]: mirror key not provided!')
  }

  await activeVaultInstance.removeMirror(key)
}

/**
 * @returns {Promise<void>}
 */
export const addDefaultBlindMirrors = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('[addDefaultBlindMirrors]: Vault not initialised')
  }

  await Promise.all(
    defaultMirrorKeys.map((key) => activeVaultInstance.addMirror(key))
  )

  await setMirrorMetadata(true)
}

/**
 * Remove all blind mirrors from the active vault
 * @returns {Promise<void>}
 */
export const removeAllBlindMirrors = async () => {
  if (!isActiveVaultInitialized) {
    throw new Error('[removeAllBlindMirrors]: Vault not initialised')
  }

  const currentMirrors = await activeVaultInstance.getMirror()
  const currentKeys = (Array.isArray(currentMirrors) ? currentMirrors : []).map(
    (m) => m?.key
  )

  await Promise.all(
    currentKeys.map((key) => activeVaultInstance.removeMirror(key))
  )

  await vaultRemove('mirror-metadata')
}

export const getHashedPassword = async () => {
  const masterEncryption = await vaultsGet('masterEncryption')
  return masterEncryption?.hashedPassword
}

/**
 * Job queue storage path management
 * @param {string} path
 * @returns {void}
 */
export const setJobStoragePath = (path) => {
  const sanitizedPath = validateAndSanitizePath(path)
  JOB_STORAGE_PATH = sanitizedPath
}

/**
 * @param {string} relativePath
 * @returns {string}
 */
export const buildJobPath = (relativePath) => {
  if (!JOB_STORAGE_PATH) {
    throw new Error('JOB_STORAGE_PATH not set')
  }

  const resolved = barePath.join(JOB_STORAGE_PATH, relativePath)

  const normalizedRoot = barePath.normalize(JOB_STORAGE_PATH)
  const normalizedResolved = barePath.normalize(resolved)

  if (
    normalizedResolved !== normalizedRoot &&
    !normalizedResolved.startsWith(normalizedRoot + barePath.sep)
  ) {
    throw new Error('Path traversal detected')
  }

  return normalizedResolved
}

/**
 * Reads and decrypts the job queue file.
 * @returns {Promise<Array>}
 */
export const readAndDecryptJobFile = async () => {
  const hashedPasswordHex = await getHashedPassword()
  if (!hashedPasswordHex) {
    return []
  }

  const filePath = buildJobPath(JOB_FILE_NAME)

  let fileData
  try {
    fileData = fs.readFileSync(filePath)
  } catch (err) {
    if (err.code === 'ENOENT') {
      return []
    }
    throw err
  }

  if (fileData.length < JOB_FILE_HEADER_SIZE + JOB_FILE_NONCE_SIZE) {
    throw new Error('Job file too small')
  }

  const magic = fileData.slice(0, 4).toString('utf-8')
  if (magic !== JOB_FILE_MAGIC) {
    throw new Error('Invalid job file magic bytes')
  }

  const version = fileData.readUInt16LE(4)
  if (version !== 1) {
    throw new Error(`Unsupported job file version: ${version}`)
  }

  const nonce = fileData.slice(
    JOB_FILE_HEADER_SIZE,
    JOB_FILE_HEADER_SIZE + JOB_FILE_NONCE_SIZE
  )
  const ciphertext = fileData.slice(JOB_FILE_HEADER_SIZE + JOB_FILE_NONCE_SIZE)

  if (ciphertext.length < sodium.crypto_secretbox_MACBYTES) {
    throw new Error('Job file ciphertext too small')
  }

  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  const plaintext = sodium.sodium_malloc(
    ciphertext.length - sodium.crypto_secretbox_MACBYTES
  )

  try {
    key.write(hashedPasswordHex, 'hex')

    const opened = sodium.crypto_secretbox_open_easy(
      plaintext,
      ciphertext,
      nonce,
      key
    )

    if (!opened) {
      throw new Error('Failed to decrypt job file: authentication failed')
    }

    const json = plaintext.toString('utf-8')
    const parsed = JSON.parse(json)
    return parsed
  } finally {
    sodium.sodium_memzero(key)
    sodium.sodium_memzero(plaintext)
  }
}

/**
 * Encrypts and writes the job queue file atomically.
 * @param {Array} jobs
 * @returns {Promise<void>}
 */
export const writeAndEncryptJobFile = async (jobs) => {
  const hashedPasswordHex = await getHashedPassword()
  if (!hashedPasswordHex) {
    throw new Error('Not authenticated')
  }

  const filePath = buildJobPath(JOB_FILE_NAME)
  const tempPath = filePath + '.tmp'

  const dirPath = barePath.dirname(filePath)
  try {
    fs.mkdirSync(dirPath, { recursive: true })
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw err
    }
  }

  const jsonBuffer = Buffer.from(JSON.stringify(jobs), 'utf-8')

  const nonce = sodium.sodium_malloc(JOB_FILE_NONCE_SIZE)
  const key = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)
  const ciphertext = sodium.sodium_malloc(
    jsonBuffer.length + sodium.crypto_secretbox_MACBYTES
  )

  try {
    sodium.randombytes_buf(nonce)
    key.write(hashedPasswordHex, 'hex')

    sodium.crypto_secretbox_easy(ciphertext, jsonBuffer, nonce, key)

    const header = Buffer.alloc(JOB_FILE_HEADER_SIZE)
    header.write(JOB_FILE_MAGIC, 0, 4, 'utf-8')
    header.writeUInt16LE(1, 4)
    header.writeUInt16LE(jobs.length, 6)

    const output = Buffer.concat([
      header,
      Buffer.from(nonce),
      Buffer.from(ciphertext)
    ])

    fs.writeFileSync(tempPath, output)
    fs.renameSync(tempPath, filePath)
  } finally {
    sodium.sodium_memzero(nonce)
    sodium.sodium_memzero(key)
    sodium.sodium_memzero(ciphertext)
  }
}

/**
 * Reads a raw record from the active vault by key without enrichment.
 * @param {string} key
 * @returns {Promise<object|null>}
 */
const activeVaultGetRaw = async (key) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const res = await activeVaultInstance.get(key)
  if (!res || !res.value) return null
  return JSON.parse(res.value)
}

/**
 * Enriches a record for client consumption.
 * If the record has an OTP config, generates the current code,
 * strips the secret, and attaches `otpPublic` to the record.
 * The original record in storage is never mutated.
 * @param {object} record
 * @returns {object}
 */
export const enrichRecordForClient = (record) => {
  if (!record?.data?.otp) {
    return record
  }

  const otp = record.data.otp
  const enriched = {
    ...record,
    data: { ...record.data }
  }

  try {
    const otpPublic = {
      type: otp.type,
      digits: otp.digits,
      issuer: otp.issuer,
      label: otp.label
    }

    if (otp.type === OTP_TYPE.TOTP) {
      const { code, timeRemaining } = generateTOTP(otp)
      otpPublic.period = otp.period
      otpPublic.currentCode = code
      otpPublic.timeRemaining = timeRemaining
    } else if (otp.type === OTP_TYPE.HOTP) {
      const { code } = generateHOTP(otp)
      otpPublic.currentCode = code
    }

    delete enriched.data.otp
    enriched.otpPublic = otpPublic
  } catch (error) {
    workletLogger.error('Failed to enrich record with OTP data:', error)
    delete enriched.data.otp
  }

  return enriched
}

/**
 * Generates OTP codes for a list of record IDs.
 * @param {string[]} recordIds
 * @returns {Promise<Array<{ recordId: string, code: string, timeRemaining?: number }>>}
 */
export const generateOtpCodesByIds = async (recordIds) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const results = []

  for (const recordId of recordIds) {
    try {
      const record = await activeVaultGetRaw(`record/${recordId}`)
      if (!record?.data?.otp) continue

      const otp = record.data.otp
      if (otp.type === OTP_TYPE.TOTP) {
        const { code, timeRemaining } = generateTOTP(otp)
        results.push({ recordId, code, timeRemaining })
      } else if (otp.type === OTP_TYPE.HOTP) {
        const { code } = generateHOTP(otp)
        results.push({ recordId, code })
      }
    } catch (error) {
      workletLogger.error(
        `Failed to generate OTP code for record ${recordId}:`,
        error
      )
    }
  }

  return results
}

/**
 * Generates the next HOTP code for a record and increments the counter.
 * @param {string} recordId
 * @returns {Promise<{ code: string, counter: number }>}
 */
export const generateHotpNext = async (recordId) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const record = await activeVaultGetRaw(`record/${recordId}`)
  if (!record) {
    throw new Error('Record not found')
  }
  if (!record.data?.otp || record.data.otp.type !== OTP_TYPE.HOTP) {
    throw new Error('Record does not have HOTP configuration')
  }

  const otp = record.data.otp
  const newCounter = (otp.counter || 0) + 1

  const { code } = generateHOTP({ ...otp, counter: newCounter })

  record.data.otp = { ...otp, counter: newCounter }
  await activeVaultAdd(`record/${recordId}`, record)

  return { code, counter: newCounter }
}

/**
 * Adds an OTP configuration to a record.
 * @param {string} recordId
 * @param {string} otpInput - otpauth:// URI or raw Base32 secret
 * @returns {Promise<void>}
 */
export const addOtpToRecord = async (recordId, otpInput) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const record = await activeVaultGetRaw(`record/${recordId}`)
  if (!record?.data) {
    throw new Error('Record not found')
  }

  const otpConfig = parseOtpInput(otpInput)
  record.data.otp = otpConfig
  await activeVaultAdd(`record/${recordId}`, record)
}

/**
 * Removes OTP configuration from a record.
 * @param {string} recordId
 * @returns {Promise<void>}
 */
export const removeOtpFromRecord = async (recordId) => {
  if (!isActiveVaultInitialized) {
    throw new Error('Vault not initialised')
  }

  const record = await activeVaultGetRaw(`record/${recordId}`)
  if (!record?.data) {
    throw new Error('Record not found')
  }

  delete record.data.otp
  await activeVaultAdd(`record/${recordId}`, record)
}
