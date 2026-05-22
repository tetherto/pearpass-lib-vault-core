import { gcm } from '@noble/ciphers/aes.js'
import { scrypt } from '@noble/hashes/scrypt.js'
import sodium from 'sodium-native'

import { workletLogger } from './utils/workletLogger'

const AEGIS_SLOT_PASSWORD = 1

const KEY_LENGTH = 32
const NONCE_LENGTH = 12
const TAG_LENGTH = 16

// Defensive upper bounds on the scrypt parameters. They arrive straight from
// the (attacker-controlled) export JSON — threat model is "user opens a
// malicious Aegis export" — so a crafted file with absurd N/r would otherwise
// hard-block the worklet thread or OOM the process (scrypt memory ≈
// 128 * N * r bytes). Fail fast with a clear reason instead. Aegis defaults are
// N=32768, r=8, p=1.
const MAX_SCRYPT_N = 1 << 20 // 1,048,576
const MAX_SCRYPT_R = 32
const MAX_SCRYPT_P = 16
const MAX_SCRYPT_MEMORY_BYTES = 1 << 30 // 1 GiB

const aegisError = (code, message) => {
  const err = new Error(message)
  err.code = code
  return err
}

const toSecureBuffer = (bytes) => {
  const secure = sodium.sodium_malloc(bytes.length)
  secure.set(bytes)
  bytes.fill(0)
  return secure
}

const HEX_RE = /^[0-9a-fA-F]+$/
const isHex = (v) =>
  typeof v === 'string' && v.length > 0 && v.length % 2 === 0 && HEX_RE.test(v)
const isHexBytes = (v, bytes) => isHex(v) && v.length === bytes * 2
const isPow2 = (n) => Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0

const fromHex = (hex) => Buffer.from(hex, 'hex')

// AES-256-GCM decrypt. Aegis stores the ciphertext and the 16-byte auth tag
// separately, while @noble/ciphers expects them concatenated.
const decryptGcm = (key, nonce, ciphertext, tag) =>
  Buffer.from(gcm(key, nonce).decrypt(Buffer.concat([ciphertext, tag])))

const validatePasswordSlot = (slot) => {
  if (
    !isHex(slot?.salt) ||
    !isHex(slot?.key) ||
    !isHexBytes(slot?.key_params?.nonce, NONCE_LENGTH) ||
    !isHexBytes(slot?.key_params?.tag, TAG_LENGTH)
  ) {
    throw aegisError(
      'AEGIS_INVALID_PAYLOAD',
      'Corrupted Aegis export: malformed encryption slot'
    )
  }
  if (
    !isPow2(slot.n) ||
    slot.n > MAX_SCRYPT_N ||
    !Number.isInteger(slot.r) ||
    slot.r <= 0 ||
    slot.r > MAX_SCRYPT_R ||
    !Number.isInteger(slot.p) ||
    slot.p <= 0 ||
    slot.p > MAX_SCRYPT_P ||
    128 * slot.n * slot.r > MAX_SCRYPT_MEMORY_BYTES
  ) {
    throw aegisError(
      'AEGIS_UNSUPPORTED_KDF',
      `Unsupported Aegis scrypt parameters (n=${slot?.n} r=${slot?.r} p=${slot?.p})`
    )
  }
}

/**
 *
 * @returns {Buffer} sodium secure buffer holding the 32-byte master key — caller frees
 * @throws {Error} AEGIS_BAD_PASSWORD if the password is wrong for this slot,
 *   AEGIS_INVALID_PAYLOAD / AEGIS_UNSUPPORTED_KDF if the slot is structurally bad
 */
const masterKeyFromSlot = (slot, password) => {
  validatePasswordSlot(slot)

  const passwordBuf = toSecureBuffer(Buffer.from(password, 'utf8'))
  let derivedKey
  try {
    const t = Date.now()
    derivedKey = toSecureBuffer(
      scrypt(passwordBuf, fromHex(slot.salt), {
        N: slot.n,
        r: slot.r,
        p: slot.p,
        dkLen: KEY_LENGTH
      })
    )
    workletLogger.info(
      `[aegis-worklet] scrypt N=${slot.n} r=${slot.r} p=${slot.p} done in ${Date.now() - t}ms`
    )
  } finally {
    sodium.sodium_memzero(passwordBuf)
    sodium.sodium_free(passwordBuf)
  }

  try {
    const masterKey = decryptGcm(
      derivedKey,
      fromHex(slot.key_params.nonce),
      fromHex(slot.key),
      fromHex(slot.key_params.tag)
    )
    return toSecureBuffer(masterKey)
  } catch {
    throw aegisError('AEGIS_BAD_PASSWORD', 'Incorrect password')
  } finally {
    sodium.sodium_memzero(derivedKey)
    sodium.sodium_free(derivedKey)
  }
}

/**
 * @param {Object} params
 * @param {Object[]} params.slots    - the export's `header.slots`
 * @param {{ nonce: string, tag: string }} params.params - the export's `header.params` (hex)
 * @param {string} params.db         - base64-encoded vault ciphertext (the export's `db`)
 * @param {string} params.password   - the Aegis export password
 * @returns {string} the decrypted `db` as a UTF-8 JSON string
 * @throws {Error} biometric-only export, missing/wrong password, or corrupted export
 */
export const decryptAegisExport = ({ slots, params, db, password }) => {
  const passwordSlots = Array.isArray(slots)
    ? slots.filter((s) => s?.type === AEGIS_SLOT_PASSWORD)
    : []

  if (passwordSlots.length === 0) {
    throw aegisError(
      'AEGIS_UNSUPPORTED',
      'This Aegis export is protected with biometrics, not a password. Re-export from Aegis using a password.'
    )
  }
  if (!password) {
    throw aegisError(
      'AEGIS_PASSWORD_REQUIRED',
      'This Aegis export is encrypted. A password is required.'
    )
  }
  if (
    !isHexBytes(params?.nonce, NONCE_LENGTH) ||
    !isHexBytes(params?.tag, TAG_LENGTH)
  ) {
    throw aegisError(
      'AEGIS_INVALID_PAYLOAD',
      'Corrupted Aegis export: malformed vault parameters'
    )
  }

  workletLogger.info(
    `[aegis-worklet] decryptAegisExport passwordSlots=${passwordSlots.length}`
  )

  let masterKey = null
  let structuralError = null
  for (const slot of passwordSlots) {
    try {
      masterKey = masterKeyFromSlot(slot, password)
      break
    } catch (error) {
      if (error.code === 'AEGIS_BAD_PASSWORD') continue
      structuralError = error
    }
  }

  if (!masterKey) {
    throw (
      structuralError ?? aegisError('AEGIS_BAD_PASSWORD', 'Incorrect password')
    )
  }

  try {
    let plaintext
    try {
      plaintext = decryptGcm(
        masterKey,
        fromHex(params.nonce),
        Buffer.from(db, 'base64'),
        fromHex(params.tag)
      )
    } catch {
      throw aegisError(
        'AEGIS_INVALID_PAYLOAD',
        'Decryption failed — corrupted Aegis export'
      )
    }
    try {
      return plaintext.toString('utf8')
    } finally {
      plaintext.fill(0)
    }
  } finally {
    sodium.sodium_memzero(masterKey)
    sodium.sodium_free(masterKey)
  }
}
