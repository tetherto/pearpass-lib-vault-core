import { gcm } from '@noble/ciphers/aes.js'
import { argon2id } from '@noble/hashes/argon2.js'
import sodium from 'sodium-native'

import { workletLogger } from './utils/workletLogger'

// Proton Authenticator v1 export: fixed Argon2id parameters sourced from
// protonpass/proton-pass-common password_exporter.rs
const ARGON2_M_COST = 19456 // KiB (19 MiB)
const ARGON2_T_COST = 2
const ARGON2_P_COST = 1
const KEY_LENGTH = 32
const NONCE_LENGTH = 12
const TAG_LENGTH = 16
// from proton-pass-common crypto.rs EncryptionTag::PasswordExport
const GCM_AAD = Buffer.from('proton.authenticator.export.v1', 'utf8')

const protonError = (code, message) => {
  const err = new Error(message)
  err.code = code
  return err
}

// Copy transient key material into libsodium secure memory, then wipe origin.
const toSecureBuffer = (bytes) => {
  const secure = sodium.sodium_malloc(bytes.length)
  secure.set(bytes)
  bytes.fill(0)
  return secure
}

// Dev helper: log the nonce / ciphertext / tag breakdown of a raw content frame.
export const debugFrame = (buffer) => {
  if (buffer.length < NONCE_LENGTH + TAG_LENGTH) {
    workletLogger.info(
      `[proton-debug] buffer too short: ${buffer.length} bytes`
    )
    return
  }
  const nonce = buffer.slice(0, NONCE_LENGTH)
  const body = buffer.slice(NONCE_LENGTH)
  const ct = body.slice(0, body.length - TAG_LENGTH)
  const tag = body.slice(body.length - TAG_LENGTH)
  workletLogger.info(
    `[proton-debug] totalLen=${buffer.length} nonce=${nonce.toString('hex')} ctLen=${ct.length} tag=${tag.toString('hex')}`
  )
}

// Returns a sodium_malloc'd secure buffer — caller must free.
const deriveKey = (password, salt) => {
  const passwordBuf = toSecureBuffer(Buffer.from(password, 'utf8'))
  const saltBuf = toSecureBuffer(Buffer.from(salt))

  workletLogger.info(
    `[proton-worklet] deriveKey argon2id m=${ARGON2_M_COST} t=${ARGON2_T_COST} p=${ARGON2_P_COST} saltLen=${saltBuf.length}`
  )

  try {
    const t = Date.now()
    const derived = argon2id(passwordBuf, saltBuf, {
      t: ARGON2_T_COST,
      m: ARGON2_M_COST,
      p: ARGON2_P_COST,
      dkLen: KEY_LENGTH
    })
    workletLogger.info(`[proton-worklet] Argon2id done in ${Date.now() - t}ms`)
    return toSecureBuffer(derived)
  } finally {
    sodium.sodium_memzero(passwordBuf)
    sodium.sodium_memzero(saltBuf)
    sodium.sodium_free(passwordBuf)
    sodium.sodium_free(saltBuf)
  }
}

// Decrypt frame = [nonce(12) || ciphertext || tag(16)] with AES-256-GCM + AAD.
const decryptAESGCM = (key, frame) => {
  const nonce = frame.slice(0, NONCE_LENGTH)
  const ciphertextWithTag = frame.slice(NONCE_LENGTH)

  workletLogger.info(
    `[proton-worklet] decryptAESGCM nonce=${nonce.toString('hex').slice(0, 8)}… ctWithTagLen=${ciphertextWithTag.length}`
  )

  try {
    return Buffer.from(gcm(key, nonce, GCM_AAD).decrypt(ciphertextWithTag))
  } catch {
    throw protonError('PROTON_BAD_PASSWORD', 'Incorrect password')
  }
}

/**
 * Decrypt a Proton Authenticator password-protected export.
 *
 * @param {{ version: number, salt: string, content: string }} input
 * @param {string} password
 * @returns {string} Decrypted UTF-8 JSON string
 */
export const decryptProtonExport = (input, password) => {
  const { version, salt, content } = input

  if (version !== 1) {
    throw protonError(
      'PROTON_UNSUPPORTED_VERSION',
      `Unsupported export version: ${version}`
    )
  }

  const saltBuf = Buffer.from(salt, 'base64')
  const frame = Buffer.from(content, 'base64')

  workletLogger.info(
    `[proton-worklet] decryptProtonExport version=${version} saltLen=${saltBuf.length} frameLen=${frame.length}`
  )

  if (frame.length < NONCE_LENGTH + TAG_LENGTH) {
    throw protonError(
      'PROTON_INVALID_PAYLOAD',
      `Content frame too short: ${frame.length} bytes`
    )
  }

  const key = deriveKey(password, saltBuf)
  try {
    const plain = decryptAESGCM(key, frame)
    try {
      return plain.toString('utf8')
    } finally {
      plain.fill(0)
    }
  } finally {
    sodium.sodium_memzero(key)
    sodium.sodium_free(key)
  }
}
