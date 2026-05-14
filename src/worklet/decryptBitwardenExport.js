import { cbc } from '@noble/ciphers/aes.js'
import { argon2id } from '@noble/hashes/argon2.js'
import crypto from 'bare-crypto'
import sodium from 'sodium-native'

import { workletLogger } from './utils/workletLogger'

const fromB64 = (s) => Buffer.from(s, 'base64')

// Defensive upper bounds on KDF parameters that arrive straight from the
// (attacker-controlled) export JSON. The threat model is "user opens a
// malicious export", so a crafted file with absurd iterations/memory would
// otherwise hard-block the worklet thread or OOM the process. Fail fast
// with a clear reason instead.
const MAX_PBKDF2_ITERATIONS = 2_000_000
const MAX_ARGON2_ITERATIONS = 100
const MAX_ARGON2_MEMORY_MIB = 1024
const MAX_ARGON2_PARALLELISM = 16

// Stable error codes so the UI can distinguish "wrong password" from
// "unsupported export format" without string-matching the message.
const bwError = (code, message) => {
  const err = new Error(message)
  err.code = code
  return err
}

// Copy a transient secret (a plain Buffer / Uint8Array produced by
// bare-crypto or @noble) into libsodium secure memory, then wipe the
// original so the only surviving copy lives in a buffer we can memzero.
const toSecureBuffer = (bytes) => {
  const secure = sodium.sodium_malloc(bytes.length)
  secure.set(bytes)
  bytes.fill(0)
  return secure
}

const deriveMasterKey = ({
  kdfType,
  password,
  salt,
  kdfIterations,
  kdfMemory,
  kdfParallelism
}) => {
  // Bitwarden treats the base64 salt string as raw UTF-8 bytes — it does NOT
  // base64-decode it.
  const passwordBuf = toSecureBuffer(Buffer.from(password, 'utf8'))
  const saltBuf = toSecureBuffer(Buffer.from(salt, 'utf8'))

  workletLogger.info(
    `[bw-worklet] deriveMasterKey kdfType=${kdfType} iters=${kdfIterations} pwLen=${passwordBuf.length} saltLen=${saltBuf.length}`
  )

  try {
    if (kdfType === 0) {
      if (!(kdfIterations > 0) || kdfIterations > MAX_PBKDF2_ITERATIONS) {
        throw bwError(
          'BW_UNSUPPORTED_KDF',
          `Unsupported KDF type: PBKDF2 iterations out of range (${kdfIterations})`
        )
      }
      const t = Date.now()
      const derived = crypto.pbkdf2Sync(
        passwordBuf,
        saltBuf,
        kdfIterations,
        32,
        'sha256'
      )
      workletLogger.info(`[bw-worklet] PBKDF2 done in ${Date.now() - t}ms`)
      return toSecureBuffer(derived)
    }

    if (kdfType === 1) {
      const iterations = kdfIterations
      const memoryMib = kdfMemory ?? 64
      const parallelism = kdfParallelism ?? 4
      if (
        !(iterations > 0) ||
        iterations > MAX_ARGON2_ITERATIONS ||
        !(memoryMib > 0) ||
        memoryMib > MAX_ARGON2_MEMORY_MIB ||
        !(parallelism > 0) ||
        parallelism > MAX_ARGON2_PARALLELISM
      ) {
        throw bwError(
          'BW_UNSUPPORTED_KDF',
          `Unsupported KDF type: Argon2id parameters out of range (t=${iterations} memMiB=${memoryMib} p=${parallelism})`
        )
      }
      // Bitwarden pre-hashes the salt with SHA-256 (32 bytes) and defaults to
      // parallelism=4. libsodium's crypto_pwhash requires 16-byte salts and
      // pins p=1, so it cannot produce a matching key. Use @noble/hashes/argon2
      // here — pure JS, but the worklet runs on Bare's V8 with JIT.
      const saltHashed = crypto.createHash('sha256').update(saltBuf).digest()
      const t = Date.now()
      const derived = argon2id(passwordBuf, saltHashed, {
        t: iterations,
        m: memoryMib * 1024,
        p: parallelism,
        dkLen: 32
      })
      workletLogger.info(`[bw-worklet] Argon2id done in ${Date.now() - t}ms`)
      return toSecureBuffer(derived)
    }

    throw bwError('BW_UNSUPPORTED_KDF', `Unsupported KDF type: ${kdfType}`)
  } finally {
    sodium.sodium_memzero(passwordBuf)
    sodium.sodium_memzero(saltBuf)
    sodium.sodium_free(passwordBuf)
    sodium.sodium_free(saltBuf)
  }
}

const hkdfExpandOneBlock = (prk, info) => {
  // Bitwarden only needs 32-byte outputs → single HMAC block, no loop.
  const h = crypto.createHmac('sha256', prk)
  h.update(info)
  h.update(Buffer.from([0x01]))
  return h.digest()
}

const parseCipherString = (s) => {
  if (typeof s !== 'string' || s.length === 0) {
    throw bwError(
      'BW_UNSUPPORTED_CIPHER',
      'Unsupported CipherString type: empty input'
    )
  }
  const dot = s.indexOf('.')
  if (dot < 0) {
    throw bwError(
      'BW_UNSUPPORTED_CIPHER',
      'Unsupported CipherString type: missing type prefix'
    )
  }
  const type = parseInt(s.slice(0, dot), 10)
  if (type !== 2) {
    throw bwError(
      'BW_UNSUPPORTED_CIPHER',
      `Unsupported CipherString type: ${type}`
    )
  }
  const p1 = s.indexOf('|', dot + 1)
  const p2 = s.indexOf('|', p1 + 1)
  if (p1 < 0 || p2 < 0) {
    throw bwError(
      'BW_UNSUPPORTED_CIPHER',
      'Unsupported CipherString type: expected iv|ct|mac segments'
    )
  }
  const iv = fromB64(s.slice(dot + 1, p1))
  const ct = fromB64(s.slice(p1 + 1, p2))
  const mac = fromB64(s.slice(p2 + 1))
  if (iv.length !== 16) {
    throw bwError(
      'BW_UNSUPPORTED_CIPHER',
      `Unsupported CipherString type: expected 16-byte IV, got ${iv.length}`
    )
  }
  if (mac.length !== 32) {
    throw bwError(
      'BW_UNSUPPORTED_CIPHER',
      `Unsupported CipherString type: expected 32-byte MAC, got ${mac.length}`
    )
  }
  return { iv, ct, mac }
}

export const decryptBitwardenExport = ({
  password,
  salt,
  kdfType,
  kdfIterations,
  kdfMemory,
  kdfParallelism,
  cipherString
}) => {
  workletLogger.info(
    `[bw-worklet] received kdfType=${kdfType} iters=${kdfIterations} mem=${kdfMemory} para=${kdfParallelism} saltLen=${salt?.length} cipherPrefix=${cipherString?.slice(0, 30)} cipherLen=${cipherString?.length}`
  )

  const masterKey = deriveMasterKey({
    kdfType,
    password,
    salt,
    kdfIterations,
    kdfMemory,
    kdfParallelism
  })

  let encKey
  let macKey
  try {
    encKey = toSecureBuffer(hkdfExpandOneBlock(masterKey, Buffer.from('enc')))
    macKey = toSecureBuffer(hkdfExpandOneBlock(masterKey, Buffer.from('mac')))

    const { iv, ct, mac } = parseCipherString(cipherString)
    workletLogger.info(
      `[bw-worklet] parsed ivLen=${iv.length} ctLen=${ct.length} macLen=${mac.length}`
    )

    const expected = crypto
      .createHmac('sha256', macKey)
      .update(iv)
      .update(ct)
      .digest()

    if (
      expected.length !== mac.length ||
      !sodium.sodium_memcmp(expected, mac)
    ) {
      workletLogger.info('[bw-worklet] MAC mismatch -> Incorrect password')
      throw bwError('BW_BAD_PASSWORD', 'Incorrect password')
    }

    workletLogger.info('[bw-worklet] AES-CBC: start decrypt')
    const tAes = Date.now()
    const plain = Buffer.from(cbc(encKey, iv).decrypt(ct))
    workletLogger.info(
      `[bw-worklet] AES-CBC done in ${Date.now() - tAes}ms plainLen=${plain.length}`
    )

    try {
      return plain.toString('utf8')
    } finally {
      plain.fill(0)
    }
  } finally {
    sodium.sodium_memzero(masterKey)
    sodium.sodium_free(masterKey)
    if (encKey) {
      sodium.sodium_memzero(encKey)
      sodium.sodium_free(encKey)
    }
    if (macKey) {
      sodium.sodium_memzero(macKey)
      sodium.sodium_free(macKey)
    }
  }
}
