jest.mock('./utils/workletLogger', () => ({
  workletLogger: {
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

import { randomBytes } from 'crypto'

import { gcm } from '@noble/ciphers/aes.js'
import { scrypt } from '@noble/hashes/scrypt.js'

import { decryptAegisExport } from './decryptAegisExport'

const toUtf8 = (s) => new TextEncoder().encode(s)
const toHex = (u8) => Buffer.from(u8).toString('hex')
const toBase64 = (u8) => Buffer.from(u8).toString('base64')
const split = (ctTag) => ({
  ct: ctTag.slice(0, ctTag.length - 16),
  tag: ctTag.slice(ctTag.length - 16)
})

// Builds an encrypted Aegis export in the real vault format. Uses small scrypt
// params (N=1024) so the KDF is fast in CI; the worklet reads the slot params,
// so the code under test runs identically to Aegis's production N=32768. Returns
// just the { slots, params, db } the worklet method consumes.
function buildEncryptedAegis(db, password, { biometricOnly = false } = {}) {
  const masterKey = new Uint8Array(randomBytes(32))
  const dbNonce = new Uint8Array(randomBytes(12))
  const { ct: dbCt, tag: dbTag } = split(
    gcm(masterKey, dbNonce).encrypt(toUtf8(JSON.stringify(db)))
  )

  const slots = []
  if (biometricOnly) {
    slots.push({ type: 2, uuid: 'bio' })
  } else {
    const salt = new Uint8Array(randomBytes(32))
    const n = 1024
    const r = 8
    const p = 1
    const slotKey = scrypt(toUtf8(password), salt, { N: n, r, p, dkLen: 32 })
    const keyNonce = new Uint8Array(randomBytes(12))
    const { ct: keyCt, tag: keyTag } = split(
      gcm(slotKey, keyNonce).encrypt(masterKey)
    )
    slots.push({
      type: 1,
      uuid: 's1',
      key: toHex(keyCt),
      key_params: { nonce: toHex(keyNonce), tag: toHex(keyTag) },
      n,
      r,
      p,
      salt: toHex(salt)
    })
  }

  return {
    slots,
    params: { nonce: toHex(dbNonce), tag: toHex(dbTag) },
    db: toBase64(dbCt)
  }
}

const DB = {
  version: 3,
  entries: [
    {
      type: 'totp',
      name: 'alice@example.com',
      issuer: 'GitHub',
      info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 }
    }
  ]
}

describe('decryptAegisExport', () => {
  it('decrypts an encrypted export and returns the plaintext db JSON', () => {
    const enc = buildEncryptedAegis(DB, 'hunter2')
    const plaintext = decryptAegisExport({ ...enc, password: 'hunter2' })
    expect(JSON.parse(plaintext)).toEqual(DB)
  })

  it('throws on a wrong password', () => {
    const enc = buildEncryptedAegis(DB, 'hunter2')
    expect(() => decryptAegisExport({ ...enc, password: 'wrong' })).toThrow(
      /incorrect password/i
    )
  })

  it('throws when no password is provided', () => {
    const enc = buildEncryptedAegis(DB, 'hunter2')
    expect(() => decryptAegisExport({ ...enc, password: '' })).toThrow(
      /password is required/i
    )
  })

  it('throws for a biometric-only export', () => {
    const enc = buildEncryptedAegis(DB, 'hunter2', { biometricOnly: true })
    expect(() => decryptAegisExport({ ...enc, password: 'hunter2' })).toThrow(
      /biometrics/i
    )
  })

  it('throws on malformed vault params', () => {
    const enc = buildEncryptedAegis(DB, 'hunter2')
    expect(() =>
      decryptAegisExport({
        ...enc,
        params: { nonce: 'zz', tag: 'zz' },
        password: 'hunter2'
      })
    ).toThrow(/malformed vault parameters/i)
  })

  it('rejects scrypt parameters outside the safe range', () => {
    const enc = buildEncryptedAegis(DB, 'hunter2')
    enc.slots[0].n = 3 // not a power of two
    expect(() => decryptAegisExport({ ...enc, password: 'hunter2' })).toThrow(
      /scrypt parameters/i
    )
  })
})
