// bare-crypto is a Bare-runtime native addon that cannot load under Node/Jest.
// Node's built-in `crypto` exposes an identical pbkdf2Sync / createHmac /
// createHash surface and produces identical output for these standard
// primitives, so the crypto behaviour exercised here is real — only the
// module loader is redirected. sodium-native and @noble run unmocked.
jest.mock('bare-crypto', () => require('crypto'))

jest.mock('./utils/workletLogger', () => ({
  workletLogger: {
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

import { decryptBitwardenExport } from './decryptBitwardenExport'

// Known-answer vectors generated with the exact algorithm the module
// implements (PBKDF2/Argon2id -> HKDF-Expand -> AES-256-CBC + HMAC-SHA256),
// using Node crypto + @noble. Decrypting them must reproduce EXPECTED_PLAINTEXT.
const PASSWORD = 'correct horse battery staple'
const SALT = 'jane.doe@example.com'
const EXPECTED_PLAINTEXT =
  '{"encrypted":false,"folders":[],"items":[{"id":"a1","type":1,"name":"Example Login","login":{"username":"jane","password":"hunter2"}}]}'

const PBKDF2_VECTOR = {
  password: PASSWORD,
  salt: SALT,
  kdfType: 0,
  kdfIterations: 100000,
  cipherString:
    '2.ABEiM0RVZneImaq7zN3u/w==|Un9ItCKAY/JooUc6FaVUxbhvg/i0jusfSejD/tytiNU+sqB+KXMeQo9jiExxv9IOI3JP2tXzIW/Ch6mQJ1fle35HZaavB1lGA4KnSav6hKXVO9wagQonndBZAjIzI+WMmhX21vGA5/zMYa8iLBcOwcpr58Ehvmn34HpZUX7+I2mTDiI3rzNDrb8h9w4+wHyF|YRUfEUT1wKvVPiXm7eS18yHAmSjktCyR8BdBDkH6QKM='
}

// Argon2id params are deliberately small (the worklet reads them from the
// export JSON anyway) so the pure-JS @noble derivation stays fast under Jest.
const ARGON2_VECTOR = {
  password: PASSWORD,
  salt: SALT,
  kdfType: 1,
  kdfIterations: 2,
  kdfMemory: 8,
  kdfParallelism: 1,
  cipherString:
    '2./+7dzLuqmYh3ZlVEMyIRAA==|L2yYvkn66ZpHWq+smXg82ExQiohSX/Cn/u7DucNyUh0DRiGGjfD0Ot9qCsqNJ4ph9odC8ok9V9AoZeNKsZgLQaCVq1Plc3VZ4l2Z9LcH7HeIHLtE2kHTAW0fWogw5ZvvP181KkJix5AZMZZRZn6KpEbrdy9gJTbS5xMOtmVBujUEcIiFgIyDJ0tvB0TQYUdF|n2Z8E/ief4v1ZbQFR3J2pTe3M2H530GMPHqHBLlmpQE='
}

// Flip the first byte of a cipherString segment (0=iv, 1=ct, 2=mac), keeping
// the segment length intact so the failure is the MAC check, not parsing.
const tamperSegment = (cipherString, index) => {
  const dot = cipherString.indexOf('.')
  const segs = cipherString.slice(dot + 1).split('|')
  const buf = Buffer.from(segs[index], 'base64')
  buf[0] ^= 0xff
  segs[index] = buf.toString('base64')
  return `${cipherString.slice(0, dot)}.${segs.join('|')}`
}

describe('decryptBitwardenExport', () => {
  describe('happy path', () => {
    it('decrypts a PBKDF2 (kdfType=0) export vector', () => {
      expect(decryptBitwardenExport(PBKDF2_VECTOR)).toBe(EXPECTED_PLAINTEXT)
    })

    it('decrypts an Argon2id (kdfType=1) export vector', () => {
      expect(decryptBitwardenExport(ARGON2_VECTOR)).toBe(EXPECTED_PLAINTEXT)
    })
  })

  describe('authentication failures (-> Incorrect password)', () => {
    it('throws on a wrong password', () => {
      expect(() =>
        decryptBitwardenExport({ ...PBKDF2_VECTOR, password: 'wrong password' })
      ).toThrow('Incorrect password')
    })

    it('exposes a stable BW_BAD_PASSWORD code on wrong password', () => {
      expect.assertions(1)
      try {
        decryptBitwardenExport({ ...PBKDF2_VECTOR, password: 'wrong password' })
      } catch (err) {
        expect(err.code).toBe('BW_BAD_PASSWORD')
      }
    })

    it('throws when the IV has been tampered with', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: tamperSegment(PBKDF2_VECTOR.cipherString, 0)
        })
      ).toThrow('Incorrect password')
    })

    it('throws when the ciphertext has been tampered with', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: tamperSegment(PBKDF2_VECTOR.cipherString, 1)
        })
      ).toThrow('Incorrect password')
    })

    it('throws when the MAC has been tampered with', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: tamperSegment(PBKDF2_VECTOR.cipherString, 2)
        })
      ).toThrow('Incorrect password')
    })
  })

  describe('unsupported KDF type', () => {
    it('throws on a kdfType other than 0 or 1', () => {
      expect(() =>
        decryptBitwardenExport({ ...PBKDF2_VECTOR, kdfType: 2 })
      ).toThrow('Unsupported KDF type')
    })

    it('exposes a stable BW_UNSUPPORTED_KDF code', () => {
      expect.assertions(1)
      try {
        decryptBitwardenExport({ ...PBKDF2_VECTOR, kdfType: 2 })
      } catch (err) {
        expect(err.code).toBe('BW_UNSUPPORTED_KDF')
      }
    })

    it('rejects out-of-range PBKDF2 iterations instead of hanging', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          kdfIterations: 10_000_000_000
        })
      ).toThrow('Unsupported KDF type')
    })

    it('rejects out-of-range Argon2id memory instead of OOMing', () => {
      expect(() =>
        decryptBitwardenExport({ ...ARGON2_VECTOR, kdfMemory: 16_777_216 })
      ).toThrow('Unsupported KDF type')
    })
  })

  describe('unsupported CipherString', () => {
    it('throws on a leading type other than 2', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: `0.${PBKDF2_VECTOR.cipherString.slice(2)}`
        })
      ).toThrow('Unsupported CipherString type')
    })

    it('exposes a stable BW_UNSUPPORTED_CIPHER code', () => {
      expect.assertions(1)
      try {
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: `0.${PBKDF2_VECTOR.cipherString.slice(2)}`
        })
      } catch (err) {
        expect(err.code).toBe('BW_UNSUPPORTED_CIPHER')
      }
    })

    it('throws on a cipherString with no type prefix', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: 'not-a-cipher-string'
        })
      ).toThrow('Unsupported CipherString type')
    })

    it('throws on a cipherString missing the iv|ct|mac segments', () => {
      expect(() =>
        decryptBitwardenExport({
          ...PBKDF2_VECTOR,
          cipherString: '2.onlyonesegment'
        })
      ).toThrow('Unsupported CipherString type')
    })
  })
})
