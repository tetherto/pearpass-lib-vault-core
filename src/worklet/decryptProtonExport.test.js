// Argon2id at Proton's production parameters (m=19456 KiB, t=2, p=1) takes
// ~400ms per invocation in @noble's pure-JS implementation. Raise the timeout
// so the suite doesn't flake on a busy CI runner.
jest.setTimeout(30_000)

jest.mock('./utils/workletLogger', () => ({
  workletLogger: {
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

import { decryptProtonExport } from './decryptProtonExport'

// Known-answer vector generated with gen-proton-vector.mjs using the exact
// same @noble/ciphers + @noble/hashes stack that the production module uses.
const PASSWORD = 'correct horse battery staple'
const EXPECTED_PLAINTEXT =
  '{"version":1,"user_data":{"totp":[{"name":"GitHub","issuer":"GitHub","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}]}}'

const VECTOR = {
  version: 1,
  salt: 'cHJvdG9udGVzdHNh',
  content:
    'cHJvdG9ubm9uY2UxWnLLvZZ9+YuApaQwj1eUZKDRL6yl8mpaak5wF0L26osXezPK+bKIZkxwpg8ZIbgCwxQaqBYXqzKLX3iR3Agz8SSSoQ80cYTlvXU8UooWskqe7xJ5Zs1MEgXm5NPIgHsSTRl+ODmlKB+zHzNG3bSimS0tLYs1SlLrze8usFoUUclY2My0CWRZ6pHW+Et5Rf6OZdzGGHV84g3mBhmB+SY='
}

describe('decryptProtonExport', () => {
  describe('happy path', () => {
    it('decrypts a v1 export and returns the raw JSON string', () => {
      expect(decryptProtonExport(VECTOR, PASSWORD)).toBe(EXPECTED_PLAINTEXT)
    })
  })

  describe('authentication failures', () => {
    it('throws on a wrong password', () => {
      expect(() => decryptProtonExport(VECTOR, 'wrong password')).toThrow(
        'Incorrect password'
      )
    })

    it('exposes a stable PROTON_BAD_PASSWORD code on wrong password', () => {
      expect.assertions(1)
      try {
        decryptProtonExport(VECTOR, 'wrong password')
      } catch (err) {
        expect(err.code).toBe('PROTON_BAD_PASSWORD')
      }
    })

    it('throws when content has been tampered with', () => {
      const frame = Buffer.from(VECTOR.content, 'base64')
      // Flip a byte in the ciphertext region (after the 12-byte nonce)
      frame[13] ^= 0xff
      const tampered = { ...VECTOR, content: frame.toString('base64') }
      expect(() => decryptProtonExport(tampered, PASSWORD)).toThrow(
        'Incorrect password'
      )
    })
  })

  describe('unsupported version', () => {
    it('throws on version !== 1', () => {
      expect(() =>
        decryptProtonExport({ ...VECTOR, version: 2 }, PASSWORD)
      ).toThrow('Unsupported export version')
    })

    it('exposes a stable PROTON_UNSUPPORTED_VERSION code', () => {
      expect.assertions(1)
      try {
        decryptProtonExport({ ...VECTOR, version: 2 }, PASSWORD)
      } catch (err) {
        expect(err.code).toBe('PROTON_UNSUPPORTED_VERSION')
      }
    })
  })

  describe('malformed payload', () => {
    it('throws on content that is too short to contain a nonce and tag', () => {
      const tiny = { ...VECTOR, content: Buffer.alloc(10).toString('base64') }
      expect(() => decryptProtonExport(tiny, PASSWORD)).toThrow(
        'Content frame too short'
      )
    })

    it('exposes a stable PROTON_INVALID_PAYLOAD code on short content', () => {
      expect.assertions(1)
      try {
        decryptProtonExport(
          { ...VECTOR, content: Buffer.alloc(10).toString('base64') },
          PASSWORD
        )
      } catch (err) {
        expect(err.code).toBe('PROTON_INVALID_PAYLOAD')
      }
    })
  })
})
