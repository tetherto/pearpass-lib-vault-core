import { decryptVaultKey } from './decryptVaultKey'
import { encryptVaultWithKey } from './encryptVaultWithKey'
import { encryptExportData, decryptExportData } from './exportDataEncryption'
import { getDecryptionKey } from './getDecryptionKey'
import { hashPassword } from './hashPassword'

jest.mock('./hashPassword')
jest.mock('./encryptVaultWithKey')
jest.mock('./getDecryptionKey')
jest.mock('./decryptVaultKey')

describe('exportDataEncryption', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('encryptExportData', () => {
    it('should encrypt data with password', () => {
      const testData = 'test data to encrypt'
      const testPassword = 'mySecurePassword'

      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const result = encryptExportData(testData, testPassword)

      expect(hashPassword).toHaveBeenCalledWith(
        Buffer.from(testPassword, 'utf8').toString('base64')
      )
      expect(encryptVaultWithKey).toHaveBeenCalledWith(
        'hashedPassword123',
        Buffer.from(testData, 'utf8').toString('base64')
      )

      expect(result).toEqual({
        version: '1.0',
        encrypted: true,
        algorithm: 'XSalsa20-Poly1305',
        kdf: 'Argon2id',
        salt: 'salt123',
        nonce: 'nonce123',
        ciphertext: 'encryptedCiphertext'
      })
    })

    it('should handle different data types', () => {
      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const jsonData = JSON.stringify({ key: 'value', array: [1, 2, 3] })
      const result = encryptExportData(jsonData, 'password')

      expect(result).toHaveProperty('encrypted', true)
      expect(result).toHaveProperty('version', '1.0')
    })

    it('should return proper encryption metadata', () => {
      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const result = encryptExportData('test', 'password')

      expect(result.algorithm).toBe('XSalsa20-Poly1305')
      expect(result.kdf).toBe('Argon2id')
      expect(result.version).toBe('1.0')
    })
  })

  describe('decryptExportData', () => {
    it('should decrypt encrypted data with correct password', () => {
      const encryptedData = {
        version: '1.0',
        encrypted: true,
        algorithm: 'XSalsa20-Poly1305',
        kdf: 'Argon2id',
        salt: 'salt123',
        nonce: 'nonce123',
        ciphertext: 'encryptedCiphertext'
      }
      const password = 'mySecurePassword'

      getDecryptionKey.mockReturnValue('hashedPassword123')
      decryptVaultKey.mockReturnValue(
        Buffer.from('decrypted data', 'utf8').toString('base64')
      )

      const result = decryptExportData(encryptedData, password)

      expect(getDecryptionKey).toHaveBeenCalledWith({
        password: Buffer.from(password, 'utf8').toString('base64'),
        salt: 'salt123'
      })

      expect(decryptVaultKey).toHaveBeenCalledWith({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123',
        hashedPassword: 'hashedPassword123'
      })

      expect(result).toBe('decrypted data')
    })

    it('should throw error if data is not encrypted', () => {
      const notEncryptedData = {
        encrypted: false,
        data: 'plaintext'
      }

      expect(() => {
        decryptExportData(notEncryptedData, 'password')
      }).toThrow('Data is not encrypted')
    })

    it('should throw error if decryption fails', () => {
      const encryptedData = {
        version: '1.0',
        encrypted: true,
        algorithm: 'XSalsa20-Poly1305',
        kdf: 'Argon2id',
        salt: 'salt123',
        nonce: 'nonce123',
        ciphertext: 'encryptedCiphertext'
      }

      getDecryptionKey.mockReturnValue('wrongHashedPassword')
      decryptVaultKey.mockReturnValue(null)

      expect(() => {
        decryptExportData(encryptedData, 'wrongPassword')
      }).toThrow('Decryption failed - invalid password or corrupted data')
    })

    it('should handle corrupted ciphertext', () => {
      const encryptedData = {
        version: '1.0',
        encrypted: true,
        algorithm: 'XSalsa20-Poly1305',
        kdf: 'Argon2id',
        salt: 'salt123',
        nonce: 'nonce123',
        ciphertext: 'corruptedCiphertext'
      }

      getDecryptionKey.mockReturnValue('hashedPassword123')
      decryptVaultKey.mockReturnValue(undefined)

      expect(() => {
        decryptExportData(encryptedData, 'password')
      }).toThrow('Decryption failed - invalid password or corrupted data')
    })
  })

  describe('encrypt/decrypt roundtrip', () => {
    it('should successfully encrypt and decrypt data', () => {
      const originalData = 'This is my sensitive data'
      const password = 'securePassword123'

      // Mock encryption
      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const encrypted = encryptExportData(originalData, password)

      expect(encrypted.encrypted).toBe(true)

      // Mock decryption
      getDecryptionKey.mockReturnValue('hashedPassword123')
      decryptVaultKey.mockReturnValue(
        Buffer.from(originalData, 'utf8').toString('base64')
      )

      const decrypted = decryptExportData(encrypted, password)

      expect(decrypted).toBe(originalData)
    })

    it('should handle JSON data in encrypt/decrypt roundtrip', () => {
      const originalData = JSON.stringify({
        records: [
          { type: 'password', data: { username: 'test', password: 'test123' } }
        ],
        metadata: { version: '1.0' }
      })
      const password = 'password123'

      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const encrypted = encryptExportData(originalData, password)

      getDecryptionKey.mockReturnValue('hashedPassword123')
      decryptVaultKey.mockReturnValue(
        Buffer.from(originalData, 'utf8').toString('base64')
      )

      const decrypted = decryptExportData(encrypted, password)

      expect(JSON.parse(decrypted)).toEqual(JSON.parse(originalData))
    })
  })

  describe('edge cases', () => {
    it('should handle empty string data', () => {
      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const result = encryptExportData('', 'password')

      expect(result.encrypted).toBe(true)
      expect(encryptVaultWithKey).toHaveBeenCalledWith(
        'hashedPassword123',
        Buffer.from('', 'utf8').toString('base64')
      )
    })

    it('should handle special characters in data', () => {
      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const specialData = '™£€¥©®§¶•ªº–≠'
      const result = encryptExportData(specialData, 'password')

      expect(result.encrypted).toBe(true)
    })

    it('should handle large data payloads', () => {
      hashPassword.mockReturnValue({
        hashedPassword: 'hashedPassword123',
        salt: 'salt123'
      })

      encryptVaultWithKey.mockReturnValue({
        ciphertext: 'encryptedCiphertext',
        nonce: 'nonce123'
      })

      const largeData = 'x'.repeat(1000000) // 1MB of data
      const result = encryptExportData(largeData, 'password')

      expect(result.encrypted).toBe(true)
    })
  })
})
