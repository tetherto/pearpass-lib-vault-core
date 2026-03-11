import { decryptVaultKey } from './decryptVaultKey'
import { encryptVaultWithKey } from './encryptVaultWithKey'
import { getDecryptionKey } from './getDecryptionKey'
import { hashPassword } from './hashPassword'

/**
 * @param {string} data
 * @param {string} password
 * @returns {Object}
 */
export const encryptExportData = (data, password) => {
  const { hashedPassword, salt } = hashPassword(
    Buffer.from(password, 'utf8').toString('base64')
  )

  const dataBuffer = Buffer.from(data, 'utf8')
  const { ciphertext, nonce } = encryptVaultWithKey(
    hashedPassword,
    dataBuffer.toString('base64')
  )

  return {
    version: '1.0',
    encrypted: true,
    algorithm: 'XSalsa20-Poly1305',
    kdf: 'Argon2id',
    salt,
    nonce,
    ciphertext
  }
}

/**
 * @param {Object} encryptedData
 * @param {string} encryptedData.version
 * @param {boolean} encryptedData.encrypted
 * @param {string} encryptedData.algorithm
 * @param {string} encryptedData.kdf
 * @param {string} encryptedData.salt
 * @param {string} encryptedData.nonce
 * @param {string} encryptedData.ciphertext
 * @param {string} password
 * @returns {string}
 * @throws {Error}
 */
export const decryptExportData = (encryptedData, password) => {
  if (!encryptedData.encrypted) {
    throw new Error('Data is not encrypted')
  }

  const hashedPassword = getDecryptionKey({
    password: Buffer.from(password, 'utf8').toString('base64'),
    salt: encryptedData.salt
  })

  const decryptedBase64 = decryptVaultKey({
    ciphertext: encryptedData.ciphertext,
    nonce: encryptedData.nonce,
    hashedPassword
  })

  if (!decryptedBase64) {
    throw new Error('Decryption failed - invalid password or corrupted data')
  }

  const decryptedData = Buffer.from(decryptedBase64, 'base64').toString('utf8')

  return decryptedData
}
