import sodium from 'sodium-native'

/**
 *
 * @param {string} hashedPassword
 * @param {Buffer<ArrayBuffer>} key
 * @returns {{
 *   ciphertext: string
 *   nonce: string
 * }}
 */
export const encryptVaultWithKey = (hashedPassword, key) => {
  const nonce = sodium.sodium_malloc(sodium.crypto_secretbox_NONCEBYTES)

  const keyLen = Buffer.byteLength(key, 'base64')
  const keyBuffer = sodium.sodium_malloc(keyLen)
  keyBuffer.write(key, 'base64')

  const ciphertext = sodium.sodium_malloc(
    keyLen + sodium.crypto_secretbox_MACBYTES
  )

  const hashedPasswordBuf = sodium.sodium_malloc(
    sodium.crypto_secretbox_KEYBYTES
  )
  hashedPasswordBuf.write(hashedPassword, 'hex')

  sodium.randombytes_buf(nonce)

  sodium.crypto_secretbox_easy(ciphertext, keyBuffer, nonce, hashedPasswordBuf)

  return {
    ciphertext: ciphertext.toString('base64'),
    nonce: nonce.toString('base64')
  }
}
