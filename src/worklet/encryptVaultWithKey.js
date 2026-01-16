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

  const ciphertext = sodium.sodium_malloc(
    keyLen + sodium.crypto_secretbox_MACBYTES
  )

  const hashedPasswordBuf = sodium.sodium_malloc(
    sodium.crypto_secretbox_KEYBYTES
  )

  try {
    hashedPasswordBuf.write(hashedPassword, 'hex')
    keyBuffer.write(key, 'base64')

    sodium.randombytes_buf(nonce)

    sodium.crypto_secretbox_easy(
      ciphertext,
      keyBuffer,
      nonce,
      hashedPasswordBuf
    )

    return {
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64')
    }
  } finally {
    sodium.sodium_memzero(nonce)
    sodium.sodium_memzero(keyBuffer)
    sodium.sodium_memzero(ciphertext)
    sodium.sodium_memzero(hashedPasswordBuf)
  }
}
