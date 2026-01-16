import sodium from 'sodium-native'

/**
 *
 * @param {string} hashedPassword
 * @returns {{
 *   ciphertext: string
 *   nonce: string
 * }}
 */
export const encryptVaultKeyWithHashedPassword = (hashedPassword) => {
  const nonce = sodium.sodium_malloc(sodium.crypto_secretbox_NONCEBYTES)
  const key = sodium.sodium_malloc(32)

  const ciphertext = sodium.sodium_malloc(
    key.length + sodium.crypto_secretbox_MACBYTES
  )

  const hashedPasswordBuf = sodium.sodium_malloc(
    sodium.crypto_secretbox_KEYBYTES
  )

  try {
    hashedPasswordBuf.write(hashedPassword, 'hex')

    sodium.randombytes_buf(key)
    sodium.randombytes_buf(nonce)

    sodium.crypto_secretbox_easy(ciphertext, key, nonce, hashedPasswordBuf)

    return {
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64')
    }
  } finally {
    sodium.sodium_memzero(nonce)
    sodium.sodium_memzero(key)
    sodium.sodium_memzero(ciphertext)
    sodium.sodium_memzero(hashedPasswordBuf)
  }
}
