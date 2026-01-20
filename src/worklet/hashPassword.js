import sodium from 'sodium-native'

/**
 * @param {string} password - Base64 encoded password
 * @returns {{
 *   salt: string
 *   hashedPassword: string
 * }}
 */
export const hashPassword = (password) => {
  const passwordBuffer = Buffer.from(password, 'base64')
  const salt = sodium.sodium_malloc(sodium.crypto_pwhash_SALTBYTES)
  const hashedPassword = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)

  const opslimit = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  const algo = sodium.crypto_pwhash_ALG_DEFAULT

  try {
    sodium.randombytes_buf(salt)

    sodium.crypto_pwhash(
      hashedPassword,
      passwordBuffer,
      salt,
      opslimit,
      memlimit,
      algo
    )

    return {
      hashedPassword: Buffer.from(hashedPassword).toString('hex'),
      salt: salt.toString('base64')
    }
  } finally {
    sodium.sodium_memzero(hashedPassword)
    sodium.sodium_memzero(salt)
    sodium.sodium_memzero(passwordBuffer)
  }
}
