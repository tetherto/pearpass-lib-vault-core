import sodium from 'sodium-native'

/**
 * @param {{
 *   salt: string      // base64-encoded salt
 *   password: string  // base64-encoded password
 * }} data
 * @returns {string}   // hex-encoded derived key
 */
export const getDecryptionKey = (data) => {
  const salt = Buffer.from(data.salt, 'base64')

  const passwordLen = Buffer.byteLength(data.password, 'base64')
  const password = sodium.sodium_malloc(passwordLen)
  password.write(data.password, 'base64')

  const hashedPassword = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)

  const opslimit = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
  const algo = sodium.crypto_pwhash_ALG_DEFAULT

  sodium.crypto_pwhash(hashedPassword, password, salt, opslimit, memlimit, algo)

  return Buffer.from(hashedPassword).toString('hex')
}
