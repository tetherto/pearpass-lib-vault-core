import {
  encryptionAdd,
  encryptionGet,
  getIsEncryptionInitialized,
  encryptionInit,
  rateLimitRecordFailure,
  vaultsAdd,
  closeVaultsInstance,
  vaultsGet,
  getIsVaultsInitialized,
  masterVaultInit,
  masterVaultInitWithNewBlindEncryption,
  vaultsList,
  closeActiveVaultInstance,
  initActiveVaultInstance,
  getIsActiveVaultInitialized,
  activeVaultGet,
  initInstanceWithNewBlindEncryption
} from './appDeps'
import { decryptVaultKey } from './decryptVaultKey'
import { encryptVaultKeyWithHashedPassword } from './encryptVaultKeyWithHashedPassword'
import { encryptVaultWithKey } from './encryptVaultWithKey'
import { getDecryptionKey } from './getDecryptionKey'
import { hashPassword } from './hashPassword'

class MasterPasswordManager {
  async ensureEncryptionInitialized() {
    if (!getIsEncryptionInitialized()) {
      await encryptionInit()
    }
  }

  async ensureVaultsInitialized({
    encryptionKey,
    hashedPassword,
    coreStoreOptions = {}
  }) {
    if (!getIsVaultsInitialized()) {
      await masterVaultInit({ encryptionKey, hashedPassword, coreStoreOptions })
    }
  }

  async getExistingMasterEncryption() {
    if (getIsVaultsInitialized()) {
      const masterEnc = await vaultsGet('masterEncryption')
      if (masterEnc) {
        return masterEnc
      }
    }

    await this.ensureEncryptionInitialized()
    const enc = await encryptionGet('masterPassword')
    return enc
  }

  async createMasterPassword({ passwordBase64, coreStoreOptions = {} }) {
    if (!passwordBase64) {
      throw new Error('Password is required')
    }

    await this.ensureEncryptionInitialized()

    const existing = await encryptionGet('masterPassword')
    if (existing) {
      throw new Error('Master password already exists')
    }

    const { hashedPassword, salt } = hashPassword(passwordBase64)
    const { ciphertext, nonce } =
      encryptVaultKeyWithHashedPassword(hashedPassword)

    const decryptedKey = decryptVaultKey({
      ciphertext,
      nonce,
      hashedPassword
    })

    if (!decryptedKey) {
      throw new Error('Error decrypting vault key')
    }

    await this.ensureVaultsInitialized({
      encryptionKey: decryptedKey,
      hashedPassword,
      coreStoreOptions
    })

    await vaultsAdd('masterEncryption', {
      ciphertext,
      nonce,
      salt,
      hashedPassword
    })

    await closeVaultsInstance()

    await encryptionAdd('masterPassword', {
      ciphertext,
      nonce,
      salt
    })

    return { hashedPassword, salt, ciphertext, nonce }
  }

  async initWithPassword({ passwordBase64, coreStoreOptions = {} }) {
    if (!passwordBase64) {
      throw new Error('Password is required')
    }

    if (getIsVaultsInitialized()) {
      const masterEncryption = await vaultsGet('masterEncryption')

      if (!masterEncryption) {
        throw new Error('Master encryption not found')
      }

      const derived = getDecryptionKey({
        salt: masterEncryption.salt,
        password: passwordBase64
      })

      if (masterEncryption.hashedPassword !== derived) {
        throw new Error(
          'Provided credentials do not match existing master encryption'
        )
      }

      return { success: true }
    }

    await this.ensureEncryptionInitialized()

    const encryptionGetRes = await encryptionGet('masterPassword')
    if (!encryptionGetRes) {
      throw new Error('Master password not set')
    }

    const { ciphertext, nonce, salt } = encryptionGetRes

    const hashedPassword = getDecryptionKey({
      salt,
      password: passwordBase64
    })

    const decryptVaultKeyRes = decryptVaultKey({
      ciphertext,
      nonce,
      hashedPassword
    })

    if (!decryptVaultKeyRes) {
      await rateLimitRecordFailure()
      throw new Error('Error decrypting vault key')
    }

    await masterVaultInit({
      encryptionKey: decryptVaultKeyRes,
      hashedPassword,
      coreStoreOptions
    })

    return { success: true }
  }

  async updateMasterPassword({
    newPassword,
    currentPassword,
    coreStoreOptions = {}
  }) {
    if (!newPassword || !currentPassword) {
      throw new Error('New and current passwords are required')
    }

    await this.ensureEncryptionInitialized()

    const masterEncryption = await this.getExistingMasterEncryption()

    if (!masterEncryption) {
      throw new Error('Master password not found')
    }

    const {
      ciphertext: currentCiphertext,
      nonce: currentNonce,
      salt: currentSalt,
      hashedPassword: currentHashedPassword
    } = masterEncryption

    const derivedCurrent = getDecryptionKey({
      salt: currentSalt,
      password: currentPassword
    })

    if (currentHashedPassword && currentHashedPassword !== derivedCurrent) {
      throw new Error('Invalid password')
    }

    const currentVaultKey = decryptVaultKey({
      ciphertext: currentCiphertext,
      nonce: currentNonce,
      hashedPassword: currentHashedPassword || derivedCurrent
    })

    if (!currentVaultKey) {
      throw new Error('Error decrypting vault key')
    }

    const { hashedPassword: newHashedPassword, salt: newSalt } =
      hashPassword(newPassword)

    const { ciphertext, nonce } = encryptVaultWithKey(
      newHashedPassword,
      currentVaultKey
    )

    const verifyKey = decryptVaultKey({
      ciphertext,
      nonce,
      hashedPassword: newHashedPassword
    })

    if (verifyKey !== currentVaultKey) {
      throw new Error('Failed to verify new password encryption')
    }

    // Get active vault info before closing anything
    const activeVault = await activeVaultGet('vault')
    const activeVaultId = activeVault?.id

    await closeVaultsInstance()

    await masterVaultInitWithNewBlindEncryption({
      encryptionKey: currentVaultKey,
      newHashedPassword,
      currentHashedPassword,
      coreStoreOptions
    })

    await vaultsAdd('masterEncryption', {
      ciphertext,
      nonce,
      salt: newSalt,
      hashedPassword: newHashedPassword
    })

    await encryptionAdd('masterPassword', {
      ciphertext,
      nonce,
      salt: newSalt
    })

    // Update blind encryption for all vaults
    await this.updateAllVaultsBlindEncryption({
      currentHashedPassword,
      newHashedPassword,
      activeVaultId,
      masterEncryptionKey: currentVaultKey,
      coreStoreOptions
    })

    return {
      hashedPassword: newHashedPassword,
      salt: newSalt,
      ciphertext,
      nonce
    }
  }

  async initWithCredentials({
    ciphertext,
    nonce,
    hashedPassword,
    coreStoreOptions = {}
  }) {
    if (!ciphertext || !nonce || !hashedPassword) {
      throw new Error('Missing required parameters')
    }

    await this.ensureEncryptionInitialized()

    const decryptVaultKeyRes = decryptVaultKey({
      ciphertext,
      nonce,
      hashedPassword
    })

    if (!decryptVaultKeyRes) {
      throw new Error('Error decrypting vault key')
    }

    await masterVaultInit({
      encryptionKey: decryptVaultKeyRes,
      hashedPassword,
      coreStoreOptions
    })

    return { success: true }
  }

  async updateAllVaultsBlindEncryption({
    currentHashedPassword,
    newHashedPassword,
    activeVaultId,
    masterEncryptionKey,
    coreStoreOptions = {}
  }) {
    if (getIsActiveVaultInitialized()) {
      await closeActiveVaultInstance()
    }

    const allVaults = await vaultsList('vault/')

    // Update blind encryption for each vault
    // Note: Blind encryption uses master password's hashedPassword for all vaults
    // The vault's encryption key is only for encrypting vault data, not blind encryption
    for (const vault of allVaults) {
      if (!vault?.id) {
        continue
      }

      // Reinitialize vault storage with new blind encryption
      // Blind encryption is always based on master password, so we can update all vaults
      const vaultInstance = await initInstanceWithNewBlindEncryption({
        path: `vault/${vault.id}`,
        encryptionKey: masterEncryptionKey,
        newHashedPassword,
        currentHashedPassword,
        coreStoreOptions
      })

      await vaultInstance.close()
    }

    // Reopen the previously active vault if it was open
    if (activeVaultId && masterEncryptionKey) {
      await initActiveVaultInstance({
        id: activeVaultId,
        encryptionKey: masterEncryptionKey,
        coreStoreOptions
      })
    }

    return { success: true }
  }
}

export const masterPasswordManager = new MasterPasswordManager()
