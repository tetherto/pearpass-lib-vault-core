import * as constantTimeHashCompareModule from '@tetherto/pearpass-utils-password-check'

import * as appDeps from './appDeps'
import * as decryptVaultKeyModule from './decryptVaultKey'
import * as encryptVaultKeyWithHashedPasswordModule from './encryptVaultKeyWithHashedPassword'
import * as encryptVaultWithKeyModule from './encryptVaultWithKey'
import * as getDecryptionKeyModule from './getDecryptionKey'
import * as hashPasswordModule from './hashPassword'
import { masterPasswordManager } from './masterPasswordManager'

jest.mock('./appDeps', () => ({
  encryptionAdd: jest.fn(),
  encryptionGet: jest.fn(),
  getIsEncryptionInitialized: jest.fn(),
  encryptionInit: jest.fn(),
  rateLimitRecordFailure: jest.fn(),
  vaultsAdd: jest.fn(),
  closeVaultsInstance: jest.fn(),
  vaultsGet: jest.fn(),
  getIsVaultsInitialized: jest.fn(),
  masterVaultInit: jest.fn(),
  masterVaultInitWithNewBlindEncryption: jest.fn(),
  vaultsList: jest.fn(),
  closeActiveVaultInstance: jest.fn(),
  initActiveVaultInstance: jest.fn(),
  getIsActiveVaultInitialized: jest.fn(),
  activeVaultGet: jest.fn(),
  initInstanceWithNewBlindEncryption: jest.fn()
}))

jest.mock('./decryptVaultKey', () => ({
  decryptVaultKey: jest.fn()
}))

jest.mock('./encryptVaultKeyWithHashedPassword', () => ({
  encryptVaultKeyWithHashedPassword: jest.fn()
}))

jest.mock('./encryptVaultWithKey', () => ({
  encryptVaultWithKey: jest.fn()
}))

jest.mock('./getDecryptionKey', () => ({
  getDecryptionKey: jest.fn()
}))

jest.mock('./hashPassword', () => ({
  hashPassword: jest.fn()
}))

jest.mock('@tetherto/pearpass-utils-password-check', () => ({
  constantTimeHashCompare: jest.fn()
}))

describe('masterPasswordManager', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('createMasterPassword', () => {
    it('creates and stores master password data', async () => {
      appDeps.getIsEncryptionInitialized.mockReturnValue(false)
      appDeps.encryptionGet.mockResolvedValue(undefined)
      hashPasswordModule.hashPassword.mockReturnValue({
        hashedPassword: 'hashed',
        salt: 'salt'
      })
      encryptVaultKeyWithHashedPasswordModule.encryptVaultKeyWithHashedPassword.mockReturnValue(
        {
          ciphertext: 'ct',
          nonce: 'nonce'
        }
      )
      decryptVaultKeyModule.decryptVaultKey.mockReturnValue('vault-key')
      appDeps.getIsVaultsInitialized.mockReturnValue(false)

      const result = await masterPasswordManager.createMasterPassword({
        passwordBase64: 'pw-base64'
      })

      expect(appDeps.encryptionInit).toHaveBeenCalled()
      expect(hashPasswordModule.hashPassword).toHaveBeenCalledWith('pw-base64')
      expect(
        encryptVaultKeyWithHashedPasswordModule.encryptVaultKeyWithHashedPassword
      ).toHaveBeenCalledWith('hashed')
      expect(appDeps.masterVaultInit).toHaveBeenCalledWith({
        encryptionKey: 'vault-key',
        hashedPassword: 'hashed'
      })
      expect(appDeps.vaultsAdd).toHaveBeenCalledWith('masterEncryption', {
        ciphertext: 'ct',
        nonce: 'nonce',
        salt: 'salt',
        hashedPassword: 'hashed'
      })
      expect(appDeps.encryptionAdd).toHaveBeenCalledWith('masterPassword', {
        ciphertext: 'ct',
        nonce: 'nonce',
        salt: 'salt'
      })
      expect(result).toEqual({
        hashedPassword: 'hashed',
        salt: 'salt',
        ciphertext: 'ct',
        nonce: 'nonce'
      })
    })
  })

  describe('initWithPassword', () => {
    it('validates against existing vaults master encryption', async () => {
      appDeps.getIsVaultsInitialized.mockReturnValue(true)
      appDeps.vaultsGet.mockResolvedValue({
        salt: 'salt',
        hashedPassword: 'stored-hash'
      })
      getDecryptionKeyModule.getDecryptionKey.mockReturnValue('derived-hash')
      constantTimeHashCompareModule.constantTimeHashCompare.mockReturnValue(
        true
      )

      const result = await masterPasswordManager.initWithPassword({
        passwordBase64: 'pw-base64'
      })

      expect(getDecryptionKeyModule.getDecryptionKey).toHaveBeenCalledWith({
        salt: 'salt',
        password: 'pw-base64'
      })
      expect(
        constantTimeHashCompareModule.constantTimeHashCompare
      ).toHaveBeenCalledWith('stored-hash', 'derived-hash')
      expect(result).toEqual({ success: true })
    })

    it('records failure when decrypting fails', async () => {
      appDeps.getIsVaultsInitialized.mockReturnValue(false)
      appDeps.getIsEncryptionInitialized.mockReturnValue(true)
      appDeps.encryptionGet.mockResolvedValue({
        ciphertext: 'ct',
        nonce: 'nonce',
        salt: 'salt'
      })
      getDecryptionKeyModule.getDecryptionKey.mockReturnValue('derived')
      decryptVaultKeyModule.decryptVaultKey.mockReturnValue(undefined)

      await expect(
        masterPasswordManager.initWithPassword({ passwordBase64: 'pw-base64' })
      ).rejects.toThrow('Error decrypting vault key')

      expect(appDeps.rateLimitRecordFailure).toHaveBeenCalled()
    })

    it('throws error when hash comparison fails', async () => {
      appDeps.getIsVaultsInitialized.mockReturnValue(true)
      appDeps.vaultsGet.mockResolvedValue({
        salt: 'salt',
        hashedPassword: 'stored-hash'
      })
      getDecryptionKeyModule.getDecryptionKey.mockReturnValue(
        'wrong-derived-hash'
      )
      constantTimeHashCompareModule.constantTimeHashCompare.mockReturnValue(
        false
      )

      await expect(
        masterPasswordManager.initWithPassword({ passwordBase64: 'pw-base64' })
      ).rejects.toThrow(
        'Provided credentials do not match existing master encryption'
      )
    })
  })

  describe('updateMasterPassword', () => {
    it('updates master password after verifying current one', async () => {
      appDeps.getIsEncryptionInitialized.mockReturnValue(true)
      appDeps.getIsVaultsInitialized.mockReturnValueOnce(true)
      appDeps.vaultsGet.mockResolvedValue({
        ciphertext: 'old-ct',
        nonce: 'old-nonce',
        salt: 'old-salt',
        hashedPassword: 'current-hash'
      })
      appDeps.activeVaultGet.mockResolvedValue({ id: 'vault-1' })
      appDeps.vaultsList.mockResolvedValue([])
      appDeps.getIsActiveVaultInitialized.mockReturnValue(false)
      getDecryptionKeyModule.getDecryptionKey.mockReturnValueOnce(
        'derived-current-hash'
      )
      constantTimeHashCompareModule.constantTimeHashCompare
        .mockReturnValueOnce(true) // current password verification
        .mockReturnValueOnce(true) // vault key verification (base64)
      decryptVaultKeyModule.decryptVaultKey
        .mockReturnValueOnce('vault-key')
        .mockReturnValueOnce('vault-key')
      hashPasswordModule.hashPassword.mockReturnValue({
        hashedPassword: 'new-hash',
        salt: 'new-salt'
      })
      encryptVaultWithKeyModule.encryptVaultWithKey.mockReturnValue({
        ciphertext: 'new-ct',
        nonce: 'new-nonce'
      })
      appDeps.getIsVaultsInitialized.mockReturnValue(true)

      const result = await masterPasswordManager.updateMasterPassword({
        newPassword: 'new-pw',
        currentPassword: 'curr-pw'
      })

      expect(getDecryptionKeyModule.getDecryptionKey).toHaveBeenCalledWith({
        salt: 'old-salt',
        password: 'curr-pw'
      })
      expect(
        constantTimeHashCompareModule.constantTimeHashCompare
      ).toHaveBeenCalledWith('current-hash', 'derived-current-hash')
      expect(hashPasswordModule.hashPassword).toHaveBeenCalledWith('new-pw')
      expect(
        encryptVaultWithKeyModule.encryptVaultWithKey
      ).toHaveBeenCalledWith('new-hash', 'vault-key')
      expect(appDeps.vaultsAdd).toHaveBeenCalledWith('masterEncryption', {
        ciphertext: 'new-ct',
        nonce: 'new-nonce',
        salt: 'new-salt',
        hashedPassword: 'new-hash'
      })
      expect(appDeps.encryptionAdd).toHaveBeenCalledWith('masterPassword', {
        ciphertext: 'new-ct',
        nonce: 'new-nonce',
        salt: 'new-salt'
      })
      expect(result).toEqual({
        hashedPassword: 'new-hash',
        salt: 'new-salt',
        ciphertext: 'new-ct',
        nonce: 'new-nonce'
      })
    })

    it('throws error when current password verification fails', async () => {
      appDeps.getIsEncryptionInitialized.mockReturnValue(true)
      appDeps.getIsVaultsInitialized.mockReturnValueOnce(true)
      appDeps.vaultsGet.mockResolvedValue({
        ciphertext: 'old-ct',
        nonce: 'old-nonce',
        salt: 'old-salt',
        hashedPassword: 'current-hash'
      })
      getDecryptionKeyModule.getDecryptionKey.mockReturnValueOnce('wrong-hash')
      constantTimeHashCompareModule.constantTimeHashCompare.mockReturnValueOnce(
        false
      )

      await expect(
        masterPasswordManager.updateMasterPassword({
          newPassword: 'new-pw',
          currentPassword: 'wrong-pw'
        })
      ).rejects.toThrow('Invalid password')
    })
  })

  describe('initWithCredentials', () => {
    it('initializes vaults with provided credentials', async () => {
      appDeps.getIsEncryptionInitialized.mockReturnValue(false)
      decryptVaultKeyModule.decryptVaultKey.mockReturnValue('vault-key')

      const result = await masterPasswordManager.initWithCredentials({
        ciphertext: 'ct',
        nonce: 'nonce',
        hashedPassword: 'hash'
      })

      expect(appDeps.encryptionInit).toHaveBeenCalled()
      expect(decryptVaultKeyModule.decryptVaultKey).toHaveBeenCalledWith({
        ciphertext: 'ct',
        nonce: 'nonce',
        hashedPassword: 'hash'
      })
      expect(appDeps.masterVaultInit).toHaveBeenCalledWith({
        encryptionKey: 'vault-key',
        hashedPassword: 'hash'
      })
      expect(result).toEqual({ success: true })
    })

    it('throws error if required parameters are missing', async () => {
      await expect(
        masterPasswordManager.initWithCredentials({})
      ).rejects.toThrow('Missing required parameters')

      await expect(
        masterPasswordManager.initWithCredentials({
          ciphertext: 'ct',
          nonce: 'nonce'
        })
      ).rejects.toThrow('Missing required parameters')
    })

    it('throws error if decryption fails', async () => {
      appDeps.getIsEncryptionInitialized.mockReturnValue(true)
      decryptVaultKeyModule.decryptVaultKey.mockReturnValue(undefined)

      await expect(
        masterPasswordManager.initWithCredentials({
          ciphertext: 'ct',
          nonce: 'nonce',
          hashedPassword: 'hash'
        })
      ).rejects.toThrow('Error decrypting vault key')
    })
  })
})
