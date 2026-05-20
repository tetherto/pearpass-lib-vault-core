/* eslint-disable import/order */
import { jest } from '@jest/globals'

jest.mock('hypercore-id-encoding', () => ({
  decode: jest.fn()
}))

jest.mock('../worklet/utils/dht', () => ({
  getSharedDHT: jest.fn()
}))

import id from 'hypercore-id-encoding'
import { getSharedDHT } from '../worklet/utils/dht'

import {
  validateMirrorKeyViaDHT,
  filterReachableMirrors,
  withMirrorValidation
} from './validateMirrorKeyViaDHT'

describe('validateMirrorKeyViaDHT', () => {
  let mockSocket
  let mockDHT

  beforeEach(() => {
    jest.clearAllMocks()

    mockSocket = {
      on: jest.fn(),
      once: jest.fn(),
      removeAllListeners: jest.fn(),
      destroy: jest.fn()
    }

    mockDHT = {
      connect: jest.fn(() => mockSocket)
    }

    getSharedDHT.mockReturnValue(mockDHT)
  })

  describe('validateMirrorKeyViaDHT', () => {
    it('should return false for invalid key encoding', async () => {
      id.decode.mockImplementation(() => {
        throw new Error('Invalid encoding')
      })

      const result = await validateMirrorKeyViaDHT('invalid-key')

      expect(result).toBe(false)
      expect(mockDHT.connect).not.toHaveBeenCalled()
    })

    it('should return true when socket opens successfully', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation((event, callback) => {
        if (event === 'open') {
          setTimeout(callback, 10)
        }
      })

      const result = await validateMirrorKeyViaDHT(validKey)

      expect(result).toBe(true)
      expect(mockDHT.connect).toHaveBeenCalledWith(decodedKey)
      expect(mockSocket.once).toHaveBeenCalledWith('open', expect.any(Function))
      expect(mockSocket.removeAllListeners).toHaveBeenCalled()
      expect(mockSocket.destroy).toHaveBeenCalled()
    })

    it('should swallow socket errors and resolve via timeout', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation(() => {})

      const result = await validateMirrorKeyViaDHT(validKey, { timeoutMs: 50 })

      expect(result).toBe(false)
      expect(mockSocket.on).toHaveBeenCalledWith('error', expect.any(Function))
      expect(mockSocket.removeAllListeners).toHaveBeenCalled()
      expect(mockSocket.destroy).toHaveBeenCalled()
    })

    it('should return false when socket times out', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation(() => {
        // No events fire, will rely on function timeout
      })

      const result = await validateMirrorKeyViaDHT(validKey, { timeoutMs: 100 })

      expect(result).toBe(false)
      expect(mockSocket.removeAllListeners).toHaveBeenCalled()
      expect(mockSocket.destroy).toHaveBeenCalled()
    })

    it('should return false after timeout when no events occur', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation(() => {
        // No events fire
      })

      const result = await validateMirrorKeyViaDHT(validKey, { timeoutMs: 100 })

      expect(result).toBe(false)
      expect(mockSocket.removeAllListeners).toHaveBeenCalled()
      expect(mockSocket.destroy).toHaveBeenCalled()
    })

    it('should use custom timeout', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation(() => {})

      const startTime = Date.now()
      const result = await validateMirrorKeyViaDHT(validKey, { timeoutMs: 200 })
      const duration = Date.now() - startTime

      expect(result).toBe(false)
      expect(duration).toBeGreaterThanOrEqual(190)
      expect(duration).toBeLessThan(300)
    })

    it('should prevent multiple resolutions when open fires after timeout', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      let openFiredAfterTimeout = false

      mockSocket.once.mockImplementation((event, callback) => {
        if (event === 'open') {
          setTimeout(() => {
            openFiredAfterTimeout = true
            callback()
          }, 80)
        }
      })

      const result = await validateMirrorKeyViaDHT(validKey, { timeoutMs: 30 })

      expect(result).toBe(false)
      await new Promise((resolve) => setTimeout(resolve, 100))
      expect(openFiredAfterTimeout).toBe(true)
    })

    it('should handle socket cleanup errors gracefully', async () => {
      const validKey = 'valid-key'
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.removeAllListeners.mockImplementation(() => {
        throw new Error('Cleanup error')
      })
      mockSocket.destroy.mockImplementation(() => {
        throw new Error('Destroy error')
      })

      mockSocket.once.mockImplementation((event, callback) => {
        if (event === 'open') {
          setTimeout(callback, 10)
        }
      })

      const result = await validateMirrorKeyViaDHT(validKey)

      expect(result).toBe(true)
      expect(mockSocket.removeAllListeners).toHaveBeenCalled()
    })
  })

  describe('filterReachableMirrors', () => {
    it('should return empty array for empty input', async () => {
      const result = await filterReachableMirrors([])
      expect(result).toEqual([])
    })

    it('should return empty array for non-array input', async () => {
      const result = await filterReachableMirrors(null)
      expect(result).toEqual([])
    })

    it('should handle single mirror validation', async () => {
      const mirrors = ['key1']
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation((event, callback) => {
        if (event === 'open') {
          setTimeout(callback, 10)
        }
      })

      const result = await filterReachableMirrors(mirrors)

      expect(result).toEqual(['key1'])
      expect(mockDHT.connect).toHaveBeenCalledWith(decodedKey)
    })

    it('should filter out unreachable mirrors', async () => {
      const mirrors = ['key1', 'key2']
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation(() => {})

      const result = await filterReachableMirrors(mirrors, { timeoutMs: 50 })

      expect(result).toEqual([])
      expect(mockDHT.connect).toHaveBeenCalledTimes(2)
    })
  })

  describe('withMirrorValidation', () => {
    let mockAction

    beforeEach(() => {
      mockAction = jest.fn()
    })

    it('should call action with valid mirrors', async () => {
      const mirrors = ['key1']
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation((event, callback) => {
        if (event === 'open') {
          setTimeout(callback, 10)
        }
      })

      mockAction.mockResolvedValue('success')

      const wrappedAction = withMirrorValidation(mockAction)
      const result = await wrappedAction(mirrors)

      expect(result).toBe('success')
      expect(mockAction).toHaveBeenCalledWith(['key1'])
    })

    it('should throw error when no mirrors are reachable', async () => {
      const mirrors = ['key1']
      const decodedKey = Buffer.from('decoded-key')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation(() => {})

      const wrappedAction = withMirrorValidation(mockAction, { timeoutMs: 50 })

      await expect(wrappedAction(mirrors)).rejects.toThrow(
        'No reachable mirrors'
      )
      expect(mockAction).not.toHaveBeenCalled()
    })

    it('should propagate action errors', async () => {
      const mirrors = ['key1']
      const decodedKey = Buffer.from('decoded-key')
      const error = new Error('Action failed')

      id.decode.mockReturnValue(decodedKey)

      mockSocket.once.mockImplementation((event, callback) => {
        if (event === 'open') {
          setTimeout(callback, 10)
        }
      })

      mockAction.mockRejectedValue(error)

      const wrappedAction = withMirrorValidation(mockAction)

      await expect(wrappedAction(mirrors)).rejects.toThrow('Action failed')
    })
  })
})
