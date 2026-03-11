jest.mock('bare-fetch', () => ({
  __esModule: true,
  default: jest.fn()
}))

jest.mock(
  'bare-fs',
  () => ({
    __esModule: true,
    default: {}
  }),
  { virtual: true }
)

jest.mock(
  'bare-path',
  () => ({
    __esModule: true,
    default: {}
  }),
  { virtual: true }
)

jest.mock(
  'bare-os',
  () => ({
    __esModule: true,
    default: {}
  }),
  { virtual: true }
)

jest.mock('./appDeps', () => ({
  activeVaultAdd: jest.fn(),
  activeVaultGetFile: jest.fn(),
  getIsActiveVaultInitialized: jest.fn()
}))

jest.mock('./utils/workletLogger', () => ({
  workletLogger: {
    log: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

// Import after mocks for modules that might have side effects or be problematic
// (Though Jest hoisting usually handles this, sometimes explicit ordering with factory mocks helps clarify)
import fetch from 'bare-fetch'

import {
  activeVaultAdd,
  activeVaultGetFile,
  getIsActiveVaultInitialized
} from './appDeps'
import { faviconManager } from './faviconManager'

describe('faviconManager', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('fetchFavicon: fetches from network when not in cache and saves to cache', async () => {
    const url = 'https://example.com'
    const arrayBuffer = new TextEncoder().encode('fake-image-data').buffer
    const mockBuffer = Buffer.from(arrayBuffer)

    getIsActiveVaultInitialized.mockReturnValue(true)
    activeVaultGetFile.mockResolvedValue(null)
    fetch.mockResolvedValue({
      ok: true,
      arrayBuffer: jest.fn().mockResolvedValue(arrayBuffer)
    })

    activeVaultAdd.mockResolvedValue()

    const result = await faviconManager.fetchFavicon(url)

    expect(activeVaultGetFile).toHaveBeenCalledWith('favicon/example.com')
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(
        'https://www.google.com/s2/favicons?domain=https://example.com&sz=64'
      )
    )

    expect(activeVaultAdd).toHaveBeenCalledWith(
      'favicon/example.com',
      expect.objectContaining({ created_at: expect.any(Number) }),
      mockBuffer,
      'example.com.png'
    )

    const expectedBase64 = `data:image/png;base64,${mockBuffer.toString('base64')}`
    expect(result).toBe(expectedBase64)
  })

  test('fetchFavicon: returns from cache if available and does not fetch', async () => {
    const url = 'https://cached.com'
    const mockBuffer = Buffer.from('cached-image-data')

    getIsActiveVaultInitialized.mockReturnValue(true)
    activeVaultGetFile.mockResolvedValue(mockBuffer)

    const result = await faviconManager.fetchFavicon(url)

    expect(activeVaultGetFile).toHaveBeenCalledWith('favicon/cached.com')
    expect(fetch).not.toHaveBeenCalled()
    expect(activeVaultAdd).not.toHaveBeenCalled()

    const expectedBase64 = `data:image/png;base64,${mockBuffer.toString('base64')}`
    expect(result).toBe(expectedBase64)
  })

  test('fetchFavicon: returns null when fetch fails', async () => {
    const url = 'https://error-site.com'

    getIsActiveVaultInitialized.mockReturnValue(true)
    activeVaultGetFile.mockResolvedValue(null)

    fetch.mockRejectedValue(new Error('Network error'))

    const result = await faviconManager.fetchFavicon(url)

    expect(activeVaultGetFile).toHaveBeenCalledWith('favicon/error-site.com')
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(
        'https://www.google.com/s2/favicons?domain=https://error-site.com&sz=64'
      )
    )

    expect(activeVaultAdd).not.toHaveBeenCalled()
    expect(result).toBeNull()
  })
})
