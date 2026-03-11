import fetch from 'bare-fetch'

import {
  activeVaultAdd,
  activeVaultGetFile,
  getIsActiveVaultInitialized
} from './appDeps'
import { addHttps } from '../utils/urlUtils'
import { workletLogger } from './utils/workletLogger'

/**
 * Retrieves a favicon from cache
 * @param {Object} params - The parameters object
 * @param {string} params.hostname - The hostname to retrieve favicon for
 * @param {string} params.cacheKey - The cache key to use
 * @param {boolean} params.isVaultReady - Whether the vault is initialized
 * @returns {Promise<string|null>} Base64 data URI string or null if not found
 */
const getFromCache = async ({ hostname, cacheKey, isVaultReady }) => {
  if (!isVaultReady) return null

  try {
    const cachedBuffer = await activeVaultGetFile(cacheKey)
    if (cachedBuffer) {
      workletLogger.log('Favicon cache hit:', hostname)
      const base64 = Buffer.from(cachedBuffer).toString('base64')
      return `data:image/png;base64,${base64}`
    }
  } catch {
    // Ignore cache read errors, proceed to fetch
  }

  return null
}

/**
 * Saves a favicon to cache
 * @param {Object} params - The parameters object
 * @param {string} params.hostname - The hostname to save favicon for
 * @param {string} params.cacheKey - The cache key to use
 * @param {Buffer} params.buffer - The favicon image buffer
 * @param {boolean} params.isVaultReady - Whether the vault is initialized
 * @returns {Promise<void>}
 */
const saveToCache = async ({ hostname, cacheKey, buffer, isVaultReady }) => {
  if (!isVaultReady) return

  try {
    workletLogger.log('Storing favicon to cache:', hostname)
    await activeVaultAdd(
      cacheKey,
      { created_at: Date.now() },
      buffer,
      `${hostname}.png`
    )
  } catch (err) {
    workletLogger.warn('Failed to cache favicon:', err)
  }
}

export const faviconManager = {
  /**
   * Fetches a favicon for the given URL and returns it as a base64 data URI
   * @param {string} url - The domain URL to fetch favicon for
   * @returns {Promise<string|null>} Base64 data URI string or null if fetch fails
   */
  fetchFavicon: async (url) => {
    if (!url) return null

    const targetUrl = addHttps(url)
    const hostname = new URL(targetUrl).hostname
    const cacheKey = `favicon/${hostname}`
    const isVaultReady = getIsActiveVaultInitialized()

    const cachedFavicon = await getFromCache({
      hostname,
      cacheKey,
      isVaultReady
    })
    if (cachedFavicon) {
      return cachedFavicon
    }

    const faviconUrl = `https://www.google.com/s2/favicons?domain=${targetUrl}&sz=64`

    try {
      const imgResponse = await fetch(faviconUrl)

      workletLogger.log('Fetching favicon from network:', hostname)

      if (imgResponse.ok) {
        const arrayBuffer = await imgResponse.arrayBuffer()
        const buffer = Buffer.from(arrayBuffer)

        await saveToCache({ hostname, cacheKey, buffer, isVaultReady })

        const base64 = buffer.toString('base64')
        return `data:image/png;base64,${base64}`
      }
    } catch (error) {
      workletLogger.warn('Failed to fetch favicon image:', error)
    }

    return null
  }
}
