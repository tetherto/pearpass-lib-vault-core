/**
 * Adds https protocol to URL if not present
 * @param {string} url
 * @returns {string}
 */
export const addHttps = (url) => {
  const lowerUrl = url.toLowerCase()
  return lowerUrl.startsWith('http://') || lowerUrl.startsWith('https://')
    ? lowerUrl
    : `https://${lowerUrl}`
}
