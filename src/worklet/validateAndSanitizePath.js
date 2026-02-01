// validateAndSanitizePath.js
import fs from 'bare-fs'
import barePath from 'bare-path'

const WHITELISTED_DOT_DIRS = ['.config']

/**
 * Validates and sanitizes a storage path
 * @param {string} rawPath - The raw path to validate
 * @returns {string} - The sanitized path
 * @throws {Error} - If path is invalid or unsafe
 */
export const validateAndSanitizePath = (rawPath) => {
  if (!rawPath || typeof rawPath !== 'string') {
    throw new Error('Storage path must be a non-empty string')
  }

  // Strip file:// protocol if present
  let cleanPath = rawPath
  if (cleanPath.startsWith('file://')) {
    cleanPath = cleanPath.substring('file://'.length)
  }

  // Trim whitespace
  cleanPath = cleanPath.trim()

  if (cleanPath.length === 0) {
    throw new Error('Storage path cannot be empty after sanitization')
  }

  // Decode URL-encoded chars (e.g. %2e%2e) before validation. No practical risk
  // since storage paths come from trusted OS APIs and buildPath() provides
  // second-layer validation, but included for robustness and future-proofing.
  try {
    cleanPath = decodeURIComponent(cleanPath)
  } catch {
    throw new Error('Storage path contains invalid URL encoding')
  }

  // Check for null bytes before any processing (path traversal attack vector)
  if (cleanPath.includes('\0')) {
    throw new Error('Storage path contains invalid null bytes')
  }

  // Block Unicode control chars (C0/C1, zero-width, bidi overrides). No practical
  // traversal risk, but prevents display confusion and ensures path hygiene.
  const dangerousUnicodePattern =
    /[\u0001-\u001F\u007F-\u009F\u200B-\u200D\u202A-\u202E\u2066-\u2069\uFEFF]/
  if (dangerousUnicodePattern.test(cleanPath)) {
    throw new Error('Storage path contains invalid control characters')
  }

  if (!barePath.isAbsolute(cleanPath)) {
    throw new Error('Storage path must be an absolute path')
  }

  // Reject any path containing traversal sequences, except whitelisted dot directories
  if (cleanPath.includes('..') || cleanPath.includes('./')) {
    throw new Error(
      'Storage path must not contain traversal sequences (. or ..)'
    )
  }

  // Check for other dot sequences that aren't whitelisted
  const dotPattern = /\/\.([^/]+)/g
  const matches = [...cleanPath.matchAll(dotPattern)]
  for (const match of matches) {
    if (!WHITELISTED_DOT_DIRS.includes(`.${match[1]}`)) {
      throw new Error(
        'Storage path must not contain traversal sequences (. or ..)'
      )
    }
  }

  // Normalize path to remove redundant slashes and trailing slashes
  cleanPath = barePath.normalize(cleanPath)

  // Reject symlinks if path exists. No practical risk currently (all data is
  // encrypted), but included for future-proofing.
  try {
    const realPath = fs.realpathSync(cleanPath)
    if (realPath !== cleanPath) {
      throw new Error('Storage path must not be a symbolic link')
    }
  } catch (err) {
    // ENOENT = path doesn't exist yet, which is valid for new storage locations
    if (err.code !== 'ENOENT') {
      throw err
    }
  }

  return cleanPath
}
