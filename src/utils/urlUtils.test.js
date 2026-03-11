import { addHttps } from './urlUtils.js'

describe('urlUtils', () => {
  describe('addHttps', () => {
    test('should add https:// to URL without protocol', () => {
      const result = addHttps('example.com')
      expect(result).toBe('https://example.com')
    })

    test('should preserve existing https:// protocol', () => {
      const result = addHttps('https://example.com')
      expect(result).toBe('https://example.com')
    })

    test('should preserve existing http:// protocol', () => {
      const result = addHttps('http://example.com')
      expect(result).toBe('http://example.com')
    })

    test('should add https:// to subdomain URLs', () => {
      const result = addHttps('www.example.com')
      expect(result).toBe('https://www.example.com')
    })

    test('should add https:// to URLs with paths', () => {
      const result = addHttps('example.com/path/to/page')
      expect(result).toBe('https://example.com/path/to/page')
    })

    test('should preserve protocol for URLs with paths', () => {
      const result = addHttps('https://example.com/path/to/page')
      expect(result).toBe('https://example.com/path/to/page')
    })

    test('should handle URLs with query parameters', () => {
      const result = addHttps('example.com?param=value')
      expect(result).toBe('https://example.com?param=value')
    })

    test('should handle URLs with ports', () => {
      const result = addHttps('example.com:8080')
      expect(result).toBe('https://example.com:8080')
    })
  })
})
