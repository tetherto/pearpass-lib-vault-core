import { logger } from './logger'
import {
  isValidInviteCodeFormat,
  validateInviteCode
} from './validateInviteCode.js'

jest.mock('./logger.js', () => ({
  logger: {
    error: jest.fn()
  }
}))

describe('isValidInviteCodeFormat', () => {
  it('accepts a valid invite code with hyphens and a single slash', () => {
    expect(
      isValidInviteCodeFormat(
        '196029f9-777b-428a-8f20-61130482b12d/yry4pdqoh6rp8qpi7rizmrrbik3f6789cxaj6o5xakauxadiy1dnd88dzmjzer576zrxomm78a7br665jsfdq1j3361th99d6retsobnra'
      )
    ).toBe(true)
  })

  it('accepts a legacy invite code', () => {
    expect(
      isValidInviteCodeFormat(
        'mk2a7bnvuujzyw706qh/yry9qnyupy4eauuubxfsh1bd8hf3suftz4wbszu3gafm51ym7aax4rmsm5t771w9g8d55rekyrp95k3458gtmegrybmdip9g9n3p5snp8e'
      )
    ).toBe(true)
  })

  it('rejects code with multiple slashes', () => {
    expect(isValidInviteCodeFormat('a'.repeat(50) + '/b'.repeat(51))).toBe(
      false
    )
  })

  it('rejects code without a slash', () => {
    expect(isValidInviteCodeFormat('a'.repeat(120))).toBe(false)
  })

  it('rejects code shorter than the minimum length', () => {
    expect(isValidInviteCodeFormat('a'.repeat(99))).toBe(false)
  })

  it('rejects code with invalid characters', () => {
    expect(
      isValidInviteCodeFormat('a'.repeat(50) + '!@#$%^&*()' + 'a'.repeat(50))
    ).toBe(false)
  })

  it('rejects code with more than two segments', () => {
    expect(
      isValidInviteCodeFormat(
        'a'.repeat(50) + '/b'.repeat(30) + '/c'.repeat(30)
      )
    ).toBe(false)
  })

  it('rejects non-string input', () => {
    expect(isValidInviteCodeFormat(null)).toBe(false)
    expect(isValidInviteCodeFormat(undefined)).toBe(false)
    expect(isValidInviteCodeFormat(123)).toBe(false)
  })
})

describe('validateInviteCode', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('returns the code when it is valid', () => {
    const code =
      '196029f9-777b-428a-8f20-61130482b12d/yry4pdqoh6rp8qpi7rizmrrbik3f6789cxaj6o5xakauxadiy1dnd88dzmjzer576zrxomm78a7br665jsfdq1j3361th99d6retsobnra'
    expect(validateInviteCode(code)).toBe(code)
    expect(logger.error).not.toHaveBeenCalled()
  })

  it('logs and throws when the code is invalid', () => {
    expect(() => validateInviteCode('a'.repeat(50))).toThrow(
      'Invalid invite code'
    )
    expect(logger.error).toHaveBeenCalled()
  })
})
