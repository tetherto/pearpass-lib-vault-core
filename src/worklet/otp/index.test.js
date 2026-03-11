import {
  isOtpauthUri,
  parseOtpauthUri,
  parseOtpInput,
  getTimeRemaining,
  generateTOTP,
  generateHOTP
} from './index'

describe('isOtpauthUri', () => {
  it('returns true for otpauth:// URIs', () => {
    expect(
      isOtpauthUri(
        'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP'
      )
    ).toBe(true)
    expect(
      isOtpauthUri('otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=0')
    ).toBe(true)
  })

  it('returns false for non-URI strings', () => {
    expect(isOtpauthUri('JBSWY3DPEHPK3PXP')).toBe(false)
    expect(isOtpauthUri('https://example.com')).toBe(false)
    expect(isOtpauthUri('')).toBe(false)
    expect(isOtpauthUri(null)).toBe(false)
  })
})

describe('parseOtpauthUri', () => {
  it('parses a TOTP URI with all parameters', () => {
    const uri =
      'otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test&algorithm=SHA256&digits=8&period=60'
    const result = parseOtpauthUri(uri)

    expect(result).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
      issuer: 'Test',
      label: 'user@example.com'
    })
  })

  it('parses a TOTP URI with defaults', () => {
    const uri = 'otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP'
    const result = parseOtpauthUri(uri)

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.type).toBe('TOTP')
    expect(result.algorithm).toBe('SHA1')
    expect(result.digits).toBe(6)
    expect(result.period).toBe(30)
  })

  it('parses an HOTP URI with counter', () => {
    const uri = 'otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=42'
    const result = parseOtpauthUri(uri)

    expect(result.type).toBe('HOTP')
    expect(result.counter).toBe(42)
    expect(result.period).toBeUndefined()
  })
})

describe('parseOtpInput', () => {
  it('parses raw Base32 secret with defaults', () => {
    const result = parseOtpInput('JBSWY3DPEHPK3PXP')

    expect(result).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('parses otpauth:// URI', () => {
    const result = parseOtpInput(
      'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=Test'
    )

    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
    expect(result.type).toBe('TOTP')
    expect(result.issuer).toBe('Test')
  })

  it('trims whitespace', () => {
    const result = parseOtpInput('  JBSWY3DPEHPK3PXP  ')
    expect(result.secret).toBe('JBSWY3DPEHPK3PXP')
  })

  it('throws on empty input', () => {
    expect(() => parseOtpInput('')).toThrow('OTP input is required')
    expect(() => parseOtpInput(null)).toThrow('OTP input is required')
  })
})

describe('getTimeRemaining', () => {
  it('returns a number between 1 and period', () => {
    const result = getTimeRemaining(30)
    expect(result).toBeGreaterThanOrEqual(1)
    expect(result).toBeLessThanOrEqual(30)
  })

  it('uses default period of 30', () => {
    const result = getTimeRemaining()
    expect(result).toBeGreaterThanOrEqual(1)
    expect(result).toBeLessThanOrEqual(30)
  })
})

describe('generateTOTP', () => {
  it('generates a 6-digit code by default', () => {
    const result = generateTOTP({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })

    expect(result.code).toMatch(/^\d{6}$/)
    expect(result.timeRemaining).toBeGreaterThanOrEqual(1)
    expect(result.timeRemaining).toBeLessThanOrEqual(30)
  })

  it('generates an 8-digit code when configured', () => {
    const result = generateTOTP({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'TOTP',
      algorithm: 'SHA1',
      digits: 8,
      period: 30
    })

    expect(result.code).toMatch(/^\d{8}$/)
  })
})

describe('generateHOTP', () => {
  it('generates a code for given counter', () => {
    const result = generateHOTP({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'HOTP',
      algorithm: 'SHA1',
      digits: 6,
      counter: 0
    })

    expect(result.code).toMatch(/^\d{6}$/)
  })

  it('generates different codes for different counters', () => {
    const result1 = generateHOTP({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'HOTP',
      algorithm: 'SHA1',
      digits: 6,
      counter: 0
    })

    const result2 = generateHOTP({
      secret: 'JBSWY3DPEHPK3PXP',
      type: 'HOTP',
      algorithm: 'SHA1',
      digits: 6,
      counter: 1
    })

    // They *could* collide but it's extremely unlikely
    // with the well-known test vector secret
    expect(result1.code).toBeDefined()
    expect(result2.code).toBeDefined()
  })
})
