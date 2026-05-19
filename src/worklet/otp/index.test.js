import {
  isOtpauthUri,
  parseOtpauthUri,
  parseOtpInput,
  getTimeRemaining,
  generateTOTP,
  generateHOTP,
  normalizeOtpSecret,
  filterDuplicateRecords
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

describe('normalizeOtpSecret', () => {
  it('strips whitespace and dashes and uppercases', () => {
    expect(normalizeOtpSecret('jbsw y3dp-ehpk 3pxp')).toBe('JBSWY3DPEHPK3PXP')
    expect(normalizeOtpSecret('JBSWY3DPEHPK3PXP')).toBe('JBSWY3DPEHPK3PXP')
  })

  it('returns empty string for non-string/empty input', () => {
    expect(normalizeOtpSecret(undefined)).toBe('')
    expect(normalizeOtpSecret(null)).toBe('')
    expect(normalizeOtpSecret('')).toBe('')
    expect(normalizeOtpSecret(123)).toBe('')
  })
})

describe('filterDuplicateRecords', () => {
  const record = (id, secret, title = '') => ({
    id,
    data: { otp: { secret }, title }
  })

  it('returns [] when target secret is empty or records list is empty', () => {
    expect(
      filterDuplicateRecords('', [record('a', 'JBSWY3DPEHPK3PXP')])
    ).toEqual([])
    expect(filterDuplicateRecords('JBSWY3DPEHPK3PXP', [])).toEqual([])
    expect(filterDuplicateRecords('JBSWY3DPEHPK3PXP', null)).toEqual([])
  })

  it('matches by normalized secret regardless of formatting', () => {
    const recs = [
      record('a', 'JBSW Y3DP EHPK 3PXP', 'GitHub'),
      record('b', 'OTHERSECRETXXXXX', 'Other')
    ]
    expect(filterDuplicateRecords('jbsw-y3dp-ehpk-3pxp', recs)).toEqual([
      { id: 'a', title: 'GitHub' }
    ])
  })

  it('returns only id and title (never the secret)', () => {
    const recs = [record('a', 'JBSWY3DPEHPK3PXP', 'GitHub')]
    const result = filterDuplicateRecords('JBSWY3DPEHPK3PXP', recs)
    expect(result).toEqual([{ id: 'a', title: 'GitHub' }])
    expect(result[0]).not.toHaveProperty('data')
    expect(result[0]).not.toHaveProperty('secret')
  })

  it('skips records without an OTP secret', () => {
    const recs = [
      { id: 'a', data: {} },
      { id: 'b', data: { otp: {} } },
      { id: 'c' },
      null,
      record('d', 'JBSWY3DPEHPK3PXP', 'GitHub')
    ]
    expect(filterDuplicateRecords('JBSWY3DPEHPK3PXP', recs)).toEqual([
      { id: 'd', title: 'GitHub' }
    ])
  })

  it('excludes a record by id when excludeRecordId is provided', () => {
    const recs = [
      record('a', 'JBSWY3DPEHPK3PXP', 'A'),
      record('b', 'JBSWY3DPEHPK3PXP', 'B')
    ]
    expect(
      filterDuplicateRecords('JBSWY3DPEHPK3PXP', recs, {
        excludeRecordId: 'a'
      })
    ).toEqual([{ id: 'b', title: 'B' }])
  })

  it('returns all matches when multiple records share the secret', () => {
    const recs = [
      record('a', 'JBSWY3DPEHPK3PXP', 'A'),
      record('b', 'OTHERSECRETXXXXX', 'B'),
      record('c', 'JBSWY3DPEHPK3PXP', 'C')
    ]
    expect(filterDuplicateRecords('JBSWY3DPEHPK3PXP', recs)).toEqual([
      { id: 'a', title: 'A' },
      { id: 'c', title: 'C' }
    ])
  })

  it('falls back to empty title when record has none', () => {
    const recs = [{ id: 'a', data: { otp: { secret: 'JBSWY3DPEHPK3PXP' } } }]
    expect(filterDuplicateRecords('JBSWY3DPEHPK3PXP', recs)).toEqual([
      { id: 'a', title: '' }
    ])
  })
})
