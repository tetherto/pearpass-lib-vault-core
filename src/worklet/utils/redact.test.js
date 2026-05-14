import { redact, redactArgs, REDACTED_FIELDS } from './redact.js'

describe('redact()', () => {
  test('top-level sensitive key', () => {
    expect(redact({ password: 'x' })).toEqual({ password: '[REDACTED]' })
  })

  test('nested sensitive key', () => {
    expect(redact({ vault: { encryptionKey: 'x' } })).toEqual({
      vault: { encryptionKey: '[REDACTED]' }
    })
  })

  test('array of objects — only sensitive ones redacted', () => {
    expect(redact([{ token: 't' }, { name: 'ok' }])).toEqual([
      { token: '[REDACTED]' },
      { name: 'ok' }
    ])
  })

  test('Buffer at sensitive key', () => {
    expect(redact({ password: Buffer.from('x') })).toEqual({
      password: '[REDACTED]'
    })
  })

  test('Buffer at non-sensitive key passes through', () => {
    const buf = Buffer.from('x')
    expect(redact({ data: buf })).toEqual({ data: buf })
  })

  test('case insensitivity — capitalized', () => {
    expect(redact({ Password: 'x' })).toEqual({ Password: '[REDACTED]' })
  })

  test('case insensitivity — uppercase compound', () => {
    expect(redact({ HASHEDPASSWORD: 'x' })).toEqual({
      HASHEDPASSWORD: '[REDACTED]'
    })
  })

  test('cycle becomes [Circular]', () => {
    const obj = { a: 1 }
    obj.self = obj
    const result = redact(obj)
    expect(result.a).toBe(1)
    expect(result.self).toBe('[Circular]')
  })

  test('depth cap', () => {
    let deep = { v: 'leaf' }
    for (let i = 0; i < 11; i++) deep = { nested: deep }
    const result = redact(deep)
    // Walk 10 levels down; 11th should be truncated
    let cursor = result
    for (let i = 0; i < 10; i++) cursor = cursor.nested
    expect(cursor).toBe('[Truncated]')
  })

  test('passes through primitives', () => {
    expect(redact(1)).toBe(1)
    expect(redact('hi')).toBe('hi')
    expect(redact(null)).toBe(null)
    expect(redact(undefined)).toBe(undefined)
    expect(redact(true)).toBe(true)
  })

  test('passes through Date / Error / RegExp / function unchanged', () => {
    const d = new Date()
    const e = new Error('boom')
    const r = /x/
    const f = () => 1
    expect(redact(d)).toBe(d)
    expect(redact(e)).toBe(e)
    expect(redact(r)).toBe(r)
    expect(redact(f)).toBe(f)
  })

  test('input not mutated', () => {
    const input = { password: 'x', other: 'y' }
    redact(input)
    expect(input.password).toBe('x')
  })

  test('publicKey is NOT redacted (no privatekey substring match)', () => {
    expect(redact({ publicKey: 'pubval' })).toEqual({ publicKey: 'pubval' })
  })

  test('inviteCode / pairingCode / mirrorKey / sentryDsn redacted', () => {
    expect(
      redact({
        inviteCode: 'abc',
        pairingCode: 'xyz',
        mirrorKey: 'mk',
        sentryDsn: 'https://x@sentry.io/1'
      })
    ).toEqual({
      inviteCode: '[REDACTED]',
      pairingCode: '[REDACTED]',
      mirrorKey: '[REDACTED]',
      sentryDsn: '[REDACTED]'
    })
  })
})

describe('redactArgs()', () => {
  test('maps redact across each arg', () => {
    const args = ['msg', { password: 'x' }, 42]
    expect(redactArgs(args)).toEqual(['msg', { password: '[REDACTED]' }, 42])
  })
})

describe('REDACTED_FIELDS', () => {
  test('includes core sensitive fields', () => {
    expect(REDACTED_FIELDS).toEqual(
      expect.arrayContaining([
        'password',
        'secret',
        'mnemonic',
        'seed',
        'privatekey',
        'token'
      ])
    )
  })
})
