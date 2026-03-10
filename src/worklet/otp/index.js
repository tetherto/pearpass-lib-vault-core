import * as OTPAuth from 'otpauth/dist/otpauth.esm.js'

import { OTP_TYPE } from '../../constants/otpType'

/**
 * @param {string} input
 * @returns {boolean}
 */
export const isOtpauthUri = (input) =>
  typeof input === 'string' && input.startsWith('otpauth://')

/**
 * Parses an otpauth:// URI into a structured OTP config object.
 * @param {string} uri
 * @returns {object}
 */
export const parseOtpauthUri = (uri) => {
  const parsed = OTPAuth.URI.parse(uri)

  const config = {
    secret: parsed.secret.base32,
    type: parsed instanceof OTPAuth.TOTP ? OTP_TYPE.TOTP : OTP_TYPE.HOTP,
    algorithm: parsed.algorithm,
    digits: parsed.digits
  }

  if (config.type === OTP_TYPE.TOTP) {
    config.period = parsed.period
  } else {
    config.counter = parsed.counter
  }

  if (parsed.issuer) {
    config.issuer = parsed.issuer
  }

  if (parsed.label) {
    config.label = parsed.label
  }

  return config
}

/**
 * Parses OTP input — either an otpauth:// URI or a raw Base32 secret.
 * Raw secrets default to TOTP / SHA1 / 6 digits / 30s period.
 * @param {string} input
 * @returns {object}
 */
export const parseOtpInput = (input) => {
  if (!input || typeof input !== 'string') {
    throw new Error('OTP input is required')
  }

  const trimmed = input.trim()

  if (isOtpauthUri(trimmed)) {
    return parseOtpauthUri(trimmed)
  }

  return {
    secret: trimmed,
    type: OTP_TYPE.TOTP,
    algorithm: 'SHA1',
    digits: 6,
    period: 30
  }
}

/**
 * Returns how many seconds remain in the current TOTP window.
 * @param {number} [period=30]
 * @returns {number}
 */
export const getTimeRemaining = (period = 30) => {
  const now = Math.floor(Date.now() / 1000)
  return period - (now % period)
}

/**
 * Generates a TOTP code from an OTP config object.
 * @param {object} otpConfig
 * @returns {{ code: string, timeRemaining: number }}
 */
export const generateTOTP = (otpConfig) => {
  const totp = new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(otpConfig.secret),
    algorithm: otpConfig.algorithm || 'SHA1',
    digits: otpConfig.digits || 6,
    period: otpConfig.period || 30,
    issuer: otpConfig.issuer,
    label: otpConfig.label
  })

  const code = totp.generate()
  const timeRemaining = getTimeRemaining(otpConfig.period || 30)

  return { code, timeRemaining }
}

/**
 * Generates an HOTP code from an OTP config object.
 * @param {object} otpConfig
 * @returns {{ code: string }}
 */
export const generateHOTP = (otpConfig) => {
  const hotp = new OTPAuth.HOTP({
    secret: OTPAuth.Secret.fromBase32(otpConfig.secret),
    algorithm: otpConfig.algorithm || 'SHA1',
    digits: otpConfig.digits || 6,
    counter: otpConfig.counter || 0,
    issuer: otpConfig.issuer,
    label: otpConfig.label
  })

  const code = hotp.generate({ counter: otpConfig.counter || 0 })

  return { code }
}
