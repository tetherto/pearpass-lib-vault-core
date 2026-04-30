import { logger } from './logger'

const INVITE_CODE_REGEX = /^[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+$/
const INVITE_CODE_MIN_LENGTH = 100

export const isValidInviteCodeFormat = (value) =>
  typeof value === 'string' &&
  value.length >= INVITE_CODE_MIN_LENGTH &&
  INVITE_CODE_REGEX.test(value)

export const validateInviteCode = (code) => {
  if (isValidInviteCodeFormat(code)) {
    return code
  }

  const errors = { code: 'Invalid invite code format' }
  logger.error(`Invalid invite code: ${JSON.stringify(errors, null, 2)}`)
  throw new Error(`Invalid invite code: ${JSON.stringify(errors, null, 2)}`)
}
