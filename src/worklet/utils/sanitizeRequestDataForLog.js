const KEYED_PAYLOAD_COMMANDS = new Set([
  'MASTER_VAULT_ADD',
  'ACTIVE_VAULT_ADD'
])

const BLIND_MIRROR_COMMANDS = new Set([
  'BLIND_MIRRORS_ADD',
  'BLIND_MIRROR_REMOVE'
])

// Fields ./redact.js doesn't catch by name.
const COMMAND_SENSITIVE_FIELDS = {
  ENCRYPTION_ENCRYPT_VAULT_WITH_KEY: ['key'],
  ADD_OTP_TO_RECORD: ['otpInput']
}

const REDACTED = '[REDACTED]'

const redactKeyedPayload = (requestData) => {
  if (typeof requestData.key !== 'string') return requestData
  const data = requestData.data
  if (!data || typeof data !== 'object') return requestData

  if (requestData.key.startsWith('vault/')) {
    if (data.name === undefined) return requestData
    return {
      ...requestData,
      data: { ...data, name: REDACTED }
    }
  }

  if (requestData.key.startsWith('record/')) {
    const next = { ...data }
    let changed = false
    if (next.data !== undefined) {
      next.data = REDACTED
      changed = true
    }
    if (typeof next.folder === 'string' && next.folder.length > 0) {
      next.folder = REDACTED
      changed = true
    }
    if (!changed) return requestData
    return { ...requestData, data: next }
  }

  return requestData
}

const redactFaviconUrl = (requestData) => {
  if (typeof requestData.url !== 'string') return requestData
  return { ...requestData, url: REDACTED }
}

const redactBlindMirrorCommand = (requestData) => {
  const next = { ...requestData }
  let changed = false

  if (Array.isArray(next.blindMirrors)) {
    next.blindMirrors = next.blindMirrors.map(() => REDACTED)
    changed = true
  }

  if (typeof next.key === 'string') {
    next.key = REDACTED
    changed = true
  }

  return changed ? next : requestData
}

const redactSensitiveFields = (requestData, fields) => {
  const next = { ...requestData }
  let changed = false
  for (const field of fields) {
    if (next[field] !== undefined) {
      next[field] = REDACTED
      changed = true
    }
  }
  return changed ? next : requestData
}

// Strips PII from a command payload before it hits the shared diagnostic log.
export const sanitizeRequestDataForLog = (commandName, requestData) => {
  if (!requestData || typeof requestData !== 'object') return requestData

  if (KEYED_PAYLOAD_COMMANDS.has(commandName)) {
    return redactKeyedPayload(requestData)
  }

  if (commandName === 'FETCH_FAVICON') {
    return redactFaviconUrl(requestData)
  }

  if (BLIND_MIRROR_COMMANDS.has(commandName)) {
    return redactBlindMirrorCommand(requestData)
  }

  const sensitiveFields = COMMAND_SENSITIVE_FIELDS[commandName]
  if (sensitiveFields) {
    return redactSensitiveFields(requestData, sensitiveFields)
  }

  return requestData
}
