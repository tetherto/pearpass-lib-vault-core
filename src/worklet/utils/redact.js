export const REDACTED_FIELDS = [
  'password',
  'secret',
  'mnemonic',
  'seed',
  'privatekey',
  'encryptionkey',
  'decryptionkey',
  'vaultkey',
  'masterkey',
  'apikey',
  'token',
  'authorization',
  'cookie',
  'session',
  'nonce',
  'ciphertext'
]

const REDACTED_VALUE = '[REDACTED]'
const CIRCULAR_VALUE = '[Circular]'
const TRUNCATED_VALUE = '[Truncated]'
const MAX_DEPTH = 10

function isSensitiveKey(key) {
  const lower = String(key).toLowerCase()
  for (const f of REDACTED_FIELDS) {
    if (lower.includes(f)) return true
  }
  return false
}

function isPassThrough(v) {
  if (v === null) return true
  if (typeof v !== 'object') return true
  if (v instanceof Date || v instanceof Error || v instanceof RegExp)
    return true
  if (v instanceof Map || v instanceof Set) return true
  return ArrayBuffer.isView(v)
}

function redactInternal(value, visited, depth) {
  if (depth >= MAX_DEPTH) return TRUNCATED_VALUE
  if (isPassThrough(value)) return value

  if (visited.has(value)) return CIRCULAR_VALUE
  visited.add(value)

  if (Array.isArray(value)) {
    const out = []
    for (let i = 0; i < value.length; i++) {
      out.push(redactInternal(value[i], visited, depth + 1))
    }
    return out
  }

  const out = {}
  for (const key of Object.keys(value)) {
    if (isSensitiveKey(key)) {
      out[key] = REDACTED_VALUE
    } else {
      out[key] = redactInternal(value[key], visited, depth + 1)
    }
  }
  return out
}

export function redact(value) {
  return redactInternal(value, new WeakSet(), 0)
}

export function redactArgs(args) {
  return args.map(redact)
}
