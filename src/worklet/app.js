import { workletLogger } from './utils/workletLogger'

// Prevent worklet crash from transient socket errors during
// suspend / resume cycles. OS tears down TCP connections while
// the app is backgrounded; when the Bare event-loop resumes,
// bare-tcp tries to clean up already-dead sockets and throws
// ENOTCONN. Without this handler the error is uncaught and
// Bare calls abort() -> SIGABRT.
const RECOVERABLE_SOCKET_ERRORS = new Set([
  'ENOTCONN',
  'ECONNRESET',
  'EPIPE',
  'ETIMEDOUT',
  'ECONNABORTED'
])

Bare.on('uncaughtException', (err) => {
  if (RECOVERABLE_SOCKET_ERRORS.has(err.code)) {
    workletLogger.warn('Suppressed recoverable socket error:', err.code, err.message)
    return // swallow - do not crash
  }

  workletLogger.error('Uncaught worklet exception:', err)
  throw err // re-throw non-socket errors to preserve default behaviour
})

let rpc
;(async () => {
  try {
    const { setupIPC, createRPC } = await import('./appCore.js')

    const ipc = setupIPC()
    rpc = createRPC(ipc)
  } catch (error) {
    workletLogger.error('Fatal error in app initialization:', error)
  }
})()

export { rpc }
