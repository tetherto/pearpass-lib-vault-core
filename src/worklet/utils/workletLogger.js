import FileLog from 'bare-file-logger'
import SystemLog from 'bare-system-logger'

import { redactArgs } from './redact.js'

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 }
const DEFAULT_FILE_MAX_SIZE = 100_000_000

export class WorkletLogger {
  // Constructor stays silent unless the caller passes an explicit option.
  // The bare `new WorkletLogger()` singleton matches the previous noop
  // logger: nothing reaches `bare-system-logger` until the host opts in
  // via `configure(...)` (the SET_LOG_OPTIONS RPC).
  constructor(opts = {}) {
    const {
      dev = false,
      logFile,
      logLevel,
      logFileMaxSize = DEFAULT_FILE_MAX_SIZE
    } = opts
    this._dev = dev
    this._level = LEVELS[logLevel] ?? LEVELS.info
    const optedIn = 'logLevel' in opts || 'logFile' in opts || 'dev' in opts
    this._system = optedIn ? new SystemLog() : null
    this._file =
      typeof logFile === 'string' && logFile.length > 0
        ? new FileLog(logFile, { maxSize: logFileMaxSize })
        : null
  }

  configure({ dev, logFile, logLevel, logFileMaxSize } = {}) {
    if (typeof dev === 'boolean') this._dev = dev
    if (typeof logLevel === 'string' && logLevel in LEVELS) {
      this._level = LEVELS[logLevel]
    }
    // Calling configure is the host's opt-in to the system sink.
    if (!this._system) this._system = new SystemLog()
    // Explicit null disables file logging mid-session.
    // String swaps to a new file; undefined leaves the sink alone.
    if (logFile === null) {
      this._closeFile()
      this._file = null
    } else if (typeof logFile === 'string' && logFile.length > 0) {
      this._closeFile()
      this._file = new FileLog(logFile, {
        maxSize: logFileMaxSize || DEFAULT_FILE_MAX_SIZE
      })
    }
  }

  _closeFile() {
    if (this._file && typeof this._file.close === 'function') {
      try {
        this._file.close()
      } catch {
        // best-effort close
      }
    }
  }

  debug(...args) {
    this._write('debug', ...args)
  }

  info(...args) {
    this._write('info', ...args)
  }

  warn(...args) {
    this._write('warn', ...args)
  }

  error(...args) {
    this._write('error', ...args)
  }

  log(...args) {
    this.info(...args)
  }

  _write(level, ...args) {
    if (LEVELS[level] < this._level) return
    if (!this._system && !this._file) return
    const redacted = redactArgs(args)
    if (this._system) this._system[level](...redacted)
    if (this._file) this._file[level](...redacted)
    if (this._dev && this._level === LEVELS.debug) {
      // eslint-disable-next-line no-console
      const out = console[level] || console.log
      out(...redacted)
    }
  }
}

export const workletLogger = new WorkletLogger()
