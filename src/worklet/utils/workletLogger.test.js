const mockSystemSink = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
}
const mockFileSink = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  close: jest.fn()
}

jest.mock('bare-system-logger', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => mockSystemSink)
}))
jest.mock('bare-file-logger', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => mockFileSink)
}))

const { WorkletLogger } = require('./workletLogger.js')

beforeEach(() => {
  jest.clearAllMocks()
})

describe('WorkletLogger', () => {
  test('default level is info — debug is filtered', () => {
    const log = new WorkletLogger()
    log.debug('debug-msg')
    expect(mockSystemSink.debug).not.toHaveBeenCalled()
  })

  test('info level emits to system sink', () => {
    const log = new WorkletLogger()
    log.info('hello')
    expect(mockSystemSink.info).toHaveBeenCalledWith('hello')
  })

  test('logLevel="debug" lets debug through', () => {
    const log = new WorkletLogger({ logLevel: 'debug' })
    log.debug('debug-msg')
    expect(mockSystemSink.debug).toHaveBeenCalledWith('debug-msg')
  })

  test('file sink only when logFile set', () => {
    const log = new WorkletLogger()
    log.info('no-file')
    expect(mockFileSink.info).not.toHaveBeenCalled()
  })

  test('file sink fires when configure passes logFile', () => {
    const log = new WorkletLogger()
    log.configure({ logFile: '/tmp/x.log' })
    log.info('with-file')
    expect(mockFileSink.info).toHaveBeenCalledWith('with-file')
  })

  test('configure replacing logFile closes previous sink', () => {
    const log = new WorkletLogger()
    log.configure({ logFile: '/tmp/a.log' })
    const firstClose = mockFileSink.close
    log.configure({ logFile: '/tmp/b.log' })
    expect(firstClose).toHaveBeenCalled()
  })

  test('configure with logFile=null closes existing sink and disables file logging', () => {
    const log = new WorkletLogger()
    log.configure({ logFile: '/tmp/a.log' })
    log.configure({ logFile: null })
    expect(mockFileSink.close).toHaveBeenCalled()
    log.info('after-disable')
    expect(mockFileSink.info).not.toHaveBeenCalled()
  })

  test('redaction applied before sinks', () => {
    const log = new WorkletLogger({ logLevel: 'info' })
    log.info('user', { password: 'secret' })
    expect(mockSystemSink.info).toHaveBeenCalledWith('user', {
      password: '[REDACTED]'
    })
  })

  test('compat shim: setLogOutput exists and does not throw', () => {
    const log = new WorkletLogger()
    expect(() => log.setLogOutput(() => {})).not.toThrow()
  })

  test('compat shim: setDebugMode exists and does not throw', () => {
    const log = new WorkletLogger()
    expect(() => log.setDebugMode(true)).not.toThrow()
  })

  test('compat shim: .log() aliases .info()', () => {
    const log = new WorkletLogger()
    log.log('alias')
    expect(mockSystemSink.info).toHaveBeenCalledWith('alias')
  })
})
