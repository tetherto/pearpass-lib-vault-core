global.BareKit = {
  IPC: {
    on: jest.fn(),
    off: jest.fn(),
    emit: jest.fn()
  }
}

global.Bare = {
  platform: 'posix',
  on: jest.fn()
}
