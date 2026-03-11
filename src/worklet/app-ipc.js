/** @typedef {import('bare')} */ /* global BareKit */
import fs from 'bare-fs'
import cenc from 'compact-encoding'

import { handleRpcCommand } from './appCore'
import { destroySharedDHT } from './utils/dht'
import { isPearWorker } from './utils/isPearWorker'
import { workletLogger } from './utils/workletLogger'

const ipc = isPearWorker()
  ? Pear.worker.pipe()
  : (typeof BareKit !== 'undefined' && BareKit?.IPC) ||
    global[Symbol.for('bare.sidecar.ipc')]

if (!ipc) {
  throw new Error(
    'Worklet IPC not available (not Pear worker and no bare.sidecar.ipc)'
  )
}

ipc.on('data', async (buffer) => {
  const rawData = buffer.toString('utf8')

  try {
    const { command, data } = JSON.parse(rawData)
    workletLogger.log('Received message:', { command, data })

    const req = {
      command: command,
      data: JSON.stringify(data),
      reply: (data) => {
        ipc.write(data)
      },
      createRequestStream: () => {
        if (data?.filePath) {
          const listeners = {}
          const stream = {
            on(event, cb) {
              listeners[event] = cb
              return stream
            }
          }
          queueMicrotask(() => {
            try {
              const metaData = { key: data.key, name: data.name }
              listeners.data?.(cenc.encode(cenc.json, metaData))
              listeners.data?.(fs.readFileSync(data.filePath))
              listeners.end?.()
            } catch (err) {
              listeners.error?.(err)
            }
          })
          return stream
        }
      },
      createResponseStream: () => {},
      send: () => {}
    }

    await handleRpcCommand(req)
  } catch (error) {
    workletLogger.error('Error receiving message:', error)
  }
})

ipc.on('close', async () => {
  await destroySharedDHT()
  // eslint-disable-next-line no-undef
  Bare.exit(0)
})

ipc.on('end', async () => {
  await destroySharedDHT()
  // eslint-disable-next-line no-undef
  Bare.exit(0)
})
