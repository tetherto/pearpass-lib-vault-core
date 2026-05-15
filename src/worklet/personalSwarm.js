import b4a from 'b4a'
import Hyperswarm from 'hyperswarm'

import { getVaultsInstance } from './appDeps'
import { getConfig } from './utils/swarm'
import { workletLogger } from './utils/workletLogger'

const FRAME_HEADER_BYTES = 4
const MAX_ENVELOPE_BYTES = 64 * 1024
const SEND_LOOKUP_TIMEOUT_MS = 30_000

let swarm = null
let topicBuffer = null
let envelopeListener = null
const pendingSends = new Map()

export const isPersonalSwarmRunning = () => swarm !== null

export const personalSwarmInit = async () => {
  if (swarm !== null) {
    return { topic: b4a.toString(topicBuffer, 'hex') }
  }

  const vaultsInstance = getVaultsInstance()
  if (!vaultsInstance) {
    throw new Error('personalSwarmInit: master vault not initialised')
  }

  const localWriterKey = vaultsInstance.base?.local?.key
  if (!localWriterKey) {
    throw new Error('personalSwarmInit: master vault has no local writer')
  }
  topicBuffer = b4a.from(localWriterKey)

  const store = vaultsInstance.store
  const conf = await getConfig(store)

  swarm = new Hyperswarm({
    keyPair: await store.createKeyPair('personal-swarm'),
    relayThrough: conf?.current?.blindRelays ?? null
  })

  swarm.on('connection', (connection, peerInfo) => {
    if (matchPendingSend(connection, peerInfo)) return
    handleIncomingConnection(connection).catch((err) => {
      workletLogger.error('personalSwarm: connection handler failed', { err })
    })
  })

  await swarm.join(topicBuffer, { server: true, client: false }).flushed()
  workletLogger.debug('personalSwarm: listening', {
    topic: b4a.toString(topicBuffer, 'hex')
  })

  return { topic: b4a.toString(topicBuffer, 'hex') }
}

export const personalSwarmClose = async () => {
  if (swarm === null) return
  try {
    await swarm.destroy()
  } catch (err) {
    workletLogger.error('personalSwarm: destroy failed', { err })
  }
  swarm = null
  topicBuffer = null
  pendingSends.clear()
}

export const personalSwarmGetTopic = () => {
  if (!topicBuffer) return null
  return b4a.toString(topicBuffer, 'hex')
}

/**
 * @param {(envelopeHex: string, peerInfo: { remotePublicKey: string }) => void} handler
 */
export const personalSwarmOnEnvelope = (handler) => {
  envelopeListener = handler
}

/**
 * @returns {Promise<{ ok: true } | { ok: false, reason: string }>}
 */
export const personalSwarmSend = async (targetTopicHex, envelopeHex) => {
  if (!targetTopicHex || !envelopeHex) {
    return { ok: false, reason: 'missing-args' }
  }
  if (swarm === null) {
    return { ok: false, reason: 'swarm-not-initialised' }
  }
  if (pendingSends.has(targetTopicHex)) {
    return { ok: false, reason: 'already-pending' }
  }

  const targetTopic = b4a.from(targetTopicHex, 'hex')
  const envelopeBytes = b4a.from(envelopeHex, 'hex')
  if (envelopeBytes.length > MAX_ENVELOPE_BYTES) {
    return { ok: false, reason: 'envelope-too-large' }
  }

  return new Promise((resolve) => {
    let resolved = false

    const finish = (next) => {
      if (resolved) return
      resolved = true
      clearTimeout(timeout)
      pendingSends.delete(targetTopicHex)
      resolve(next)
    }

    const timeout = setTimeout(() => {
      finish({ ok: false, reason: 'lookup-timeout' })
    }, SEND_LOOKUP_TIMEOUT_MS)

    pendingSends.set(targetTopicHex, {
      targetTopic,
      envelopeBytes,
      finish
    })

    swarm
      .join(targetTopic, { server: false, client: true })
      .flushed()
      .catch((err) => {
        workletLogger.error('personalSwarm: send join failed', { err })
        finish({ ok: false, reason: 'join-failed' })
      })
  })
}

function matchPendingSend(connection, peerInfo) {
  if (!peerInfo?.client) return false
  for (const pending of pendingSends.values()) {
    if (peerInfo.topics?.some((t) => b4a.equals(t, pending.targetTopic))) {
      writeFramed(connection, pending.envelopeBytes)
        .then(() => pending.finish({ ok: true }))
        .catch((err) => {
          workletLogger.error('personalSwarm: send failed', { err })
          pending.finish({
            ok: false,
            reason: `write-failed: ${err?.message ?? err}`
          })
        })
      return true
    }
  }
  return false
}

async function handleIncomingConnection(connection) {
  try {
    const envelopeBytes = await readFramed(connection)
    if (!envelopeListener) return

    const peerInfo = {
      remotePublicKey: connection.remotePublicKey
        ? b4a.toString(connection.remotePublicKey, 'hex')
        : ''
    }
    envelopeListener(b4a.toString(envelopeBytes, 'hex'), peerInfo)
  } finally {
    try {
      connection.end()
    } catch {}
  }
}

function writeFramed(connection, bytes) {
  return new Promise((resolve, reject) => {
    const header = b4a.alloc(FRAME_HEADER_BYTES)
    header.writeUInt32BE(bytes.length, 0)

    let done = false
    let writesQueued = false
    const finish = (err) => {
      if (done) return
      done = true
      if (err) reject(err)
      else resolve()
    }

    connection.once('error', (err) => {
      if (writesQueued) return finish()
      finish(err)
    })

    try {
      connection.write(header)
      connection.write(bytes)
      connection.end()
      writesQueued = true
    } catch (err) {
      return finish(err)
    }

    setTimeout(() => finish(), 100)
  })
}

async function readFramed(connection) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let expected = null
    let received = 0

    const finish = (err, bytes) => {
      connection.removeAllListeners('data')
      connection.removeAllListeners('end')
      connection.removeAllListeners('error')
      if (err) reject(err)
      else resolve(bytes)
    }

    connection.on('data', (chunk) => {
      chunks.push(chunk)
      received += chunk.length
      if (expected === null && received >= FRAME_HEADER_BYTES) {
        const head = b4a.concat(chunks).slice(0, FRAME_HEADER_BYTES)
        expected = head.readUInt32BE(0)
        if (expected > MAX_ENVELOPE_BYTES) {
          return finish(new Error('frame-too-large'))
        }
      }
      if (expected !== null && received >= FRAME_HEADER_BYTES + expected) {
        const all = b4a.concat(chunks)
        finish(
          null,
          all.slice(FRAME_HEADER_BYTES, FRAME_HEADER_BYTES + expected)
        )
      }
    })

    connection.on('end', () => {
      if (expected !== null) return
      finish(new Error('peer-ended-before-frame'))
    })

    connection.on('error', (err) => finish(err))
  })
}
