import Autopass from 'autopass'
import Corestore from 'corestore'

import { getConfig } from './utils/swarm'

export class PearPassPairer {
  constructor() {
    /**
     * @type {Corestore | null}
     */
    this.store = null
    /**
     * @type {any | null}
     */
    this.pair = null
    /**
     * Used to serialize cleanup so we don't leave partially-closed resources around.
     * @type {Promise<void>}
     */
    this._cleanupInFlight = Promise.resolve()
  }

  async pairInstance(path, invite) {
    // We start from a clean state (important after timeouts / expired invites).
    await this.cancelPairing()

    const store = new Corestore(path)
    this.store = store

    if (!store) {
      throw new Error('Error creating store')
    }

    const conf = await getConfig(store)

    const pair = Autopass.pair(store, invite, {
      relayThrough: conf.current.blindRelays
    })
    this.pair = pair

    try {
      const instance = await pair.finished()
      await instance.ready()

      const encryptionKey = instance.encryptionKey.toString('base64')

      await instance.close()
      return encryptionKey
    } catch (error) {
      throw new Error(`Pairing failed: ${error.message}`)
    } finally {
      await this.cancelPairing()
    }
  }

  async cancelPairing() {
    // Serialize cleanup to avoid races between pairInstance() finally and an explicit cancel RPC.
    this._cleanupInFlight = this._cleanupInFlight.then(async () => {
      const pair = this.pair
      const store = this.store

      // Clear references first so concurrent callers won't try to reuse half-closed resources.
      this.pair = null
      this.store = null

      if (pair) {
        try {
          await pair.close()
        } catch {
          // Ignore close errors
        }
      }

      if (store) {
        try {
          await store.close()
        } catch {
          // Ignore close errors
        }
      }
    })

    await this._cleanupInFlight
  }
}
