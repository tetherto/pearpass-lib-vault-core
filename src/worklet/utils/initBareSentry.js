let initialized = false

/**
 * Optional peer-dep gateway for `sentry-bare`. The package is only
 * installed in non-public builds (e.g. nightly), so the dynamic import
 * keeps this module load-safe in public / self-built distributions.
 *
 * The host is responsible for gating: it must only send `sentryDsn` over
 * SET_LOG_OPTIONS for nightly, non-dev runs. This function trusts that
 * gate and initializes whenever a DSN is provided.
 *
 * Default integrations are disabled because sentry-bare's
 * onUncaughtException / onUnhandledRejection integrations call
 * `Bare.exit()` when no other listener is registered, which would tear
 * down the worker without graceful RPC teardown.
 *
 * Idempotent — subsequent calls are no-ops once initialized.
 *
 * @param {string} dsn - Sentry DSN; required to initialize
 * @returns {Promise<void>}
 */
export async function initBareSentry(dsn) {
  if (initialized || !dsn) return

  let Sentry
  try {
    Sentry = await import('sentry-bare')
  } catch {
    return
  }

  Sentry.init({
    dsn,
    environment: 'nightly',
    defaultIntegrations: false,
    integrations: [Sentry.contextIntegration()]
  })
  initialized = true
}
