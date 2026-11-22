/**
 * KIRON PROHORI — Server API Controllers (/server/controllers/index.ts)
 * Provides structured controller helpers for connector status, keyless startup diagnostics, and security health.
 */

import { getOptionalConfiguredSecret } from '../validators';
import { CONNECTOR_ENDPOINTS } from '../connectors';

export interface StartupConnectorConfigSummary {
  cisaKevMode: 'KEYLESS_DIRECT_JSON_FEED';
  nvdMode: 'UNAUTHENTICATED_PUBLIC_RATE_LIMIT' | 'AUTHENTICATED_SERVER_KEY';
  urlhausStatus: 'NOT CONFIGURED' | 'CONFIGURED';
  zeroCostCompliant: true;
  endpoints: typeof CONNECTOR_ENDPOINTS;
}

/**
 * Returns the current startup configuration summary without requiring NVD_API_KEY or URLHAUS_AUTH_KEY.
 */
export function getStartupConnectorConfigSummary(): StartupConnectorConfigSummary {
  const nvdKey = getOptionalConfiguredSecret(process.env.NVD_API_KEY);
  const urlhausKey = getOptionalConfiguredSecret(process.env.URLHAUS_AUTH_KEY);

  return {
    cisaKevMode: 'KEYLESS_DIRECT_JSON_FEED',
    nvdMode: nvdKey ? 'AUTHENTICATED_SERVER_KEY' : 'UNAUTHENTICATED_PUBLIC_RATE_LIMIT',
    urlhausStatus: urlhausKey ? 'CONFIGURED' : 'NOT CONFIGURED',
    zeroCostCompliant: true,
    endpoints: CONNECTOR_ENDPOINTS,
  };
}
