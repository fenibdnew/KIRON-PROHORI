/**
 * KIRON PROHORI — Server Input & SSRF Outbound Validators (/server/validators/index.ts)
 * Rejects placeholder/fake API keys, enforces SSRF outbound host allowlists, and validates client payloads.
 */

import { ALLOWED_OUTBOUND_HOSTS } from '../../shared/constants';
export * from '../../shared/schemas';

const ALLOWED_HOST_SET = new Set<string>(ALLOWED_OUTBOUND_HOSTS);

/**
 * Evaluates optional server-side environment variables (such as NVD_API_KEY or URLHAUS_AUTH_KEY).
 * Never uses fake keys, short strings, or placeholder values.
 */
export function getOptionalConfiguredSecret(rawValue: string | undefined): string | null {
  if (!rawValue) return null;
  const trimmed = rawValue.trim();
  if (trimmed.length <= 8) return null;
  const lower = trimmed.toLowerCase();
  if (
    lower.startsWith('my_') ||
    lower.startsWith('your_') ||
    lower.includes('placeholder') ||
    lower.includes('example') ||
    lower.includes('fake') ||
    lower.includes('dummy') ||
    lower === 'undefined' ||
    lower === 'null' ||
    lower === 'none'
  ) {
    return null;
  }
  return trimmed;
}

/**
 * Verifies that an outbound server fetch URL targets only an explicitly authorized
 * HTTPS public threat intelligence host (prevents Server-Side Request Forgery / SSRF).
 */
export function verifyAllowedOutboundUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:') {
    throw new Error(`SSRF Guard: Blocked non-HTTPS outbound protocol '${parsed.protocol}'`);
  }
  if (!ALLOWED_HOST_SET.has(parsed.hostname)) {
    throw new Error(`SSRF Guard: Outbound host '${parsed.hostname}' is not in ALLOWED_OUTBOUND_HOSTS`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('SSRF Guard: Blocked embedded URL credentials');
  }
  return parsed;
}
