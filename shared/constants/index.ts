/**
 * KIRON PROHORI — Shared Platform Constants (/shared/constants/index.ts)
 * Independent Cyber Threat Intelligence Platform (v0.1.0, Strict $0.00 Budget)
 */

export * from '../../src/data/moduleDefinitions';
export { MANDATORY_REPORT_DISCLAIMER, SECURITY_CHECKLIST_TRACKS } from '../../src/toolkit/engine';
export { EXTERNAL_API_DEPENDENCIES_MATRIX } from '../../src/qa/phase6.test';

export const APP_NAME = 'KIRON PROHORI';
export const APP_NAME_BN = 'কিরণ প্রহরী';
export const APP_VERSION = '0.1.0';

export const NON_AFFILIATION_STATEMENT =
  'KIRON PROHORI is an independent defensive cybersecurity education and intelligence platform. It is not affiliated with, endorsed by, or operated by CISA, NIST, MITRE/CVE, FIRST, abuse.ch, CIRCL, GitHub, Google, or any government agency.';

export const ALLOWED_OUTBOUND_HOSTS = [
  'www.cisa.gov',
  'services.nvd.nist.gov',
  'api.first.org',
  'feodotracker.abuse.ch',
  'urlhaus-api.abuse.ch',
  'api.github.com',
  'hashlookup.circl.lu',
] as const;

export const ZERO_COST_STARTUP_POLICY = {
  budgetUsd: 0,
  requireNvdApiKeyOnStartup: false,
  requireUrlhausAuthKeyOnStartup: false,
  cisaKevRequiresApiKey: false,
  allowFakeOrPlaceholderKeys: false,
  allowPaidCloudBilling: false,
} as const;
