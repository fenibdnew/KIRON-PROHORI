/**
 * KIRON PROHORI — Server Threat Intelligence Connectors (/server/connectors/index.ts)
 * Keyless CISA KEV, Unauthenticated/Optional-Key NIST NVD 2.0, FIRST EPSS v1, and Optional URLhaus connectors.
 */

export * from '../../src/connectors/parsers';

export const CONNECTOR_ENDPOINTS = {
  cisa_kev: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  nist_nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  first_epss: 'https://api.first.org/data/v1/epss',
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/30/',
  github_advisories: 'https://api.github.com/advisories?per_page=25',
  circl_hashlookup: 'https://hashlookup.circl.lu/lookup/sha256/',
} as const;
