/**
 * KIRON PROHORI — Server API Route Registry (/server/routes/index.ts)
 * Canonical registry of all server-side defensive API endpoints exposed by server.ts.
 */

export const SERVER_API_ROUTES = {
  securityHealth: '/api/security/health',
  securityValidateInput: '/api/security/validate-input',
  securityAdminConfigureSource: '/api/security/admin/configure-source',
  securityAdminModerateScam: '/api/security/admin/moderate-scam',
  securityAdminAssignRole: '/api/security/admin/assign-role',
  securityAdminUpdateSettings: '/api/security/admin/update-settings',
  securityReportAppeal: '/api/security/report-appeal',
  securityAuditLogs: '/api/security/audit-logs',
  connectorsStatus: '/api/connectors/status',
  connectorsCisaKevSync: '/api/connectors/cisa-kev/sync',
  connectorsCisaKevRecords: '/api/connectors/cisa-kev/records',
  connectorsNvdSearch: '/api/connectors/nvd/search',
  connectorsEpssLookup: '/api/connectors/epss/lookup',
  connectorsUrlhausSync: '/api/connectors/urlhaus/sync',
  connectorsAdvisories: '/api/connectors/advisories',
  toolkitHashReputation: '/api/toolkit/hash-reputation',
} as const;
