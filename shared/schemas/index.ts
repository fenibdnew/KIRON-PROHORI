/**
 * KIRON PROHORI — Shared Validation Schemas & Contracts (/shared/schemas/index.ts)
 * Enforces strict zero-trust input validation and schema verification across client and server.
 */

export * from '../../src/security/validation';
export {
  CVE_ID_REGEX,
  validateAndParseCisaKevCatalog,
  validateAndParseNvdResponse,
  validateAndParseEpssResponse,
  validateAndParseUrlhausResponse,
} from '../../src/connectors/parsers';

export const FIRESTORE_COLLECTION_SCHEMAS = {
  users: ['uid', 'displayName', 'email', 'photoURL', 'preferredLanguage', 'createdAt', 'lastLoginAt'],
  roles: ['uid', 'role', 'assignedBy', 'assignedAt', 'reason'],
  cves: ['cveId', 'description', 'cvssScore', 'severity', 'vendor', 'product', 'cweId', 'inKev', 'publishedAt', 'updatedAt'],
  kev_entries: ['cveId', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'shortDescription', 'requiredAction', 'dueDate', 'knownRansomwareCampaignUse', 'catalogVersion'],
  threat_indicators: ['indicatorId', 'indicatorType', 'defangedValue', 'threatType', 'malwareFamily', 'status', 'severity', 'sourceName', 'sourceUrl', 'firstSeenAt', 'updatedAt'],
  security_advisories: ['advisoryId', 'title', 'source', 'category', 'severity', 'publishedDate', 'summary', 'officialUrl'],
  scam_reports: ['reportId', 'reporterUid', 'title', 'category', 'suspiciousDomain', 'description', 'status', 'moderatorNotes', 'createdAt', 'moderatedAt'],
  watchlists: ['itemId', 'uid', 'targetType', 'targetValue', 'notes', 'createdAt'],
  notifications: ['notificationId', 'uid', 'category', 'title', 'message', 'severity', 'read', 'createdAt'],
  data_sources: ['sourceId', 'name', 'endpointUrl', 'requiresAuth', 'enabled', 'refreshIntervalMinutes', 'lastSyncAt', 'lastSyncStatus'],
  sync_logs: ['logId', 'sourceId', 'startedAt', 'completedAt', 'status', 'recordsProcessed', 'errorMessage'],
  audit_logs: ['auditId', 'actorUid', 'actorRole', 'action', 'targetCollection', 'targetId', 'summary', 'createdAt'],
  feedback: ['feedbackId', 'uid', 'category', 'subject', 'message', 'status', 'createdAt'],
  app_settings: ['settingId', 'maintenanceMode', 'publicScamSubmissionEnabled', 'defaultLanguage', 'updatedBy', 'updatedAt'],
} as const;
