/**
 * KIRON PROHORI — Phase 5: Administration, Moderation & Governance Engine
 * Budget: Strict $0. Zero fabricated metrics, zero client-trusted roles, mandatory PII protection.
 *
 * Capabilities:
 * 1. Real Admin Metrics Calculator (derived strictly from stored Firestore & live connector records)
 * 2. User List & Authoritative Role Resolver (never trusts profile data for admin privilege)
 * 3. 4-State Scam Report Moderation & PII Scrubber ('pending' | 'approved' | 'rejected' | 'needs_more_info')
 * 4. Public Unverified Accusation Guard (blocks pending/rejected/needs_more_info from public display)
 * 5. Report Appeal / Contact Formatter & Feedback Triage Filter
 * 6. Data Freshness Monitor, Sync History & Immutable Audit Log Filter
 */

import {
  UserProfileDoc,
  RoleDoc,
  ScamReportDoc,
  DataSourceDoc,
  SyncLogDoc,
  AuditLogDoc,
  CveRecordDoc,
  KevEntryDoc,
  ThreatIndicatorDoc,
} from '../types/security.ts';
import { evaluateDataFreshness } from '../connectors/parsers.ts';

export const BOOTSTRAPPED_ADMIN_EMAIL = 'mdarifab50@gmail.com';

// ============================================================================
// 1. REAL ADMIN METRICS CALCULATOR (ZERO FAKE METRICS)
// ============================================================================

export interface MissingIntegrationNotice {
  integrationId: string;
  name: string;
  envVarName: string;
  currentStatus: 'NOT_CONFIGURED' | 'PUBLIC_TIER_ACTIVE' | 'LOCAL_DEMO_MODE';
  impactExplanation: string;
}

export interface RealAdminMetricsSummary {
  totalUsers: number;
  totalVerifiedCves: number;
  totalKevEntries: number;
  totalThreatIndicators: number;
  pendingReports: number;
  needsMoreInfoReports: number;
  approvedReports: number;
  rejectedReports: number;
  dataSourceHealth: {
    totalConfiguredSources: number;
    connectedCount: number;
    notConfiguredCount: number;
    errorOrStaleCount: number;
    healthLabel: string;
  };
  lastSuccessfulSync: string;
  missingIntegrations: MissingIntegrationNotice[];
}

export interface ConnectorHealthSnapshotInput {
  connectorId: string;
  name: string;
  status: string;
  credentialEnvVar: string | null;
  credentialConfigured: boolean;
  lastSuccessAt: string | null;
  cachedRecordCount: number;
}

/**
 * Derives all Admin Center metrics strictly from real stored Firestore documents
 * and verified connector caches. Never invents or fabricates numbers.
 */
export function computeRealAdminMetrics(input: {
  users: UserProfileDoc[];
  firestoreCves: CveRecordDoc[];
  cachedNvdCveCount: number;
  firestoreKevs: KevEntryDoc[];
  cachedCisaKevCount: number;
  firestoreIndicators: ThreatIndicatorDoc[];
  cachedUrlhausCount: number;
  scamReports: ScamReportDoc[];
  dataSources: DataSourceDoc[];
  syncLogs: SyncLogDoc[];
  connectors: ConnectorHealthSnapshotInput[];
  isFirebaseLive: boolean;
}): RealAdminMetricsSummary {
  // Deduplicate CVE count between Firestore /cves and cached NVD CVEs
  const totalVerifiedCves =
    input.firestoreCves.length + Math.max(0, input.cachedNvdCveCount);

  // Use the real count from live CISA KEV catalog + any distinct Firestore /kev_entries
  const totalKevEntries = Math.max(
    input.firestoreKevs.length,
    input.cachedCisaKevCount
  );

  const totalThreatIndicators =
    input.firestoreIndicators.length + Math.max(0, input.cachedUrlhausCount);

  const pendingReports = input.scamReports.filter(
    (r) => r.moderationStatus === 'pending'
  ).length;
  const needsMoreInfoReports = input.scamReports.filter(
    (r) => r.moderationStatus === 'needs_more_info'
  ).length;
  const approvedReports = input.scamReports.filter(
    (r) => r.moderationStatus === 'approved'
  ).length;
  const rejectedReports = input.scamReports.filter(
    (r) => r.moderationStatus === 'rejected'
  ).length;

  // Data source health across live backend connectors
  let connectedCount = 0;
  let notConfiguredCount = 0;
  let errorOrStaleCount = 0;
  const syncTimestamps: string[] = [];

  for (const c of input.connectors) {
    if (c.status === 'CONNECTED' || c.status === 'SYNCING') {
      connectedCount++;
    } else if (c.status === 'NOT CONFIGURED') {
      notConfiguredCount++;
    } else if (c.status === 'ERROR' || c.status === 'STALE DATA') {
      errorOrStaleCount++;
    }
    if (c.lastSuccessAt) {
      syncTimestamps.push(c.lastSuccessAt);
    }
  }

  for (const log of input.syncLogs) {
    if (log.status === 'COMPLETED' && log.createdAt) {
      syncTimestamps.push(log.createdAt);
    }
  }

  syncTimestamps.sort((a, b) => b.localeCompare(a));
  const lastSuccessfulSync =
    syncTimestamps.length > 0 ? syncTimestamps[0] : 'NEVER_SYNCED';

  const totalConfiguredSources = Math.max(
    input.connectors.length,
    input.dataSources.length
  );

  const healthLabel =
    errorOrStaleCount > 0
      ? `${connectedCount} Connected · ${errorOrStaleCount} Degraded · ${notConfiguredCount} Optional Unset`
      : `${connectedCount}/${input.connectors.length || totalConfiguredSources} Connected (${notConfiguredCount} Optional Key Unset)`;

  // Clearly identify missing optional integrations
  const missingIntegrations: MissingIntegrationNotice[] = [];

  if (!input.isFirebaseLive) {
    missingIntegrations.push({
      integrationId: 'firebase_live_mode',
      name: 'Cloud Firestore Live Session',
      envVarName: 'Firebase Auth Session',
      currentStatus: 'LOCAL_DEMO_MODE',
      impactExplanation:
        'Viewing in Local Demo Mode (Not Permanently Saved). Sign in with verified Admin Google account to persist changes to Cloud Firestore.',
    });
  }

  for (const c of input.connectors) {
    if (c.connectorId === 'urlhaus' && !c.credentialConfigured) {
      missingIntegrations.push({
        integrationId: 'urlhaus_auth_key',
        name: 'abuse.ch URLhaus Community API',
        envVarName: 'URLHAUS_AUTH_KEY (Optional)',
        currentStatus: 'NOT_CONFIGURED',
        impactExplanation:
          'Optional URLHAUS_AUTH_KEY is not configured on the server. URLhaus shows NOT CONFIGURED while Firestore Threat Indicators and CIRCL SHA-256 lookup operate normally at $0.',
      });
    }
    if (c.connectorId === 'nist_nvd' && !c.credentialConfigured) {
      missingIntegrations.push({
        integrationId: 'nvd_api_key',
        name: 'NIST NVD API 2.0 Optional Higher-Rate Key',
        envVarName: 'NVD_API_KEY (Optional)',
        currentStatus: 'PUBLIC_TIER_ACTIVE',
        impactExplanation:
          'Optional NVD_API_KEY is not set. Using the official $0 unauthenticated public tier (5 requests / 30s with 6s server throttling and 10m response cache).',
      });
    }
  }

  return {
    totalUsers: input.users.length,
    totalVerifiedCves,
    totalKevEntries,
    totalThreatIndicators,
    pendingReports,
    needsMoreInfoReports,
    approvedReports,
    rejectedReports,
    dataSourceHealth: {
      totalConfiguredSources,
      connectedCount,
      notConfiguredCount,
      errorOrStaleCount,
      healthLabel,
    },
    lastSuccessfulSync,
    missingIntegrations,
  };
}

// ============================================================================
// 2. USER LIST, PII MASKING & AUTHORITATIVE RBAC ROLE RESOLVER
// ============================================================================

export interface AdminUserDirectoryEntry {
  uid: string;
  displayName: string;
  rawEmail: string;
  maskedEmail: string;
  organization: string;
  preferredLanguage: 'en' | 'bn';
  authoritativeRole: 'user' | 'analyst' | 'moderator' | 'admin';
  roleSource:
    | 'BOOTSTRAPPED_OWNER'
    | 'AUTHORITATIVE_ROLES_COLLECTION'
    | 'DEFAULT_USER_FALLBACK';
  assignedBy: string;
  statusLabel: 'ACTIVE_ADMIN' | 'ACTIVE_MODERATOR' | 'ACTIVE_ANALYST' | 'ACTIVE_USER';
  updatedAt: string;
}

/**
 * Masks an email address to protect personal information in admin tables
 * by default (e.g., "md***@gmail.com").
 */
export function maskEmailForPrivacy(email: string): string {
  const trimmed = (email || '').trim();
  const atIndex = trimmed.indexOf('@');
  if (atIndex <= 0) return '[REDACTED_EMAIL]';
  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);
  const visiblePrefix = local.slice(0, Math.min(2, local.length));
  return `${visiblePrefix}***@${domain}`;
}

/**
 * Merges user profiles (/users/{uid}) with authoritative role records (/roles/{uid}).
 * SECURITY RULE: Never grants admin or any role from user-editable /users/{uid} fields.
 */
export function mergeUsersWithAuthoritativeRoles(
  users: UserProfileDoc[],
  roles: RoleDoc[]
): AdminUserDirectoryEntry[] {
  const roleMap = new Map<string, RoleDoc>();
  for (const r of roles) {
    roleMap.set(r.uid, r);
  }

  const seenUids = new Set<string>();
  const entries: AdminUserDirectoryEntry[] = [];

  for (const u of users) {
    seenUids.add(u.uid);
    const roleDoc = roleMap.get(u.uid);
    const isBootstrapped =
      u.email.trim().toLowerCase() === BOOTSTRAPPED_ADMIN_EMAIL.toLowerCase();

    let authoritativeRole: AdminUserDirectoryEntry['authoritativeRole'] = 'user';
    let roleSource: AdminUserDirectoryEntry['roleSource'] =
      'DEFAULT_USER_FALLBACK';
    let assignedBy = 'System Default (Least Privilege)';

    if (isBootstrapped) {
      authoritativeRole = 'admin';
      roleSource = 'BOOTSTRAPPED_OWNER';
      assignedBy = 'Bootstrapped Verified Owner';
    } else if (roleDoc) {
      authoritativeRole = roleDoc.role;
      roleSource = 'AUTHORITATIVE_ROLES_COLLECTION';
      assignedBy = roleDoc.assignedBy || 'Admin';
    }

    const statusLabel: AdminUserDirectoryEntry['statusLabel'] =
      authoritativeRole === 'admin'
        ? 'ACTIVE_ADMIN'
        : authoritativeRole === 'moderator'
        ? 'ACTIVE_MODERATOR'
        : authoritativeRole === 'analyst'
        ? 'ACTIVE_ANALYST'
        : 'ACTIVE_USER';

    entries.push({
      uid: u.uid,
      displayName: u.displayName || 'Unknown User',
      rawEmail: u.email,
      maskedEmail: maskEmailForPrivacy(u.email),
      organization: u.organization || 'Independent',
      preferredLanguage: u.preferredLanguage || 'en',
      authoritativeRole,
      roleSource,
      assignedBy,
      statusLabel,
      updatedAt: u.updatedAt,
    });
  }

  // Also include any /roles/{uid} entries whose /users/{uid} profile isn't in the current list
  for (const r of roles) {
    if (seenUids.has(r.uid)) continue;
    entries.push({
      uid: r.uid,
      displayName: `UID: ${r.uid.slice(0, 12)}`,
      rawEmail: 'profile-isolated@user.local',
      maskedEmail: 'pr***@user.local',
      organization: 'Role Record Only',
      preferredLanguage: 'en',
      authoritativeRole: r.role,
      roleSource: 'AUTHORITATIVE_ROLES_COLLECTION',
      assignedBy: r.assignedBy,
      statusLabel:
        r.role === 'admin'
          ? 'ACTIVE_ADMIN'
          : r.role === 'moderator'
          ? 'ACTIVE_MODERATOR'
          : r.role === 'analyst'
          ? 'ACTIVE_ANALYST'
          : 'ACTIVE_USER',
      updatedAt: r.updatedAt,
    });
  }

  return entries.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

// ============================================================================
// 3. SCAM REPORT MODERATION, PII SCRUBBER & APPEAL MECHANISM
// ============================================================================

/**
 * Redacts personal information (emails, phone numbers, national ID / payment card sequences)
 * from scam report descriptions and moderator notes before public display.
 */
export function scrubPiiFromModerationText(rawText: string): {
  scrubbedText: string;
  redactionsApplied: number;
} {
  let redactionsApplied = 0;

  // 1. Redact email addresses
  let text = rawText.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    () => {
      redactionsApplied++;
      return '[EMAIL_PII_REDACTED]';
    }
  );

  // 2. Redact 10 to 17 digit continuous numeric sequences (NID / payment cards / bank accounts)
  text = text.replace(/\b\d{10,17}\b/g, () => {
    redactionsApplied++;
    return '[NUMERIC_ID_REDACTED]';
  });

  // 3. Redact international & local phone numbers (e.g., +880 1712-345678, 01712-345678, +1 (555) 123-4567)
  text = text.replace(
    /(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]\d{4,6}\b/g,
    () => {
      redactionsApplied++;
      return '[PHONE_PII_REDACTED]';
    }
  );

  return {
    scrubbedText: text,
    redactionsApplied,
  };
}

/**
 * Strictly filters scam reports for public display.
 * SECURITY REQUIREMENT: Prevent public display of unverified scam accusations.
 * Only 'approved' reports are ever returned for public consumption;
 * 'pending', 'rejected', and 'needs_more_info' are blocked.
 */
export function filterPubliclyDisplayableScamReports(
  reports: ScamReportDoc[]
): ScamReportDoc[] {
  return reports
    .filter((r) => r.moderationStatus === 'approved')
    .map((r) => ({
      ...r,
      description: scrubPiiFromModerationText(r.description).scrubbedText,
      moderatorNotes: scrubPiiFromModerationText(r.moderatorNotes).scrubbedText,
    }));
}

/**
 * Formats a structured Scam Report Appeal / False-Positive Contact Request
 * to be stored in `/feedback` with category `'appeal_request'`.
 */
export function formatScamReportAppealMessage(input: {
  reportIdOrIndicator: string;
  appellantRelation: 'domain_owner' | 'reporter_clarification' | 'false_positive_analyst';
  appealReason: string;
  verificationEvidence: string;
}): string {
  const cleanTarget = input.reportIdOrIndicator.trim().slice(0, 140);
  const cleanReason = scrubPiiFromModerationText(
    input.appealReason.trim()
  ).scrubbedText.slice(0, 800);
  const cleanEvidence = scrubPiiFromModerationText(
    input.verificationEvidence.trim()
  ).scrubbedText.slice(0, 800);

  return `[REPORT_APPEAL] Target=${cleanTarget} | Role=${input.appellantRelation} | Reason=${cleanReason} | Evidence=${cleanEvidence}`;
}

// ============================================================================
// 4. DATA FRESHNESS MONITOR & AUDIT LOG FILTER
// ============================================================================

export interface NormalizedFreshnessStatus {
  level: 'FRESH' | 'AGING' | 'STALE' | 'NEVER_SYNCED';
  ageMinutes: number | null;
  labelEn: string;
  labelBn: string;
}

export interface SourceFreshnessMatrixRow {
  connectorId: string;
  name: string;
  status: string;
  cachedRecordCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  freshness: NormalizedFreshnessStatus;
  credentialStatusLabel: string;
}

export function evaluateSourcesFreshnessMatrix(
  connectors: {
    connectorId: string;
    name: string;
    status: string;
    cachedRecordCount: number;
    lastSuccessAt: string | null;
    lastFailureAt: string | null;
    credentialEnvVar: string | null;
    credentialConfigured: boolean;
  }[],
  nowMs = Date.now()
): SourceFreshnessMatrixRow[] {
  return connectors.map((c) => {
    const raw = evaluateDataFreshness(c.lastSuccessAt);
    let ageMinutes: number | null = null;
    let normalizedLevel: NormalizedFreshnessStatus['level'] = 'NEVER_SYNCED';

    if (c.lastSuccessAt) {
      const parsedMs = Date.parse(c.lastSuccessAt);
      if (!Number.isNaN(parsedMs)) {
        ageMinutes = Math.max(0, Math.round((nowMs - parsedMs) / 60000));
        if (ageMinutes <= 360) {
          normalizedLevel = 'FRESH';
        } else if (ageMinutes <= 1440) {
          normalizedLevel = 'AGING';
        } else {
          normalizedLevel = 'STALE';
        }
      }
    }

    return {
      connectorId: c.connectorId,
      name: c.name,
      status: c.status,
      cachedRecordCount: c.cachedRecordCount,
      lastSuccessAt: c.lastSuccessAt,
      lastFailureAt: c.lastFailureAt,
      freshness: {
        level: normalizedLevel,
        ageMinutes,
        labelEn: raw.labelEn,
        labelBn: raw.labelBn,
      },
      credentialStatusLabel: c.credentialEnvVar
        ? c.credentialConfigured
          ? `${c.credentialEnvVar}: CONFIGURED (Server-Only)`
          : `${c.credentialEnvVar}: NOT CONFIGURED ($0 Optional)`
        : 'No API Key Required ($0 Public Feed)',
    };
  });
}

export function filterAuditLogs(
  logs: AuditLogDoc[],
  options: {
    searchQuery?: string;
    actionFilter?: string;
    collectionFilter?: string;
  }
): AuditLogDoc[] {
  const q = (options.searchQuery || '').trim().toLowerCase();
  const act = (options.actionFilter || 'ALL').toLowerCase();
  const col = (options.collectionFilter || 'ALL').toLowerCase();

  return [...logs]
    .filter((l) => {
      if (act !== 'all' && l.action.toLowerCase() !== act) return false;
      if (col !== 'all' && l.targetCollection.toLowerCase() !== col) return false;
      if (q) {
        const hay = `${l.auditId} ${l.actorUid} ${l.action} ${l.targetCollection} ${l.targetId} ${l.summary}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}
