/**
 * KIRON PROHORI — Phase 0 Payload-First Security TDD Test Suite
 * Verifies that all 12 "Dirty Dozen" adversarial payloads are rejected
 * with PERMISSION_DENIED by firestore.rules.
 */

export interface DirtyDozenAssertion {
  id: number;
  name: string;
  actorRole: 'unauthenticated' | 'normal_user' | 'unverified_admin_spoof' | 'admin';
  operation: 'get' | 'list' | 'create' | 'update' | 'delete';
  collection: string;
  docId: string;
  payload?: Record<string, unknown>;
  expectedOutcome: 'PERMISSION_DENIED' | 'ALLOWED';
  enforcingRuleGate: string;
}

export const DIRTY_DOZEN_SECURITY_TESTS: DirtyDozenAssertion[] = [
  {
    id: 1,
    name: 'Self-Admin Privilege Escalation (/roles/{userId})',
    actorRole: 'normal_user',
    operation: 'create',
    collection: 'roles',
    docId: 'user_alice',
    payload: {
      uid: 'user_alice',
      role: 'admin',
      assignedBy: 'user_alice',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: 'match /roles/{userId} -> allow create: if ... && isAdmin();',
  },
  {
    id: 2,
    name: 'Shadow Role Field in User Profile (/users/{userId})',
    actorRole: 'normal_user',
    operation: 'create',
    collection: 'users',
    docId: 'user_alice',
    payload: {
      uid: 'user_alice',
      email: 'alice@example.com',
      displayName: 'Alice',
      organization: 'SecOps',
      preferredLanguage: 'en',
      role: 'admin',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: "isValidUser() -> data.keys().hasOnly(['uid', 'email', 'displayName', 'organization', 'preferredLanguage', 'createdAt', 'updatedAt'])",
  },
  {
    id: 3,
    name: 'Cross-User PII Profile Read (/users/{otherUid})',
    actorRole: 'normal_user',
    operation: 'get',
    collection: 'users',
    docId: 'user_bob',
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: 'match /users/{userId} -> allow get: if isValidId(userId) && (isOwner(userId) || isAdmin());',
  },
  {
    id: 4,
    name: 'Unverified Email Admin Spoof (/data_sources/{sourceId})',
    actorRole: 'unverified_admin_spoof',
    operation: 'create',
    collection: 'data_sources',
    docId: 'src_nvd',
    payload: {
      sourceId: 'src_nvd',
      name: 'NIST NVD API 2.0',
      endpointUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      sourceType: 'nvd_cve',
      isEnabled: true,
      costTier: 'FREE_PUBLIC_ZERO_COST',
      lastSyncStatus: 'READY',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: 'isVerifiedUser() -> request.auth.token.email_verified == true',
  },
  {
    id: 5,
    name: 'Unauthorized Public Threat Intelligence Mutation (/cves/{cveId})',
    actorRole: 'normal_user',
    operation: 'create',
    collection: 'cves',
    docId: 'CVE-2026-9999',
    payload: {
      cveId: 'CVE-2026-9999',
      title: 'Fake Injected Vulnerability',
      severity: 'CRITICAL',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: 'match /cves/{cveId} -> allow create: if ... && isAdmin();',
  },
  {
    id: 6,
    name: 'Scam Report Pre-Approval Bypass (/scam_reports/{reportId})',
    actorRole: 'normal_user',
    operation: 'create',
    collection: 'scam_reports',
    docId: 'rep_bypass_1',
    payload: {
      reportId: 'rep_bypass_1',
      reporterUid: 'user_alice',
      title: 'Phishing Portal',
      category: 'phishing_url',
      defangedIndicator: 'hxxps://fake-login[.]example[.]invalid',
      description: 'Attempting to skip pending moderation queue',
      moderationStatus: 'approved',
      moderatorNotes: 'Self-approved',
      reviewedBy: 'user_alice',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: "allow create: if ... && incoming().moderationStatus == 'pending' && incoming().moderatorNotes == '' && incoming().reviewedBy == ''",
  },
  {
    id: 7,
    name: 'Unapproved Scam Report Public Scraping (/scam_reports/{reportId})',
    actorRole: 'unauthenticated',
    operation: 'get',
    collection: 'scam_reports',
    docId: 'rep_pending_1',
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: "allow get: if existing().moderationStatus == 'approved' || (isSignedIn() && existing().reporterUid == request.auth.uid) || isAdmin()",
  },
  {
    id: 8,
    name: 'Cross-User Watchlist Query Scraping (/watchlists)',
    actorRole: 'normal_user',
    operation: 'list',
    collection: 'watchlists',
    docId: '*',
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: 'allow list: if isSignedIn() && (resource.data.userId == request.auth.uid || isBootstrappedAdmin());',
  },
  {
    id: 9,
    name: 'Watchlist Owner Hijack & Immutable Field Mutation (/watchlists/{watchlistId})',
    actorRole: 'normal_user',
    operation: 'update',
    collection: 'watchlists',
    docId: 'wl_alice_1',
    payload: {
      userId: 'user_bob',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: "incoming().userId == existing().userId && incoming().diff(existing()).affectedKeys().hasOnly(['targetValue', 'notes', 'severityFilter', 'updatedAt'])",
  },
  {
    id: 10,
    name: 'Immutable Audit Log Deletion Attempt (/audit_logs/{auditId})',
    actorRole: 'admin',
    operation: 'delete',
    collection: 'audit_logs',
    docId: 'aud_101',
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: 'match /audit_logs/{auditId} -> allow update, delete: if false;',
  },
  {
    id: 11,
    name: 'Zero-Cost Policy Violation on Data Source (/data_sources/{sourceId})',
    actorRole: 'admin',
    operation: 'create',
    collection: 'data_sources',
    docId: 'src_paid_feed',
    payload: {
      sourceId: 'src_paid_feed',
      costTier: 'PAID_COMMERCIAL_FEED',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: "isValidDataSource() -> data.costTier == 'FREE_PUBLIC_ZERO_COST'",
  },
  {
    id: 12,
    name: 'Path Variable ID Poisoning (/watchlists/{badId})',
    actorRole: 'normal_user',
    operation: 'create',
    collection: 'watchlists',
    docId: 'malicious$id!@#',
    payload: {
      watchlistId: 'malicious$id!@#',
    },
    expectedOutcome: 'PERMISSION_DENIED',
    enforcingRuleGate: "isValidId(id) -> id.matches('^[a-zA-Z0-9_\\\\-]+$')",
  },
];
