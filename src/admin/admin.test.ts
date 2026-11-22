/**
 * KIRON PROHORI — Phase 5: Administration, Moderation & Governance Automated Test Suite
 * Tests:
 * 1. Real Admin Metrics: Derive total users, CVEs, KEVs, indicators, pending reports, source health, and last sync strictly from real records & flag missing integrations
 * 2. User List & Authoritative RBAC: Join /users with /roles, mask email PII, and never grant admin from user-editable profile fields
 * 3. 4-State Scam Moderation & PII Protection: Support pending/approved/rejected/needs_more_info, block unverified accusations from public view, and scrub PII
 * 4. Report Appeal / Contact Mechanism: Format structured report appeal requests with automatic PII redaction
 * 5. Data Freshness & Immutable Audit Log Viewer: Evaluate connector freshness levels and filter audit trail records
 */

import {
  computeRealAdminMetrics,
  maskEmailForPrivacy,
  mergeUsersWithAuthoritativeRoles,
  scrubPiiFromModerationText,
  filterPubliclyDisplayableScamReports,
  formatScamReportAppealMessage,
  evaluateSourcesFreshnessMatrix,
  filterAuditLogs,
} from './engine.ts';
import { ScamReportDoc, AuditLogDoc } from '../types/security.ts';

export interface AdminGovernanceTestResult {
  id: string;
  module: string;
  testName: string;
  passed: boolean;
  details: string;
}

export function runAdminGovernanceTests(): AdminGovernanceTestResult[] {
  const results: AdminGovernanceTestResult[] = [];

  // ---------------------------------------------------------------------------
  // TEST 1: Real Admin Metrics & Missing Integration Identification (Zero Fake Metrics)
  // ---------------------------------------------------------------------------
  const metrics = computeRealAdminMetrics({
    users: [
      {
        uid: 'u_admin',
        email: 'mdarifab50@gmail.com',
        displayName: 'Bootstrapped Admin',
        organization: 'KIRON PROHORI',
        preferredLanguage: 'en',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
      {
        uid: 'u_analyst',
        email: 'analyst@example.org',
        displayName: 'SOC Analyst',
        organization: 'Cert Team',
        preferredLanguage: 'bn',
        createdAt: '2026-11-21T01:00:00Z',
        updatedAt: '2026-11-21T01:00:00Z',
      },
    ],
    firestoreCves: [
      {
        cveId: 'CVE-2021-44228',
        title: 'Log4Shell',
        description: 'Log4j2 RCE',
        vendor: 'Apache',
        product: 'Log4j2',
        severity: 'CRITICAL',
        cvssScore: 10.0,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        source: 'NIST NVD',
        publishedAt: '2021-12-10',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
    ],
    cachedNvdCveCount: 15,
    firestoreKevs: [],
    cachedCisaKevCount: 1790,
    firestoreIndicators: [
      {
        indicatorId: 'ind_1',
        indicatorType: 'url',
        defangedValue: 'hxxps://bad[.]example[.]invalid',
        malwareFamily: 'PhishKit',
        severity: 'HIGH',
        source: 'Firestore',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
    ],
    cachedUrlhausCount: 0,
    scamReports: [
      {
        reportId: 'r1',
        reporterUid: 'u_analyst',
        title: 'Pending Scam 1',
        category: 'phishing_url',
        defangedIndicator: 'hxxp://scam1[.]invalid',
        description: 'Pending review',
        moderationStatus: 'pending',
        moderatorNotes: '',
        reviewedBy: '',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
      {
        reportId: 'r2',
        reporterUid: 'u_analyst',
        title: 'Needs Info Scam 2',
        category: 'otp_scam',
        defangedIndicator: 'hxxp://scam2[.]invalid',
        description: 'Needs screenshot proof',
        moderationStatus: 'needs_more_info',
        moderatorNotes: 'Provide header evidence',
        reviewedBy: 'u_admin',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
    ],
    dataSources: [],
    syncLogs: [],
    connectors: [
      {
        connectorId: 'cisa_kev',
        name: 'CISA KEV',
        status: 'CONNECTED',
        credentialEnvVar: null,
        credentialConfigured: true,
        lastSuccessAt: '2026-11-21T22:00:00.000Z',
        cachedRecordCount: 1790,
      },
      {
        connectorId: 'urlhaus',
        name: 'URLhaus',
        status: 'NOT CONFIGURED',
        credentialEnvVar: 'URLHAUS_AUTH_KEY',
        credentialConfigured: false,
        lastSuccessAt: null,
        cachedRecordCount: 0,
      },
    ],
    isFirebaseLive: true,
  });

  const t1Passed =
    metrics.totalUsers === 2 &&
    metrics.totalVerifiedCves === 16 &&
    metrics.totalKevEntries === 1790 &&
    metrics.totalThreatIndicators === 1 &&
    metrics.pendingReports === 1 &&
    metrics.needsMoreInfoReports === 1 &&
    metrics.lastSuccessfulSync === '2026-11-21T22:00:00.000Z' &&
    metrics.missingIntegrations.some((m) => m.integrationId === 'urlhaus_auth_key');

  results.push({
    id: 'phase5-real-admin-metrics',
    module: '1. Admin Dashboard & Real Metrics',
    testName:
      'Derive total users, CVEs, KEVs, indicators, pending reports, and last sync strictly from stored records and identify missing integrations',
    passed: t1Passed,
    details: t1Passed
      ? `Verified: Users=${metrics.totalUsers}, CVEs=${metrics.totalVerifiedCves}, KEVs=${metrics.totalKevEntries}, Pending=${metrics.pendingReports}, NeedsInfo=${metrics.needsMoreInfoReports}, MissingIntegrations=${metrics.missingIntegrations.length}`
      : 'Failed real admin metrics calculation or missing integration detection.',
  });

  // ---------------------------------------------------------------------------
  // TEST 2: User List, PII Masking & Authoritative Role Management
  // ---------------------------------------------------------------------------
  const directory = mergeUsersWithAuthoritativeRoles(
    [
      {
        uid: 'u_normal',
        email: 'citizen.user@example.com',
        displayName: 'Citizen User',
        organization: 'Public',
        preferredLanguage: 'en',
        createdAt: '2026-11-21T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
      },
      {
        uid: 'u_mod',
        email: 'moderator.team@example.com',
        displayName: 'Trust Moderator',
        organization: 'CERT',
        preferredLanguage: 'bn',
        createdAt: '2026-11-21T01:00:00Z',
        updatedAt: '2026-11-21T01:00:00Z',
      },
    ],
    [
      {
        uid: 'u_mod',
        role: 'moderator',
        assignedBy: 'u_admin',
        createdAt: '2026-11-21T01:00:00Z',
        updatedAt: '2026-11-21T01:00:00Z',
      },
    ]
  );

  const normalEntry = directory.find((d) => d.uid === 'u_normal');
  const modEntry = directory.find((d) => d.uid === 'u_mod');

  const t2Passed =
    maskEmailForPrivacy('citizen.user@example.com') === 'ci***@example.com' &&
    normalEntry?.authoritativeRole === 'user' &&
    normalEntry?.roleSource === 'DEFAULT_USER_FALLBACK' &&
    modEntry?.authoritativeRole === 'moderator' &&
    modEntry?.roleSource === 'AUTHORITATIVE_ROLES_COLLECTION';

  results.push({
    id: 'phase5-user-role-governance',
    module: '2. User List & Role Management',
    testName:
      'Resolve user roles exclusively from authoritative /roles collection (never from user profile) and mask email PII by default',
    passed: t2Passed,
    details: t2Passed
      ? `Verified: Masked email="${normalEntry?.maskedEmail}", default role="${normalEntry?.authoritativeRole}", assigned role="${modEntry?.authoritativeRole}" (${modEntry?.roleSource})`
      : 'Failed authoritative role resolution or email PII masking.',
  });

  // ---------------------------------------------------------------------------
  // TEST 3: 4-State Scam Moderation, Unverified Accusation Block & PII Scrubber
  // ---------------------------------------------------------------------------
  const sampleReports: ScamReportDoc[] = [
    {
      reportId: 'rep_pending',
      reporterUid: 'u1',
      title: 'Unverified Pending Accusation',
      category: 'phishing_url',
      defangedIndicator: 'hxxps://unverified-accused[.]example[.]com',
      description: 'Submitted by anonymous user',
      moderationStatus: 'pending',
      moderatorNotes: '',
      reviewedBy: '',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
    {
      reportId: 'rep_needs_info',
      reporterUid: 'u1',
      title: 'Needs More Info Report',
      category: 'invoice_fraud',
      defangedIndicator: 'hxxps://needs-proof[.]example[.]com',
      description: 'Awaiting headers',
      moderationStatus: 'needs_more_info',
      moderatorNotes: 'Please provide full SMTP headers',
      reviewedBy: 'admin_1',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
    {
      reportId: 'rep_rejected',
      reporterUid: 'u1',
      title: 'Rejected False Accusation',
      category: 'brand_impersonation',
      defangedIndicator: 'hxxps://legitimate-site[.]example[.]com',
      description: 'False positive',
      moderationStatus: 'rejected',
      moderatorNotes: 'Verified legitimate domain',
      reviewedBy: 'admin_1',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
    {
      reportId: 'rep_approved',
      reporterUid: 'u1',
      title: 'Verified Phishing Kit',
      category: 'phishing_url',
      defangedIndicator: 'hxxps://confirmed-phish[.]example[.]invalid',
      description:
        'Victim victim.name@gmail.com reported call from +880 1712-345678 and card 4532015112830366.',
      moderationStatus: 'approved',
      moderatorNotes: 'Confirmed malicious indicator',
      reviewedBy: 'admin_1',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
  ];

  const publicReports = filterPubliclyDisplayableScamReports(sampleReports);

  const t3Passed =
    publicReports.length === 1 &&
    publicReports[0].reportId === 'rep_approved' &&
    !publicReports[0].description.includes('victim.name@gmail.com') &&
    !publicReports[0].description.includes('1712-345678') &&
    !publicReports[0].description.includes('4532015112830366') &&
    publicReports[0].description.includes('[EMAIL_PII_REDACTED]') &&
    publicReports[0].description.includes('[PHONE_PII_REDACTED]') &&
    publicReports[0].description.includes('[NUMERIC_ID_REDACTED]');

  results.push({
    id: 'phase5-moderation-pii-guard',
    module: '3. Scam Moderation & PII Protection',
    testName:
      'Support pending/approved/rejected/needs_more_info statuses, block unverified accusations from public view, and scrub PII',
    passed: t3Passed,
    details: t3Passed
      ? `Verified: 3 unverified reports (pending/needs_more_info/rejected) blocked from public display; 1 approved report scrubbed of email, phone & numeric ID PII`
      : 'Failed unverified report filtering or PII scrubbing check.',
  });

  // ---------------------------------------------------------------------------
  // TEST 4: Scam Report Appeal / Contact Mechanism
  // ---------------------------------------------------------------------------
  const appealMsg = formatScamReportAppealMessage({
    reportIdOrIndicator: 'scam_12345 (hxxps://my-shop[.]example[.]com)',
    appellantRelation: 'domain_owner',
    appealReason:
      'Our domain was compromised last week and cleaned. Contact owner@my-shop.example.com for proof.',
    verificationEvidence: 'Removed malicious script and rotated TLS certificates.',
  });

  const t4Passed =
    appealMsg.startsWith('[REPORT_APPEAL]') &&
    appealMsg.includes('Role=domain_owner') &&
    appealMsg.includes('[EMAIL_PII_REDACTED]') &&
    !appealMsg.includes('owner@my-shop.example.com');

  results.push({
    id: 'phase5-appeal-mechanism',
    module: '4. Report Appeal & Contact Mechanism',
    testName:
      'Format structured scam report appeal / false-positive contact requests with automatic PII protection',
    passed: t4Passed,
    details: t4Passed
      ? `Verified: Appeal payload formatted with role attribution and automatic PII scrubbing`
      : 'Failed report appeal formatting check.',
  });

  // ---------------------------------------------------------------------------
  // TEST 5: Data Freshness Matrix & Immutable Audit Log Filter
  // ---------------------------------------------------------------------------
  const nowMs = Date.parse('2026-11-21T22:00:00.000Z');
  const freshnessRows = evaluateSourcesFreshnessMatrix(
    [
      {
        connectorId: 'cisa_kev',
        name: 'CISA KEV',
        status: 'CONNECTED',
        cachedRecordCount: 1790,
        lastSuccessAt: '2026-11-21T21:30:00.000Z', // 30 mins ago -> FRESH
        lastFailureAt: null,
        credentialEnvVar: null,
        credentialConfigured: true,
      },
      {
        connectorId: 'urlhaus',
        name: 'URLhaus',
        status: 'NOT CONFIGURED',
        cachedRecordCount: 0,
        lastSuccessAt: null, // NEVER_SYNCED
        lastFailureAt: null,
        credentialEnvVar: 'URLHAUS_AUTH_KEY',
        credentialConfigured: false,
      },
    ],
    nowMs
  );

  const sampleAuditLogs: AuditLogDoc[] = [
    {
      auditId: 'aud_1',
      actorUid: 'admin_1',
      action: 'moderate_scam_report',
      targetCollection: 'scam_reports',
      targetId: 'rep_1',
      summary: 'Moderated scam report rep_1 to needs_more_info',
      createdAt: '2026-11-21T21:00:00Z',
    },
    {
      auditId: 'aud_2',
      actorUid: 'admin_1',
      action: 'assign_role',
      targetCollection: 'roles',
      targetId: 'u_mod',
      summary: 'Assigned role moderator to u_mod',
      createdAt: '2026-11-21T21:10:00Z',
    },
  ];

  const filteredAudits = filterAuditLogs(sampleAuditLogs, {
    actionFilter: 'moderate_scam_report',
    collectionFilter: 'scam_reports',
  });

  const t5Passed =
    freshnessRows[0].freshness.level === 'FRESH' &&
    freshnessRows[0].freshness.ageMinutes === 30 &&
    freshnessRows[1].freshness.level === 'NEVER_SYNCED' &&
    freshnessRows[1].credentialStatusLabel.includes('NOT CONFIGURED') &&
    filteredAudits.length === 1 &&
    filteredAudits[0].auditId === 'aud_1';

  results.push({
    id: 'phase5-freshness-and-audit-logs',
    module: '5. Data Freshness & Audit Log Viewer',
    testName:
      'Evaluate real-time connector data freshness (FRESH/AGING/STALE/NEVER_SYNCED) and filter immutable audit logs',
    passed: t5Passed,
    details: t5Passed
      ? `Verified: CISA KEV freshness=${freshnessRows[0].freshness.level} (${freshnessRows[0].freshness.ageMinutes}m old), URLhaus=${freshnessRows[1].freshness.level}, Audit filter matched ${filteredAudits.length} record`
      : 'Failed data freshness evaluation or audit log filtering.',
  });

  return results;
}

// Allow direct CLI execution via `npx tsx src/admin/admin.test.ts`
const isDirectRun =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1]?.includes('admin.test.ts');

if (isDirectRun) {
  const suite = runAdminGovernanceTests();
  let failed = 0;
  for (const r of suite) {
    const badge = r.passed ? 'PASS' : 'FAIL';
    console.log(`${badge} [${r.module}] ${r.testName} -> ${r.details}`);
    if (!r.passed) failed++;
  }
  if (failed > 0) {
    process.exit(1);
  }
}
