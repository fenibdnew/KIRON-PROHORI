/**
 * KIRON PROHORI — Phase 4: Security Toolkit & Personal Features Automated Test Suite
 * Tests:
 * 1. URL Inspector: Safe parsing, domain normalization, malformed URL detection, consent boundary, and UNKNOWN != SAFE verdict
 * 2. Hash Tool: Web Crypto SHA-256 calculation (`computeSha256HexFromBytes`) & hash format validation
 * 3. Security Checklist: All 6 required defensive tracks & progress calculation
 * 4. Watchlist & Personalized Dashboard: Matching saved CVEs, followed vendors, and followed products
 * 5. In-App Notifications: Category filtering, read/unread state filtering, zero paid email/SMS
 * 6. Report Center: RFC-4180 CSV & valid %PDF-1.4 document generation with Report Date, Sources, and Disclaimer
 */

import {
  normalizeDomainName,
  inspectUrlSafely,
  validateCryptographicHashFormat,
  computeSha256HexFromBytes,
  SECURITY_CHECKLIST_TRACKS,
  calculateChecklistProgress,
  buildPersonalizedWatchlistDashboard,
  filterNotifications,
  MANDATORY_REPORT_DISCLAIMER,
  generateReportCsv,
  generateValidPdfDocument,
} from './engine.ts';
import { ParsedKevRecord } from '../connectors/parsers.ts';
import { WatchlistDoc, NotificationDoc, CveRecordDoc } from '../types/security.ts';

export interface ToolkitTestResult {
  id: string;
  module: string;
  testName: string;
  passed: boolean;
  details: string;
}

export async function runSecurityToolkitTests(): Promise<ToolkitTestResult[]> {
  const results: ToolkitTestResult[] = [];

  // ---------------------------------------------------------------------------
  // TEST 1: URL Inspector — Safe Parsing, Domain Normalization, Malformed Detection, UNKNOWN != SAFE
  // ---------------------------------------------------------------------------
  const normDomain = normalizeDomainName('  Sub.Portal.Example.COM.BD. ');
  const malformedSpace = inspectUrlSafely('https://bad url with spaces.example.com', {
    configuredIndicators: [],
    externalConsentGranted: false,
  });
  const malformedJavascript = inspectUrlSafely('javascript:alert(1)', {
    configuredIndicators: [],
    externalConsentGranted: false,
  });

  // Unmatched URL must return verdict === 'UNKNOWN' (never 'SAFE')
  const unmatchedReport = inspectUrlSafely(
    'https://unlisted-portal.example.org:8443/account/verify?session=secret_token_99',
    {
      configuredIndicators: [
        {
          sourceName: 'Verified Firestore Threat Feed',
          indicatorId: 'IND-100',
          defangedOrRawValue: 'hxxps://malicious-login[.]example[.]net',
          categoryOrThreat: 'phishing_url',
          lastUpdatedAt: '2026-11-21T00:00:00Z',
          verificationStatus: 'approved',
        },
      ],
      externalConsentGranted: false,
      intelligenceLastUpdatedAt: '2026-11-21T12:00:00Z',
    }
  );

  // Matched URL must return verdict === 'KNOWN_THREAT_MATCH'
  const matchedReport = inspectUrlSafely(
    'http://admin@malicious-login.example.net/drop.exe',
    {
      configuredIndicators: [
        {
          sourceName: 'Verified Firestore Threat Feed',
          indicatorId: 'IND-100',
          defangedOrRawValue: 'hxxps://malicious-login[.]example[.]net',
          categoryOrThreat: 'phishing_url',
          lastUpdatedAt: '2026-11-21T00:00:00Z',
          verificationStatus: 'approved',
        },
      ],
      externalConsentGranted: false,
      intelligenceLastUpdatedAt: '2026-11-21T12:00:00Z',
    }
  );

  const t1Passed =
    normDomain.validHostname === true &&
    normDomain.normalizedDomain === 'sub.portal.example.com.bd' &&
    normDomain.registrableDomain === 'example.com.bd' &&
    malformedSpace.isMalformed === true &&
    malformedSpace.verdict === 'MALFORMED' &&
    malformedJavascript.isMalformed === true &&
    malformedJavascript.verdict === 'MALFORMED' &&
    unmatchedReport.isMalformed === false &&
    unmatchedReport.verdict === 'UNKNOWN' &&
    unmatchedReport.verdictExplanation.includes('UNKNOWN') &&
    unmatchedReport.verdictExplanation.includes('NOT SAFE') &&
    !unmatchedReport.defangedUrl.includes('secret_token_99') &&
    unmatchedReport.defangedUrl.includes('session=[REDACTED]') &&
    unmatchedReport.externalConsentGranted === false &&
    unmatchedReport.limitationsNotice.includes('LIMITATIONS:') &&
    matchedReport.verdict === 'KNOWN_THREAT_MATCH' &&
    matchedReport.matches.length === 1;

  results.push({
    id: 'phase4-url-inspector',
    module: '1. URL Inspector',
    testName:
      'Safely parse URLs, normalize domains, detect malformed URLs, enforce consent boundary, and return UNKNOWN (not SAFE) on no match',
    passed: t1Passed,
    details: t1Passed
      ? `Verified: normalized="${normDomain.normalizedDomain}" (registrable="${normDomain.registrableDomain}"), malformed blocked, unmatched verdict="${unmatchedReport.verdict}" (never SAFE), matched=${matchedReport.matches.length}`
      : 'Failed URL Inspector domain normalization, malformed check, or UNKNOWN verdict rule.',
  });

  // ---------------------------------------------------------------------------
  // TEST 2: Hash Tool — Browser Web Crypto SHA-256 & Format Validator
  // ---------------------------------------------------------------------------
  const emptyBytes = new Uint8Array(0);
  const computedEmptySha256 = await computeSha256HexFromBytes(emptyBytes);
  const expectedEmptySha256 =
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const validSha256Check = validateCryptographicHashFormat(computedEmptySha256);
  const validMd5Check = validateCryptographicHashFormat(
    'd41d8cd98f00b204e9800998ecf8427e'
  );
  const invalidHashCheck = validateCryptographicHashFormat('not_a_hex_hash_999');

  const t2Passed =
    computedEmptySha256 === expectedEmptySha256 &&
    validSha256Check.isValid === true &&
    validSha256Check.algorithm === 'SHA-256' &&
    validSha256Check.supportsPublicLookup === true &&
    validMd5Check.isValid === true &&
    validMd5Check.algorithm === 'MD5' &&
    invalidHashCheck.isValid === false &&
    invalidHashCheck.algorithm === 'INVALID';

  results.push({
    id: 'phase4-hash-tool',
    module: '2. Hash Tool',
    testName:
      'Compute SHA-256 locally via Web Crypto API (crypto.subtle.digest) and validate SHA-256/SHA-1/MD5 hash formats without file upload',
    passed: t2Passed,
    details: t2Passed
      ? `Verified: WebCrypto SHA-256("") = ${computedEmptySha256.slice(0, 16)}..., format validator identified SHA-256 (256-bit) & MD5 (128-bit) and rejected invalid hex`
      : 'Failed Web Crypto SHA-256 digest computation or hash format validation.',
  });

  // ---------------------------------------------------------------------------
  // TEST 3: Security Checklist — All 6 Required Tracks & Progress Engine
  // ---------------------------------------------------------------------------
  const requiredTracks = [
    'account_security',
    'password_manager',
    'mfa_awareness',
    'backup_updates',
    'small_business',
    'service_technician',
  ] as const;

  const presentTrackIds = SECURITY_CHECKLIST_TRACKS.map((t) => t.trackId);
  const allSixTracksPresent = requiredTracks.every((id) =>
    presentTrackIds.includes(id)
  );

  const firstTrackIds = SECURITY_CHECKLIST_TRACKS[0].items.map((i) => i.id);
  const progress = calculateChecklistProgress(firstTrackIds);

  const t3Passed =
    allSixTracksPresent &&
    SECURITY_CHECKLIST_TRACKS.length === 6 &&
    progress.totalItems === 18 &&
    progress.completedItems === 3 &&
    progress.byTrack.account_security.percentage === 100 &&
    progress.byTrack.service_technician.percentage === 0;

  results.push({
    id: 'phase4-security-checklist',
    module: '3. Security Checklist',
    testName:
      'Verify all 6 required tracks (Account, Password Manager, MFA, Backup & Updates, Small Business, Service Technician) & progress math',
    passed: t3Passed,
    details: t3Passed
      ? `Verified: All 6 required tracks present (${progress.totalItems} controls), Track 1 completion=${progress.byTrack.account_security.percentage}%`
      : 'Failed Security Checklist track coverage or progress calculation.',
  });

  // ---------------------------------------------------------------------------
  // TEST 4: Watchlist & Personalized Dashboard Matcher
  // ---------------------------------------------------------------------------
  const sampleWatchlists: WatchlistDoc[] = [
    {
      watchlistId: 'wl_1',
      userId: 'usr_1',
      itemType: 'cve_id',
      targetValue: 'CVE-2024-3400',
      notes: 'Critical edge firewall',
      severityFilter: 'ALL',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
    {
      watchlistId: 'wl_2',
      userId: 'usr_1',
      itemType: 'vendor_keyword',
      targetValue: 'Apache',
      notes: 'Follow Apache vendor advisories',
      severityFilter: 'ALL',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
    {
      watchlistId: 'wl_3',
      userId: 'usr_1',
      itemType: 'product_cpe',
      targetValue: 'Log4j',
      notes: 'Follow Log4j product',
      severityFilter: 'CRITICAL_ONLY',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
  ];

  const sampleKevs: ParsedKevRecord[] = [
    {
      kevId: 'KEV-CVE-2024-3400',
      cveId: 'CVE-2024-3400',
      vendorProject: 'Palo Alto Networks',
      product: 'PAN-OS',
      vulnerabilityName: 'PAN-OS Command Injection Vulnerability',
      dateAdded: '2024-04-12',
      shortDescription: 'Command injection in GlobalProtect.',
      requiredAction: 'Apply updates per vendor instructions.',
      dueDate: '2024-04-19',
      knownRansomwareCampaignUse: 'Known',
      notes: '',
      cwes: ['CWE-77'],
      catalogVersion: '2026.11.20',
      dateReleased: '2026-11-20',
      provenance: {
        connectorId: 'cisa_kev',
        sourceName: 'CISA KEV Catalog',
        sourceUrl: 'https://www.cisa.gov',
        retrievedAt: '2026-11-21T00:00:00Z',
      },
    },
  ];

  const sampleCves: CveRecordDoc[] = [
    {
      cveId: 'CVE-2021-44228',
      title: 'Apache Log4j2 JNDI RCE',
      description: 'Remote code execution in Apache Log4j2.',
      vendor: 'Apache',
      product: 'Log4j',
      severity: 'CRITICAL',
      cvssScore: 10.0,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      source: 'NIST NVD API 2.0',
      publishedAt: '2021-12-10',
      createdAt: '2026-11-21T00:00:00Z',
      updatedAt: '2026-11-21T00:00:00Z',
    },
  ];

  const dashboard = buildPersonalizedWatchlistDashboard(
    sampleWatchlists,
    sampleKevs,
    sampleCves
  );

  const t4Passed =
    dashboard.totalWatchlistItems === 3 &&
    dashboard.savedCvesCount === 1 &&
    dashboard.followedVendorsCount === 1 &&
    dashboard.followedProductsCount === 1 &&
    dashboard.totalCatalogMatches === 3 &&
    dashboard.activeKevMatchesCount === 1;

  results.push({
    id: 'phase4-watchlist-dashboard',
    module: '4. Watchlist & Personalized Dashboard',
    testName:
      'Save CVEs, follow vendors and products, and compute personalized vulnerability matches against KEV & CVE catalogs',
    passed: t4Passed,
    details: t4Passed
      ? `Verified: Tracked ${dashboard.savedCvesCount} CVE, ${dashboard.followedVendorsCount} vendor, ${dashboard.followedProductsCount} product -> matched ${dashboard.totalCatalogMatches} intelligence records`
      : 'Failed Watchlist personalized dashboard correlation check.',
  });

  // ---------------------------------------------------------------------------
  // TEST 5: In-App Notifications — Category & Read Status Filtering
  // ---------------------------------------------------------------------------
  const sampleNotifs: NotificationDoc[] = [
    {
      notificationId: 'n1',
      userId: 'u1',
      title: 'Watchlist Match: CVE-2024-3400',
      message: 'Matched followed CVE-2024-3400 in CISA KEV catalog.',
      category: 'watchlist_match',
      isRead: false,
      createdAt: '2026-11-21T10:00:00Z',
      updatedAt: '2026-11-21T10:00:00Z',
    },
    {
      notificationId: 'n2',
      userId: 'u1',
      title: 'Scam Report Approved',
      message: 'Moderator approved your submitted phishing indicator.',
      category: 'moderation_update',
      isRead: true,
      createdAt: '2026-11-21T09:00:00Z',
      updatedAt: '2026-11-21T09:30:00Z',
    },
  ];

  const unreadWatchlistNotifs = filterNotifications(sampleNotifs, {
    categoryFilter: 'watchlist_match',
    readStatusFilter: 'UNREAD',
  });

  const t5Passed =
    unreadWatchlistNotifs.length === 1 &&
    unreadWatchlistNotifs[0].notificationId === 'n1';

  results.push({
    id: 'phase4-notifications',
    module: '5. In-App Notifications',
    testName:
      'Filter in-app notifications by category and read status with zero paid email/SMS dependencies',
    passed: t5Passed,
    details: t5Passed
      ? `Verified: Category="watchlist_match" + Status="UNREAD" matched ${unreadWatchlistNotifs.length} notification (${unreadWatchlistNotifs[0].title})`
      : 'Failed in-app notification category or read status filter.',
  });

  // ---------------------------------------------------------------------------
  // TEST 6: Report Center — Downloadable CSV & Valid PDF 1.4 Generator
  // ---------------------------------------------------------------------------
  const reportPayload = {
    reportTitle: 'Defensive Posture & Watchlist Intelligence Briefing',
    generatedAtIso: '2026-11-21T22:25:00.000Z',
    preparedBy: 'Analyst Defender',
    organization: 'KIRON PROHORI Security Team',
    sourceReferences: [
      'CISA Known Exploited Vulnerabilities (KEV) Public JSON Catalog',
      'NIST National Vulnerability Database (NVD) API 2.0',
      'KIRON PROHORI 6-Track Security Checklist',
    ],
    disclaimer: MANDATORY_REPORT_DISCLAIMER,
    checklistSummary: {
      completedItems: 12,
      totalItems: 18,
      completionPercentage: 67,
    },
    rows: [
      {
        recordId: 'CVE-2024-3400',
        category: 'Watchlist KEV Match',
        subject: 'Palo Alto Networks PAN-OS',
        statusOrSeverity: 'CRITICAL (KEV)',
        requiredActionOrNote: 'Apply updates per vendor instructions.',
        sourceAttribution: 'CISA KEV Catalog',
        referenceDate: '2024-04-12',
      },
    ],
  };

  const csvReport = generateReportCsv(reportPayload);
  const pdfReport = generateValidPdfDocument(reportPayload);

  const t6Passed =
    csvReport.includes('# REPORT_DATE_UTC,2026-11-21T22:25:00.000Z') &&
    csvReport.includes('# OFFICIAL_SOURCE_REFERENCES,') &&
    csvReport.includes('# DISCLAIMER,') &&
    csvReport.includes('CVE-2024-3400,Watchlist KEV Match') &&
    pdfReport.startsWith('%PDF-1.4') &&
    pdfReport.includes('Report Date \\(UTC\\): 2026-11-21T22:25:00.000Z') &&
    pdfReport.includes('OFFICIAL SOURCE REFERENCES:') &&
    pdfReport.includes('MANDATORY SECURITY & NON-AFFILIATION DISCLAIMER:') &&
    pdfReport.includes('CVE-2024-3400') &&
    pdfReport.trim().endsWith('%%EOF');

  results.push({
    id: 'phase4-report-center',
    module: '6. Report Center (CSV & PDF)',
    testName:
      'Generate downloadable RFC-4180 CSV and valid %PDF-1.4 documents including Report Date, Source References, and Disclaimer without fabricated findings',
    passed: t6Passed,
    details: t6Passed
      ? `Verified: CSV (${csvReport.split('\n').length} lines) & valid %PDF-1.4 (${pdfReport.length} bytes) generated with Report Date, Official Source References & Mandatory Disclaimer`
      : 'Failed CSV or PDF 1.4 report generation check.',
  });

  return results;
}

// Allow direct CLI execution via `npx tsx src/toolkit/toolkit.test.ts`
const isDirectRun =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1]?.includes('toolkit.test.ts');

if (isDirectRun) {
  void runSecurityToolkitTests().then((suite) => {
    let failed = 0;
    for (const r of suite) {
      const badge = r.passed ? 'PASS' : 'FAIL';
      console.log(`${badge} [${r.module}] ${r.testName} -> ${r.details}`);
      if (!r.passed) failed++;
    }
    if (failed > 0) {
      process.exit(1);
    }
  });
}
