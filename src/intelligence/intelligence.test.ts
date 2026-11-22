/**
 * KIRON PROHORI — Phase 3: Intelligence Center Automated Test Suite
 * Tests:
 * 1. CVE Explorer: Search by CVE ID/vendor/product, filter by CVSS & severity, missing fields normalized to Unknown, sorting, pagination & CSV export
 * 2. CISA KEV Tracker: Filter by vendor/product/date, Unknown ransomware semantics (not interpreted as No), and snapshot diff comparison for newly imported records
 * 3. Malware Intelligence: SHA-256 hash format validation, indicator filtering by threat type/status/source, and defanging
 * 4. Scam & Phishing: Suspicious URL parser (Punycode, @ userinfo, IP host), feed matching, and mandatory "No match does not mean safe" explanation
 * 5. Security Advisories: Official source link, source name, publication date, short summary, and category filtering
 */

import {
  normalizeCveRecordWithUnknowns,
  filterAndSortCveRecords,
  exportCveRecordsToCsv,
  computeKevSnapshotDiff,
  filterAndSortKevRecords,
  isValidSha256Hash,
  filterMalwareIndicators,
  parseAndInspectSuspiciousUrl,
  validateAndParseGithubAdvisories,
  filterAndSortAdvisories,
  paginateArray,
} from './engine.ts';
import { ParsedKevRecord } from '../connectors/parsers.ts';

export interface IntelligenceTestResult {
  id: string;
  module: string;
  testName: string;
  passed: boolean;
  details: string;
}

export function runIntelligenceCenterTests(): IntelligenceTestResult[] {
  const results: IntelligenceTestResult[] = [];

  // ---------------------------------------------------------------------------
  // TEST 1: CVE Explorer — Missing fields as 'Unknown', Search, CVSS/Severity Filter, Sort & CSV Export
  // ---------------------------------------------------------------------------
  const cveA = normalizeCveRecordWithUnknowns({
    cveId: 'CVE-2024-3094',
    description: 'Malicious backdoor in upstream xz/liblzma tarballs.',
    vendor: 'tukaani',
    product: 'xz',
    cvss: {
      version: '3.1',
      baseScore: 10.0,
      baseSeverity: 'CRITICAL',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      exploitabilityScore: 3.9,
      impactScore: 6.0,
    },
    cwes: ['CWE-506'],
    affectedConfigurations: ['cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*'],
    published: '2024-03-29T17:15:00.000',
    lastModified: '2024-04-02T12:00:00.000',
  });

  // Missing vendor, product, CWE, CVSS vector, and configurations must normalize to 'Unknown'
  const cveMissing = normalizeCveRecordWithUnknowns({
    cveId: 'CVE-2025-0001',
    description: '',
    vendor: '',
    product: 'N/A',
    cwes: [],
    affectedConfigurations: [],
  });

  const filteredCritical = filterAndSortCveRecords([cveA, cveMissing], {
    searchQuery: 'tukaani',
    severityFilter: 'CRITICAL',
    minCvss: 9.0,
    maxCvss: 10.0,
    sortBy: 'cvssScore',
    sortDirection: 'desc',
  });

  const csvOut = exportCveRecordsToCsv([cveA, cveMissing]);

  const t1Passed =
    cveMissing.vendor === 'Unknown' &&
    cveMissing.product === 'Unknown' &&
    cveMissing.description === 'Unknown' &&
    cveMissing.cweDisplay === 'Unknown' &&
    cveMissing.cvssScoreDisplay === 'Unknown' &&
    cveMissing.affectedConfigurationsDisplay === 'Unknown' &&
    cveMissing.kevSafetyNote.includes('does NOT mean this CVE is safe') &&
    filteredCritical.length === 1 &&
    filteredCritical[0].cveId === 'CVE-2024-3094' &&
    csvOut.includes('CVE_ID,Vendor,Product,Severity') &&
    csvOut.includes('CVE-2024-3094,tukaani,xz,CRITICAL,10.0');

  results.push({
    id: 'phase3-cve-explorer',
    module: '1. CVE Explorer',
    testName:
      'Search by CVE/vendor/product, filter by CVSS & severity, display missing fields as Unknown, and export RFC-4180 CSV',
    passed: t1Passed,
    details: t1Passed
      ? `Verified: Missing fields -> "${cveMissing.vendor}" / "${cveMissing.cweDisplay}", CVSS>=9.0 matched ${filteredCritical.length} record(s), CSV generated (${csvOut.split('\n').length} lines)`
      : 'Failed CVE Explorer normalization, filtering, or CSV export check.',
  });

  // ---------------------------------------------------------------------------
  // TEST 2: CISA KEV Tracker — Snapshot Diff for Newly Imported Records, Vendor/Product/Date Filter & 'Unknown != No' Ransomware Semantics
  // ---------------------------------------------------------------------------
  const sampleKevRecords: ParsedKevRecord[] = [
    {
      kevId: 'KEV-CVE-2024-3400',
      cveId: 'CVE-2024-3400',
      vendorProject: 'Palo Alto Networks',
      product: 'PAN-OS',
      vulnerabilityName: 'PAN-OS Command Injection Vulnerability',
      dateAdded: '2024-04-12',
      shortDescription: 'Command injection in GlobalProtect feature.',
      requiredAction: 'Apply updates per vendor instructions.',
      dueDate: '2024-04-19',
      knownRansomwareCampaignUse: 'Known',
      notes: '',
      cwes: ['CWE-77'],
      catalogVersion: '2026.11.20',
      dateReleased: '2026-11-20',
      provenance: {
        connectorId: 'cisa_kev',
        sourceName: 'CISA Known Exploited Vulnerabilities (KEV) Catalog',
        sourceUrl:
          'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        retrievedAt: '2026-11-21T00:00:00Z',
      },
    },
    {
      kevId: 'KEV-CVE-2026-129448',
      cveId: 'CVE-2026-129448',
      vendorProject: 'Apache',
      product: 'Roller',
      vulnerabilityName: 'Apache Roller Deserialization Vulnerability',
      dateAdded: '2026-11-20',
      shortDescription: 'Untrusted data deserialization in XML-RPC.',
      requiredAction: 'Apply updates per vendor instructions.',
      dueDate: '2026-12-11',
      knownRansomwareCampaignUse: 'Unknown',
      notes: '',
      cwes: ['CWE-502'],
      catalogVersion: '2026.11.20',
      dateReleased: '2026-11-20',
      provenance: {
        connectorId: 'cisa_kev',
        sourceName: 'CISA Known Exploited Vulnerabilities (KEV) Catalog',
        sourceUrl:
          'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        retrievedAt: '2026-11-21T00:00:00Z',
      },
    },
  ];

  // Previous sync snapshot only had CVE-2024-3400; CVE-2026-129448 should be identified as newly imported
  const diffResult = computeKevSnapshotDiff(['CVE-2024-3400'], sampleKevRecords);
  const filteredNewApache = filterAndSortKevRecords(diffResult.records, {
    vendorFilter: 'Apache',
    productFilter: 'Roller',
    dateFrom: '2026-11-01',
    dateTo: '2026-11-30',
    snapshotFilter: 'NEWLY_IMPORTED',
  });

  const t2Passed =
    diffResult.summary.newlyImportedCount === 1 &&
    diffResult.summary.newlyImportedCveIds[0] === 'CVE-2026-129448' &&
    filteredNewApache.length === 1 &&
    filteredNewApache[0].isNewlyImported === true &&
    filteredNewApache[0].ransomwareSemanticLabel.includes(
      'Do NOT interpret Unknown as No'
    );

  results.push({
    id: 'phase3-cisa-kev',
    module: '2. CISA KEV Tracker',
    testName:
      'Identify newly imported records via snapshot diff, filter by vendor/product/date, and preserve Unknown != No ransomware semantics',
    passed: t2Passed,
    details: t2Passed
      ? `Verified: Snapshot diff detected ${diffResult.summary.newlyImportedCount} newly imported CVE (${diffResult.summary.newlyImportedCveIds.join(', ')}), ransomware label="${filteredNewApache[0].ransomwareSemanticLabel}"`
      : 'Failed CISA KEV snapshot diff or ransomware Unknown semantics check.',
  });

  // ---------------------------------------------------------------------------
  // TEST 3: Malware Intelligence — SHA-256 Lookup Validation & Authorized Indicator Filtering
  // ---------------------------------------------------------------------------
  const validHash =
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
  const invalidHash = 'not-a-valid-sha256-hash-12345';

  const indicators = filterMalwareIndicators(
    [
      {
        indicatorId: 'IND-SHA256-01',
        indicatorType: 'sha256',
        defangedValue: validHash,
        threatType: 'malware_payload_hash',
        malwareFamily: 'Public Verification Test Hash',
        status: 'verified',
        severity: 'HIGH',
        sourceName: 'CIRCL Public Hashlookup / Authorized Firestore Feed',
        sourceUrl: 'https://hashlookup.circl.lu/',
        firstSeenAt: '2026-11-20T00:00:00Z',
        updatedAt: '2026-11-21T00:00:00Z',
        sha256: validHash,
      },
    ],
    {
      searchQuery: validHash.slice(0, 16),
      indicatorType: 'sha256',
      statusFilter: 'verified',
    }
  );

  const t3Passed =
    isValidSha256Hash(validHash) === true &&
    isValidSha256Hash(invalidHash) === false &&
    indicators.length === 1 &&
    indicators[0].sourceName.includes('CIRCL');

  results.push({
    id: 'phase3-malware-intel',
    module: '3. Malware Intelligence',
    testName:
      'Validate 64-hex SHA-256 lookup hashes and filter authorized threat indicators with source attribution',
    passed: t3Passed,
    details: t3Passed
      ? `Verified: 64-hex SHA-256 validation passed, invalid hash rejected, matched ${indicators.length} authorized indicator`
      : 'Failed SHA-256 validation or indicator filtering.',
  });

  // ---------------------------------------------------------------------------
  // TEST 4: Scam & Phishing — Suspicious URL Parsing, Threat Feed Matching & 'No Match != Safe' Explanation
  // ---------------------------------------------------------------------------
  const suspiciousAnalysis = parseAndInspectSuspiciousUrl(
    'http://admin@xn--pple-43d-login-verify.example.com:8080/auth/drop.exe?token=secret123&otp=9999',
    [
      {
        feedName: 'Verified Community Scam Reports (Firestore)',
        indicatorId: 'SCAM-001',
        defangedOrRawValue: 'hxxp://xn--pple-43d-login-verify[.]example[.]com',
        categoryOrThreat: 'brand_impersonation',
        verificationStatus: 'approved',
      },
    ]
  );

  const unmatchedAnalysis = parseAndInspectSuspiciousUrl(
    'https://unlisted-new-domain-test.example.org/login',
    []
  );

  const t4Passed =
    suspiciousAnalysis.validSyntax === true &&
    suspiciousAnalysis.defangedUrl.startsWith('hxxp://') &&
    suspiciousAnalysis.defangedUrl.includes('[REDACTED]') &&
    !suspiciousAnalysis.defangedUrl.includes('secret123') &&
    suspiciousAnalysis.structuralRiskSignals.length >= 4 &&
    suspiciousAnalysis.matchCount === 1 &&
    unmatchedAnalysis.matchCount === 0 &&
    unmatchedAnalysis.noMatchSafetyExplanation.includes(
      'NO MATCH DOES NOT MEAN SAFE'
    );

  results.push({
    id: 'phase3-scam-phishing',
    module: '4. Scam & Phishing',
    testName:
      'Parse suspicious URLs (defang, redact query secrets, flag Punycode/@/IP), match feeds, and explain No Match != Safe',
    passed: t4Passed,
    details: t4Passed
      ? `Verified: Detected ${suspiciousAnalysis.structuralRiskSignals.length} structural signals, matched ${suspiciousAnalysis.matchCount} feed entry, redacted query values, and enforced "NO MATCH DOES NOT MEAN SAFE" disclaimer`
      : 'Failed suspicious URL analysis or feed matching.',
  });

  // ---------------------------------------------------------------------------
  // TEST 5: Security Advisories & Pagination — Official Source Links, Publication Date, Category Filter & Pagination
  // ---------------------------------------------------------------------------
  const parsedAdvisories = validateAndParseGithubAdvisories([
    {
      ghsa_id: 'GHSA-xxxx-yyyy-zzzz',
      cve_id: 'CVE-2024-3094',
      summary: 'Critical backdoor in xz package',
      description: 'Upstream xz release tarballs contained obfuscated backdoor code.',
      severity: 'critical',
      published_at: '2024-03-29T17:15:00Z',
      html_url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
      vulnerabilities: [{ package: { ecosystem: 'npm', name: 'xz-wrapper' } }],
    },
    {
      ghsa_id: 'GHSA-aaaa-bbbb-cccc',
      cve_id: null,
      summary: 'High severity deserialization in pip library',
      description: 'Arbitrary code execution via pickle load.',
      severity: 'high',
      published_at: '2024-03-20T10:00:00Z',
      html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      vulnerabilities: [{ package: { ecosystem: 'pip', name: 'sample-pkg' } }],
    },
  ]);

  const npmOnly = filterAndSortAdvisories(parsedAdvisories.records, {
    categoryFilter: 'npm',
    severityFilter: 'CRITICAL',
  });

  const paginated = paginateArray(
    Array.from({ length: 25 }, (_, i) => ({ id: i + 1 })),
    2,
    10
  );

  const t5Passed =
    parsedAdvisories.valid &&
    parsedAdvisories.records.length === 2 &&
    parsedAdvisories.records[1].cveId === 'Unknown' &&
    npmOnly.length === 1 &&
    npmOnly[0].officialSourceUrl ===
      'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz' &&
    npmOnly[0].sourceName.includes('GitHub Security Advisory Database') &&
    paginated.currentPage === 2 &&
    paginated.totalPages === 3 &&
    paginated.pageItems.length === 10 &&
    paginated.hasPrevPage === true &&
    paginated.hasNextPage === true;

  results.push({
    id: 'phase3-advisories-pagination',
    module: '5. Security Advisories & Pagination',
    testName:
      'Validate official advisory source links, publication dates, category filters, attribution, and pagination math',
    passed: t5Passed,
    details: t5Passed
      ? `Verified: Category filter matched ${npmOnly.length} advisory (${npmOnly[0].officialSourceUrl}), pagination Page 2/3 returned ${paginated.pageItems.length} items`
      : 'Failed Security Advisories parsing, category filtering, or pagination check.',
  });

  return results;
}

// Allow direct CLI execution via `npx tsx src/intelligence/intelligence.test.ts`
const isDirectRun =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1]?.includes('intelligence.test.ts');

if (isDirectRun) {
  const suite = runIntelligenceCenterTests();
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
