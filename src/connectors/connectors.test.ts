/**
 * KIRON PROHORI — Phase 2 Automated Connector Parsing, Validation & Non-Destructive Cache Tests
 * Executable both in Node/CLI (`npx tsx src/connectors/connectors.test.ts`) and inside the UI Test Runner.
 */

import {
  validateAndParseCisaKevCatalog,
  validateAndParseNvdResponse,
  validateAndParseEpssResponse,
  validateAndParseUrlhausResponse,
  validateAndParseFeodoTrackerResponse,
  mergeNonDestructiveById,
  evaluateDataFreshness,
} from './parsers';

export interface AutomatedParserTestResult {
  id: string;
  connector: string;
  testName: string;
  passed: boolean;
  details: string;
}

export function runAutomatedConnectorParserTests(): AutomatedParserTestResult[] {
  const results: AutomatedParserTestResult[] = [];

  // 1. CISA KEV Valid Schema & Metadata Preservation + Duplicate Detection
  const sampleKevPayload = {
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    catalogVersion: '2026.11.21',
    dateReleased: '2026-11-21T00:00:00.000Z',
    count: 2,
    vulnerabilities: [
      {
        cveID: 'CVE-2021-44228',
        vendorProject: 'Apache',
        product: 'Log4j2',
        vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
        dateAdded: '2021-12-10',
        shortDescription: 'JNDI lookup RCE vulnerability.',
        requiredAction: 'Apply updates per vendor instructions.',
        dueDate: '2021-12-24',
        knownRansomwareCampaignUse: 'Known',
        notes: 'https://logging.apache.org/log4j/2.x/security.html',
        cwes: ['CWE-502'],
      },
      // Duplicate CVE ID to test upsert deduplication
      {
        cveID: 'CVE-2021-44228',
        vendorProject: 'Apache',
        product: 'Log4j2',
        vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability (Updated)',
        dateAdded: '2021-12-10',
        shortDescription: 'JNDI lookup RCE vulnerability updated record.',
        requiredAction: 'Apply updates per vendor instructions.',
        dueDate: '2021-12-24',
        knownRansomwareCampaignUse: 'Known',
      },
      // Invalid CVE ID to test schema rejection of malformed entries
      {
        cveID: 'INVALID-ID-999',
        vendorProject: 'BadEntry',
      },
    ],
  };

  const kevParsed = validateAndParseCisaKevCatalog(sampleKevPayload);
  const kevPass =
    kevParsed.valid &&
    kevParsed.catalogVersion === '2026.11.21' &&
    kevParsed.dateReleased === '2026-11-21T00:00:00.000Z' &&
    kevParsed.uniqueCount === 1 &&
    kevParsed.duplicatesCollapsed === 1 &&
    kevParsed.invalidSkipped === 1 &&
    kevParsed.records[0].knownRansomwareCampaignUse === 'Known';

  results.push({
    id: 'kev_schema_and_dedup',
    connector: 'CISA KEV',
    testName: 'Parse catalogVersion, dateReleased, deduplicate CVE IDs & skip malformed items',
    passed: kevPass,
    details: kevPass
      ? `Verified: catalogVersion=${kevParsed.catalogVersion}, unique=1, duplicatesCollapsed=1, invalidSkipped=1`
      : `Failed KEV parser assertions: ${JSON.stringify(kevParsed)}`,
  });

  // 2. CISA KEV Malformed Root Rejection
  const badKev = validateAndParseCisaKevCatalog({ invalidRoot: true });
  results.push({
    id: 'kev_reject_malformed_root',
    connector: 'CISA KEV',
    testName: 'Reject malformed response missing catalogVersion / vulnerabilities array',
    passed: !badKev.valid && Boolean(badKev.error),
    details: !badKev.valid
      ? `Correctly rejected with error: "${badKev.error}"`
      : 'Unexpectedly accepted malformed KEV root object',
  });

  // 3. NIST NVD API 2.0 Schema, CVSS v3.1, CWE, References & CPE Extraction
  const sampleNvdPayload = {
    resultsPerPage: 1,
    startIndex: 0,
    totalResults: 1,
    format: 'NVD_CVE',
    version: '2.0',
    timestamp: '2026-11-21T12:00:00.000',
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2024-3094',
          published: '2024-03-29T17:15:11.000',
          lastModified: '2024-04-02T14:20:00.000',
          vulnStatus: 'Analyzed',
          descriptions: [
            {
              lang: 'en',
              value: 'Malicious code was discovered in the upstream tarballs of xz.',
            },
          ],
          metrics: {
            cvssMetricV31: [
              {
                type: 'Primary',
                cvssData: {
                  version: '3.1',
                  vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                  baseScore: 10.0,
                  baseSeverity: 'CRITICAL',
                },
                exploitabilityScore: 3.9,
                impactScore: 6.0,
              },
            ],
          },
          weaknesses: [
            {
              description: [{ lang: 'en', value: 'CWE-506' }],
            },
          ],
          configurations: [
            {
              nodes: [
                {
                  cpeMatch: [
                    {
                      vulnerable: true,
                      criteria: 'cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*',
                    },
                  ],
                },
              ],
            },
          ],
          references: [
            {
              url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
              source: 'NIST NVD',
              tags: ['Vendor Advisory'],
            },
          ],
        },
      },
    ],
  };

  const nvdParsed = validateAndParseNvdResponse(sampleNvdPayload);
  const nvdRec = nvdParsed.records[0];
  const nvdPass =
    nvdParsed.valid &&
    nvdParsed.totalResults === 1 &&
    nvdRec?.cveId === 'CVE-2024-3094' &&
    nvdRec?.cvss.baseScore === 10.0 &&
    nvdRec?.cvss.baseSeverity === 'CRITICAL' &&
    nvdRec?.cwes.includes('CWE-506') &&
    nvdRec?.vendor === 'tukaani' &&
    nvdRec?.product === 'xz' &&
    nvdRec?.references.length === 1;

  results.push({
    id: 'nvd_api2_parse',
    connector: 'NIST NVD 2.0',
    testName: 'Extract CVSS v3.1 metrics, CWEs, CPE vendor/product, and pagination metadata',
    passed: nvdPass,
    details: nvdPass
      ? `Verified: ${nvdRec.cveId} CVSS=${nvdRec.cvss.baseScore} (${nvdRec.cvss.baseSeverity}), CWE=${nvdRec.cwes[0]}, CPE=${nvdRec.vendor}/${nvdRec.product}`
      : 'Failed NVD 2.0 parser assertion',
  });

  // 4. FIRST EPSS 30-Day Probability Estimation Parser & Disclaimer Verification
  const sampleEpssPayload = {
    status: 'OK',
    'status-code': 200,
    version: '1.0',
    total: 1,
    data: [
      {
        cve: 'CVE-2021-44228',
        epss: '0.97565',
        percentile: '0.99985',
        date: '2026-11-21',
      },
    ],
  };

  const epssParsed = validateAndParseEpssResponse(sampleEpssPayload);
  const epssRec = epssParsed.records[0];
  const epssPass =
    epssParsed.valid &&
    epssRec?.cveId === 'CVE-2021-44228' &&
    epssRec?.epssPercentage === '97.57%' &&
    epssRec?.estimateDisclaimer.includes('next 30 days');

  results.push({
    id: 'first_epss_parse',
    connector: 'FIRST EPSS',
    testName: 'Parse EPSS probability & enforce 30-day estimation disclaimer label',
    passed: epssPass,
    details: epssPass
      ? `Verified: ${epssRec.cveId} EPSS=${epssRec.epssPercentage} (${epssRec.percentilePercentage} percentile) with mandatory 30-day estimate label`
      : 'Failed FIRST EPSS parser assertion',
  });

  // 5. URLhaus Response Validation & Mandatory Automatic URL Defanging
  const sampleUrlhausPayload = {
    query_status: 'ok',
    urls: [
      {
        id: '2890123',
        url_status: 'online',
        date_added: '2026-11-21 08:10:00 UTC',
        url: 'http://198.51.100.42/payload/dropper.exe',
        host: '198.51.100.42',
        threat: 'malware_download',
        tags: ['exe', 'Mirai'],
        urlhaus_reference: 'https://urlhaus.abuse.ch/url/2890123/',
        reporter: 'sec_analyst',
      },
    ],
  };

  const urlhausParsed = validateAndParseUrlhausResponse(sampleUrlhausPayload);
  const uhRec = urlhausParsed.records[0];
  const uhPass =
    urlhausParsed.valid &&
    uhRec?.defangedUrl === 'hxxp://198[.]51[.]100[.]42/payload/dropper[.]exe' &&
    uhRec?.defangedHost === '198[.]51[.]100[.]42';

  results.push({
    id: 'urlhaus_defang_parse',
    connector: 'URLhaus',
    testName: 'Validate URLhaus schema and automatically defang URLs & hosts (hxxp://...[.])',
    passed: uhPass,
    details: uhPass
      ? `Verified defanged output: ${uhRec.defangedUrl}`
      : 'Failed URLhaus defanging assertion',
  });

  // 6. abuse.ch Feodo Tracker Keyless Botnet C2 Blocklist Parser, Defanging & Deduplication
  const sampleFeodoPayload = [
    {
      ip_address: '50.16.16.211',
      port: 443,
      status: 'online',
      hostname: 'ec2-50-16-16-211.compute-1.amazonaws.com',
      as_number: 14618,
      as_name: 'AMAZON-AES',
      country: 'US',
      first_seen: '2025-12-30 13:56:31',
      last_online: '2026-03-12',
      malware: 'QakBot',
    },
    // Duplicate IP:Port to test deduplication
    {
      ip_address: '50.16.16.211',
      port: 443,
      status: 'online',
      hostname: 'ec2-50-16-16-211.compute-1.amazonaws.com',
      as_number: 14618,
      as_name: 'AMAZON-AES',
      country: 'US',
      first_seen: '2025-12-30 13:56:31',
      last_online: '2026-03-12',
      malware: 'QakBot',
    },
    // Malformed entry to test rejection
    {
      ip_address: 'not_an_ip',
      port: 999999,
    },
  ];

  const feodoParsed = validateAndParseFeodoTrackerResponse(sampleFeodoPayload);
  const feodoRec = feodoParsed.records[0];
  const feodoPass =
    feodoParsed.valid &&
    feodoParsed.uniqueCount === 1 &&
    feodoParsed.duplicatesCollapsed === 1 &&
    feodoParsed.invalidSkipped === 1 &&
    feodoRec?.defangedIpPort === '50[.]16[.]16[.]211:443' &&
    feodoRec?.defangedHostname === 'ec2-50-16-16-211[.]compute-1[.]amazonaws[.]com' &&
    feodoRec?.malwareFamily === 'QakBot' &&
    feodoRec?.c2Status === 'online';

  results.push({
    id: 'feodo_tracker_parse_and_dedup',
    connector: 'Feodo Tracker',
    testName: 'Validate keyless Feodo Tracker Botnet C2 JSON, defang IP:Port & hostname, and deduplicate',
    passed: feodoPass,
    details: feodoPass
      ? `Verified: ${feodoRec.defangedIpPort} (${feodoRec.malwareFamily}), unique=1, duplicatesCollapsed=1, invalidSkipped=1`
      : 'Failed Feodo Tracker parser assertion',
  });

  // 7. Non-Destructive Cache Preservation on Upstream Failure / Partial Upsert
  const existingCache = [
    { id: 'CVE-2021-44228', val: 'v1' },
    { id: 'CVE-2023-4863', val: 'v1' },
  ];
  const failedEmptyPull = mergeNonDestructiveById(existingCache, [], (x) => x.id);
  const upsertPull = mergeNonDestructiveById(
    existingCache,
    [
      { id: 'CVE-2021-44228', val: 'v2_updated' },
      { id: 'CVE-2024-3094', val: 'v1_new' },
    ],
    (x) => x.id
  );
  const freshnessStale = evaluateDataFreshness('2026-11-10T00:00:00.000Z');

  const cachePass =
    failedEmptyPull.merged.length === 2 &&
    upsertPull.merged.length === 3 &&
    upsertPull.insertedCount === 1 &&
    upsertPull.updatedCount === 1 &&
    freshnessStale.level === 'stale' &&
    Boolean(freshnessStale.warningEn);

  results.push({
    id: 'non_destructive_cache_and_freshness',
    connector: 'Data Engine',
    testName: 'Preserve existing cache on failed/empty pull, upsert by ID, and emit staleness warnings',
    passed: cachePass,
    details: cachePass
      ? `Verified: Empty pull preserved 2/2 cached records; upsert inserted=1, updated=1 (total 3); stale snapshot emitted warning`
      : 'Failed non-destructive cache or staleness check',
  });

  return results;
}

// Allow direct CLI execution via `npx tsx src/connectors/connectors.test.ts`
const isDirectExecution =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1]?.includes('connectors.test');

if (isDirectExecution) {
  const suite = runAutomatedConnectorParserTests();
  let failed = 0;
  for (const t of suite) {
    console.log(
      `${t.passed ? 'PASS' : 'FAIL'} [${t.connector}] ${t.testName} -> ${t.details}`
    );
    if (!t.passed) failed++;
  }
  if (failed > 0) {
    process.exit(1);
  }
}
