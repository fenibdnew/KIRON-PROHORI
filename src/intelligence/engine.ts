/**
 * KIRON PROHORI — Phase 3: Intelligence Center Core Engine
 * Pure, deterministic functions for:
 * 1. CVE Explorer (Search, CVSS/Severity Filter, Unknown normalization, Sorting, Pagination, CSV Export)
 * 2. CISA KEV Tracker (Vendor/Product/Date Filter, Ransomware 'Unknown != No' semantics, Snapshot Diff comparison)
 * 3. Malware Intelligence (SHA-256 validation, Authorized Indicator Filtering, Defanging)
 * 4. Scam & Phishing Intelligence (Suspicious URL Parsing, Threat Feed Matching, Mandatory 'No Match != Safe' Notice)
 * 5. Security Advisories (Official GHSA + CISA KEV + Firestore Advisory Parsing, Category Filtering, Attribution)
 */

import {
  CVE_ID_REGEX,
  ParsedKevRecord,
  ParsedNvdCveRecord,
  ParsedEpssRecord,
  defangUrlOrHost,
} from '../connectors/parsers.ts';

// ============================================================================
// 1. CVE EXPLORER TYPES & FUNCTIONS
// ============================================================================

export interface NormalizedCveIntelligenceRecord {
  cveId: string;
  title: string;
  description: string;
  vendor: string;
  product: string;
  cvssVersion: string;
  cvssScore: number | null;
  cvssScoreDisplay: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'Unknown';
  cvssVector: string;
  exploitabilityScore: number | null;
  impactScore: number | null;
  cwes: string[];
  cweDisplay: string;
  affectedConfigurations: string[];
  affectedConfigurationsDisplay: string;
  references: { url: string; source: string; tags: string[] }[];
  publishedAt: string;
  lastModifiedAt: string;
  sourceName: string;
  sourceUrl: string;
  retrievedAt: string;
  inKev: boolean;
  kevRecord: ParsedKevRecord | null;
  kevStatusLabel: string;
  kevSafetyNote: string;
  epssRecord: ParsedEpssRecord | null;
}

export interface CveFilterAndSortOptions {
  searchQuery?: string;
  vendorFilter?: string;
  productFilter?: string;
  severityFilter?: 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'Unknown';
  minCvss?: number;
  maxCvss?: number;
  kevFilter?: 'ALL' | 'IN_KEV' | 'NOT_IN_KEV';
  sortBy?: 'cvssScore' | 'publishedAt' | 'lastModifiedAt' | 'cveId';
  sortDirection?: 'asc' | 'desc';
}

function cleanFieldOrUnknown(value: unknown): string {
  if (typeof value !== 'string') return 'Unknown';
  const trimmed = value.trim();
  if (
    !trimmed ||
    trimmed.toLowerCase() === 'n/a' ||
    trimmed.toLowerCase() === 'unspecified' ||
    trimmed.toLowerCase() === 'none' ||
    trimmed.toLowerCase() === 'not specified'
  ) {
    return 'Unknown';
  }
  return trimmed;
}

/**
 * Normalizes any NVD or Firestore CVE record so missing fields are explicitly 'Unknown'
 * and KEV status never labels non-KEV CVEs as safe.
 */
export function normalizeCveRecordWithUnknowns(
  rec: Partial<ParsedNvdCveRecord> & {
    cveId: string;
    kevRecord?: ParsedKevRecord | null;
    epssRecord?: ParsedEpssRecord | null;
    cvssScore?: number;
    severity?: string;
    cvssVector?: string;
    source?: string;
    publishedAt?: string;
  }
): NormalizedCveIntelligenceRecord {
  const cveId = cleanFieldOrUnknown(rec.cveId).toUpperCase();
  const vendor = cleanFieldOrUnknown(rec.vendor);
  const product = cleanFieldOrUnknown(rec.product);
  const description = cleanFieldOrUnknown(rec.description);

  const rawScore =
    typeof rec.cvss?.baseScore === 'number'
      ? rec.cvss.baseScore
      : typeof rec.cvssScore === 'number'
      ? rec.cvssScore
      : null;

  const hasValidScore =
    rawScore !== null && !Number.isNaN(rawScore) && rawScore > 0;
  const cvssScore = hasValidScore ? rawScore : null;
  const cvssScoreDisplay =
    cvssScore !== null ? cvssScore.toFixed(1) : 'Unknown';

  const rawSev = (
    rec.cvss?.baseSeverity ||
    rec.severity ||
    ''
  )
    .toString()
    .trim()
    .toUpperCase();

  let severity: NormalizedCveIntelligenceRecord['severity'] = 'Unknown';
  if (
    rawSev === 'CRITICAL' ||
    rawSev === 'HIGH' ||
    rawSev === 'MEDIUM' ||
    rawSev === 'LOW'
  ) {
    severity = rawSev;
  } else if (cvssScore !== null) {
    if (cvssScore >= 9.0) severity = 'CRITICAL';
    else if (cvssScore >= 7.0) severity = 'HIGH';
    else if (cvssScore >= 4.0) severity = 'MEDIUM';
    else if (cvssScore > 0) severity = 'LOW';
  }

  const rawVector = rec.cvss?.vectorString || rec.cvssVector || '';
  const cvssVector =
    typeof rawVector === 'string' &&
    rawVector.trim() &&
    !rawVector.includes('UNKNOWN')
      ? rawVector.trim()
      : 'Unknown';

  const rawCwes = Array.isArray(rec.cwes)
    ? rec.cwes
        .map((c) => cleanFieldOrUnknown(c))
        .filter((c) => c !== 'Unknown' && !c.includes('NVD-CWE'))
    : [];
  const cwes = rawCwes.length > 0 ? rawCwes : ['Unknown'];
  const cweDisplay = cwes.join(', ');

  const rawConfigs = Array.isArray(rec.affectedConfigurations)
    ? rec.affectedConfigurations
        .map((c) => cleanFieldOrUnknown(c))
        .filter((c) => c !== 'Unknown')
    : [];
  const affectedConfigurations =
    rawConfigs.length > 0 ? rawConfigs : ['Unknown'];
  const affectedConfigurationsDisplay = affectedConfigurations.join(' | ');

  const references =
    Array.isArray(rec.references) && rec.references.length > 0
      ? rec.references.map((r) => ({
          url: cleanFieldOrUnknown(r.url),
          source: cleanFieldOrUnknown(r.source),
          tags: Array.isArray(r.tags) ? r.tags : [],
        }))
      : [];

  const publishedAt = cleanFieldOrUnknown(rec.published || rec.publishedAt);
  const lastModifiedAt = cleanFieldOrUnknown(
    rec.lastModified || rec.published || rec.publishedAt
  );
  const sourceName = cleanFieldOrUnknown(
    rec.provenance?.sourceName || rec.source || 'NIST National Vulnerability Database (NVD API 2.0)'
  );
  const sourceUrl =
    rec.provenance?.sourceUrl && rec.provenance.sourceUrl.trim()
      ? rec.provenance.sourceUrl.trim()
      : `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const retrievedAt =
    rec.provenance?.retrievedAt || new Date().toISOString();

  const kevRecord = rec.kevRecord || null;
  const inKev = Boolean(kevRecord);
  const kevStatusLabel = inKev
    ? 'CONFIRMED IN CISA KEV'
    : 'Not Listed in CISA KEV';
  const kevSafetyNote = inKev
    ? `Confirmed active exploitation in CISA KEV (Added ${kevRecord?.dateAdded || 'Unknown'}, Due ${kevRecord?.dueDate || 'Unknown'}).`
    : 'Not listed in CISA KEV — Absence from KEV does NOT mean this CVE is safe or unexploited.';

  return {
    cveId,
    title:
      rec.title && rec.title.trim()
        ? rec.title.trim()
        : `${cveId} (${vendor} / ${product})`,
    description,
    vendor,
    product,
    cvssVersion: cleanFieldOrUnknown(rec.cvss?.version || '3.1'),
    cvssScore,
    cvssScoreDisplay,
    severity,
    cvssVector,
    exploitabilityScore:
      typeof rec.cvss?.exploitabilityScore === 'number'
        ? rec.cvss.exploitabilityScore
        : null,
    impactScore:
      typeof rec.cvss?.impactScore === 'number' ? rec.cvss.impactScore : null,
    cwes,
    cweDisplay,
    affectedConfigurations,
    affectedConfigurationsDisplay,
    references,
    publishedAt,
    lastModifiedAt,
    sourceName,
    sourceUrl,
    retrievedAt,
    inKev,
    kevRecord,
    kevStatusLabel,
    kevSafetyNote,
    epssRecord: rec.epssRecord || null,
  };
}

/**
 * Filters and sorts normalized CVE records by CVE ID, vendor, product, CVSS range, severity, and KEV status.
 */
export function filterAndSortCveRecords(
  records: NormalizedCveIntelligenceRecord[],
  options: CveFilterAndSortOptions
): NormalizedCveIntelligenceRecord[] {
  const q = (options.searchQuery || '').trim().toLowerCase();
  const vendorQ = (options.vendorFilter || '').trim().toLowerCase();
  const productQ = (options.productFilter || '').trim().toLowerCase();
  const sev = options.severityFilter || 'ALL';
  const minCvss =
    typeof options.minCvss === 'number' && !Number.isNaN(options.minCvss)
      ? options.minCvss
      : 0;
  const maxCvss =
    typeof options.maxCvss === 'number' && !Number.isNaN(options.maxCvss)
      ? options.maxCvss
      : 10;
  const kevFilter = options.kevFilter || 'ALL';
  const sortBy = options.sortBy || 'cvssScore';
  const sortDir = options.sortDirection || 'desc';

  const filtered = records.filter((rec) => {
    if (q) {
      const hay = `${rec.cveId} ${rec.vendor} ${rec.product} ${rec.description} ${rec.cweDisplay} ${rec.affectedConfigurationsDisplay}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }

    if (vendorQ && !rec.vendor.toLowerCase().includes(vendorQ)) {
      return false;
    }

    if (productQ && !rec.product.toLowerCase().includes(productQ)) {
      return false;
    }

    if (sev !== 'ALL' && rec.severity !== sev) {
      return false;
    }

    if (minCvss > 0 || maxCvss < 10) {
      const scoreVal = rec.cvssScore ?? 0;
      if (scoreVal < minCvss || scoreVal > maxCvss) return false;
    }

    if (kevFilter === 'IN_KEV' && !rec.inKev) return false;
    if (kevFilter === 'NOT_IN_KEV' && rec.inKev) return false;

    return true;
  });

  const multiplier = sortDir === 'asc' ? 1 : -1;

  return [...filtered].sort((a, b) => {
    if (sortBy === 'cvssScore') {
      const sa = a.cvssScore ?? -1;
      const sb = b.cvssScore ?? -1;
      if (sa !== sb) return (sa - sb) * multiplier;
    } else if (sortBy === 'publishedAt') {
      const cmp = a.publishedAt.localeCompare(b.publishedAt);
      if (cmp !== 0) return cmp * multiplier;
    } else if (sortBy === 'lastModifiedAt') {
      const cmp = a.lastModifiedAt.localeCompare(b.lastModifiedAt);
      if (cmp !== 0) return cmp * multiplier;
    }
    return a.cveId.localeCompare(b.cveId) * multiplier;
  });
}

function escapeCsvCell(value: string): string {
  const normalized = value.replace(/\r?\n|\r/g, ' ');
  if (
    normalized.includes(',') ||
    normalized.includes('"') ||
    normalized.includes(';')
  ) {
    return `"${normalized.replace(/"/g, '""')}"`;
  }
  return normalized;
}

/**
 * Generates an RFC-4180 compliant CSV string for exported CVE records with full source attribution.
 */
export function exportCveRecordsToCsv(
  records: NormalizedCveIntelligenceRecord[]
): string {
  const headers = [
    'CVE_ID',
    'Vendor',
    'Product',
    'Severity',
    'CVSS_Score',
    'CVSS_Vector',
    'CWE',
    'KEV_Status',
    'Published_Date',
    'Last_Modified_Date',
    'Affected_Configurations',
    'Source_Attribution',
    'Official_Reference_URL',
    'Description',
  ];

  const rows = records.map((r) =>
    [
      r.cveId,
      r.vendor,
      r.product,
      r.severity,
      r.cvssScoreDisplay,
      r.cvssVector,
      r.cweDisplay,
      r.kevStatusLabel,
      r.publishedAt,
      r.lastModifiedAt,
      r.affectedConfigurationsDisplay,
      r.sourceName,
      r.sourceUrl,
      r.description,
    ]
      .map(escapeCsvCell)
      .join(',')
  );

  return [headers.join(','), ...rows].join('\n');
}

// ============================================================================
// 2. CISA KEV TRACKER & SNAPSHOT DIFF FUNCTIONS
// ============================================================================

export interface KevSnapshotDiffSummary {
  previousCount: number;
  currentCount: number;
  newlyImportedCount: number;
  retainedCount: number;
  newlyImportedCveIds: string[];
}

export interface EnrichedKevIntelligenceRecord extends ParsedKevRecord {
  isNewlyImported: boolean;
  ransomwareSemanticLabel: string;
  officialCatalogUrl: string;
  officialNvdUrl: string;
}

export interface KevFilterOptions {
  searchQuery?: string;
  vendorFilter?: string;
  productFilter?: string;
  dateFrom?: string;
  dateTo?: string;
  ransomwareFilter?: 'ALL' | 'Known' | 'Unknown';
  snapshotFilter?: 'ALL' | 'NEWLY_IMPORTED';
  sortBy?: 'dateAdded' | 'dueDate' | 'cveId' | 'vendorProject';
  sortDirection?: 'asc' | 'desc';
}

/**
 * Compares current KEV records against a previous sync snapshot of CVE IDs
 * to identify newly imported records.
 */
export function computeKevSnapshotDiff(
  previousSnapshotCveIds: Iterable<string>,
  currentRecords: ParsedKevRecord[]
): {
  summary: KevSnapshotDiffSummary;
  records: EnrichedKevIntelligenceRecord[];
} {
  const prevSet = new Set<string>();
  for (const id of previousSnapshotCveIds) {
    prevSet.add(id.trim().toUpperCase());
  }

  const newlyImportedCveIds: string[] = [];
  let retainedCount = 0;

  const enriched: EnrichedKevIntelligenceRecord[] = currentRecords.map((rec) => {
    const normId = rec.cveId.trim().toUpperCase();
    // If a previous snapshot existed, any CVE absent from prevSet is newly imported
    const isNew = prevSet.size > 0 ? !prevSet.has(normId) : false;
    if (isNew) {
      newlyImportedCveIds.push(normId);
    } else {
      retainedCount++;
    }

    // Explicitly preserve Unknown without interpreting Unknown as No
    const ransomwareSemanticLabel =
      rec.knownRansomwareCampaignUse === 'Known'
        ? 'Known (Confirmed Ransomware Campaign Use)'
        : 'Unknown (Unconfirmed — Do NOT interpret Unknown as No)';

    return {
      ...rec,
      vendorProject: cleanFieldOrUnknown(rec.vendorProject),
      product: cleanFieldOrUnknown(rec.product),
      vulnerabilityName: cleanFieldOrUnknown(rec.vulnerabilityName),
      requiredAction: cleanFieldOrUnknown(rec.requiredAction),
      isNewlyImported: isNew,
      ransomwareSemanticLabel,
      officialCatalogUrl:
        'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      officialNvdUrl: `https://nvd.nist.gov/vuln/detail/${normId}`,
    };
  });

  return {
    summary: {
      previousCount: prevSet.size,
      currentCount: currentRecords.length,
      newlyImportedCount: newlyImportedCveIds.length,
      retainedCount,
      newlyImportedCveIds,
    },
    records: enriched,
  };
}

/**
 * Filters and sorts enriched CISA KEV records by vendor, product, date range, ransomware use, and snapshot diff status.
 */
export function filterAndSortKevRecords(
  records: EnrichedKevIntelligenceRecord[],
  options: KevFilterOptions
): EnrichedKevIntelligenceRecord[] {
  const q = (options.searchQuery || '').trim().toLowerCase();
  const vendorQ = (options.vendorFilter || '').trim().toLowerCase();
  const productQ = (options.productFilter || '').trim().toLowerCase();
  const dateFrom = (options.dateFrom || '').trim();
  const dateTo = (options.dateTo || '').trim();
  const rw = options.ransomwareFilter || 'ALL';
  const snap = options.snapshotFilter || 'ALL';
  const sortBy = options.sortBy || 'dateAdded';
  const sortDir = options.sortDirection || 'desc';

  const filtered = records.filter((r) => {
    if (q) {
      const hay = `${r.cveId} ${r.vendorProject} ${r.product} ${r.vulnerabilityName} ${r.shortDescription} ${r.requiredAction}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }

    if (vendorQ && !r.vendorProject.toLowerCase().includes(vendorQ)) {
      return false;
    }

    if (productQ && !r.product.toLowerCase().includes(productQ)) {
      return false;
    }

    if (dateFrom && r.dateAdded < dateFrom) {
      return false;
    }

    if (dateTo && r.dateAdded > dateTo) {
      return false;
    }

    if (rw === 'Known' && r.knownRansomwareCampaignUse !== 'Known') {
      return false;
    }

    if (rw === 'Unknown' && r.knownRansomwareCampaignUse !== 'Unknown') {
      return false;
    }

    if (snap === 'NEWLY_IMPORTED' && !r.isNewlyImported) {
      return false;
    }

    return true;
  });

  const mult = sortDir === 'asc' ? 1 : -1;
  return [...filtered].sort((a, b) => {
    if (sortBy === 'dateAdded') {
      const cmp = a.dateAdded.localeCompare(b.dateAdded);
      if (cmp !== 0) return cmp * mult;
    } else if (sortBy === 'dueDate') {
      const cmp = a.dueDate.localeCompare(b.dueDate);
      if (cmp !== 0) return cmp * mult;
    } else if (sortBy === 'vendorProject') {
      const cmp = a.vendorProject.localeCompare(b.vendorProject);
      if (cmp !== 0) return cmp * mult;
    }
    return a.cveId.localeCompare(b.cveId) * mult;
  });
}

// ============================================================================
// 3. MALWARE INTELLIGENCE & SHA-256 HASH LOOKUP FUNCTIONS
// ============================================================================

export const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;

export interface AuthorizedThreatIndicator {
  indicatorId: string;
  indicatorType: 'url' | 'domain' | 'ip' | 'sha256' | 'md5';
  defangedValue: string;
  threatType: string;
  malwareFamily: string;
  status: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sourceName: string;
  sourceUrl: string;
  firstSeenAt: string;
  updatedAt: string;
  sha256?: string;
}

export function isValidSha256Hash(input: string): boolean {
  return SHA256_REGEX.test(input.trim());
}

export function filterMalwareIndicators(
  indicators: AuthorizedThreatIndicator[],
  options: {
    searchQuery?: string;
    indicatorType?: string;
    statusFilter?: string;
    sourceFilter?: string;
  }
): AuthorizedThreatIndicator[] {
  const q = (options.searchQuery || '').trim().toLowerCase();
  const typeF = options.indicatorType || 'ALL';
  const statusF = (options.statusFilter || 'ALL').toLowerCase();
  const sourceF = (options.sourceFilter || '').trim().toLowerCase();

  return indicators.filter((ind) => {
    if (q) {
      const hay = `${ind.indicatorId} ${ind.defangedValue} ${ind.malwareFamily} ${ind.threatType} ${ind.sourceName} ${ind.sha256 || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (typeF !== 'ALL' && ind.indicatorType !== typeF) {
      return false;
    }
    if (statusF !== 'all' && ind.status.toLowerCase() !== statusF) {
      return false;
    }
    if (sourceF && !ind.sourceName.toLowerCase().includes(sourceF)) {
      return false;
    }
    return true;
  });
}

// ============================================================================
// 4. SCAM & PHISHING SUSPICIOUS URL PARSER & THREAT FEED MATCHER
// ============================================================================

export interface FeedMatchHit {
  feedName: string;
  indicatorId: string;
  matchedValue: string;
  categoryOrThreat: string;
  verificationStatus: string;
}

export interface SuspiciousUrlAnalysisResult {
  validSyntax: boolean;
  rawInputLength: number;
  defangedUrl: string;
  defangedHostname: string;
  normalizedHostname: string;
  scheme: string;
  port: string;
  tld: string;
  subdomainDepth: number;
  path: string;
  queryParamKeys: string[];
  structuralRiskSignals: string[];
  feedMatches: FeedMatchHit[];
  matchCount: number;
  noMatchSafetyExplanation: string;
}

const SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'rb.gy',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'shorturl.at',
]);

/**
 * Safely parses a user-supplied URL or domain string locally without visiting it,
 * extracts structural risk signals, matches against configured threat feeds,
 * and enforces the mandatory explanation that no match does NOT mean safe.
 */
export function parseAndInspectSuspiciousUrl(
  rawInput: string,
  configuredFeedIndicators: {
    feedName: string;
    indicatorId: string;
    defangedOrRawValue: string;
    categoryOrThreat: string;
    verificationStatus: string;
  }[]
): SuspiciousUrlAnalysisResult {
  const noMatchSafetyExplanation =
    'NO MATCH DOES NOT MEAN SAFE: Absence from configured threat feeds or verified community scam reports does NOT guarantee that a URL or domain is legitimate. Phishing domains frequently rotate within minutes. Never enter credentials or OTP codes on untrusted links.';

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      validSyntax: false,
      rawInputLength: 0,
      defangedUrl: 'Unknown',
      defangedHostname: 'Unknown',
      normalizedHostname: 'Unknown',
      scheme: 'Unknown',
      port: 'Default',
      tld: 'Unknown',
      subdomainDepth: 0,
      path: '/',
      queryParamKeys: [],
      structuralRiskSignals: ['Empty input provided.'],
      feedMatches: [],
      matchCount: 0,
      noMatchSafetyExplanation,
    };
  }

  // Re-fang temporarily in memory ONLY for URL constructor parsing, then immediately defang
  const refangedForParse = trimmed
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[\.\]/g, '.');

  const candidateWithScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(
    refangedForParse
  )
    ? refangedForParse
    : `http://${refangedForParse}`;

  let protocol = 'http:';
  let username = '';
  let password = '';
  let hostLower = '';
  let port = '';
  let pathname = '/';
  let queryParamKeys: string[] = [];

  try {
    const parsedUrl = new URL(candidateWithScheme);
    protocol = parsedUrl.protocol;
    username = parsedUrl.username;
    password = parsedUrl.password;
    hostLower = parsedUrl.hostname.toLowerCase();
    port = parsedUrl.port;
    pathname = parsedUrl.pathname || '/';
    queryParamKeys = Array.from(
      new Set(Array.from(parsedUrl.searchParams.keys()))
    );
  } catch {
    // Resilient fallback lexical decomposition for malformed or non-standard Punycode phishing URLs
    const match = candidateWithScheme.match(
      /^([a-zA-Z][a-zA-Z0-9+.-]*:)\/\/([^/?#]*)([^?#]*)(\?[^#]*)?/
    );
    if (!match) {
      return {
        validSyntax: false,
        rawInputLength: trimmed.length,
        defangedUrl: defangUrlOrHost(trimmed),
        defangedHostname: 'Unknown',
        normalizedHostname: 'Unknown',
        scheme: 'Unknown',
        port: 'Unknown',
        tld: 'Unknown',
        subdomainDepth: 0,
        path: 'Unknown',
        queryParamKeys: [],
        structuralRiskSignals: [
          'Malformed URL syntax could not be parsed by standard RFC-3986 URL parser.',
        ],
        feedMatches: [],
        matchCount: 0,
        noMatchSafetyExplanation,
      };
    }
    protocol = match[1].toLowerCase();
    const authority = match[2] || '';
    pathname = match[3] || '/';
    const rawQuery = match[4] ? match[4].slice(1) : '';
    const atIdx = authority.lastIndexOf('@');
    const hostPort = atIdx !== -1 ? authority.slice(atIdx + 1) : authority;
    if (atIdx !== -1) {
      username = authority.slice(0, atIdx);
    }
    const colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx !== -1 && !hostPort.endsWith(']')) {
      hostLower = hostPort.slice(0, colonIdx).toLowerCase();
      port = hostPort.slice(colonIdx + 1);
    } else {
      hostLower = hostPort.toLowerCase();
    }
    if (rawQuery) {
      queryParamKeys = Array.from(
        new Set(
          rawQuery
            .split('&')
            .map((kv) => kv.split('=')[0]?.trim())
            .filter(Boolean)
        )
      );
    }
  }

  const hostLabels = hostLower.split('.').filter(Boolean);
  const tld =
    hostLabels.length >= 2 ? `.${hostLabels[hostLabels.length - 1]}` : 'Unknown';
  const subdomainDepth = Math.max(0, hostLabels.length - 2);

  const signals: string[] = [];

  if (protocol === 'http:') {
    signals.push('Unencrypted HTTP transport scheme (no TLS).');
  }

  if (username || password || refangedForParse.includes('@')) {
    signals.push(
      'Contains "@" userinfo segment in URL (classic credential-spoofing trick to disguise actual destination host).'
    );
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostLower) || hostLower.startsWith('[')) {
    signals.push(
      'Destination host is a raw IP literal rather than a registered domain name.'
    );
  }

  if (hostLower.includes('xn--')) {
    signals.push(
      'Contains IDN Punycode ("xn--") label — inspect carefully for Unicode homograph / lookalike character spoofing.'
    );
  }

  if (subdomainDepth >= 3) {
    signals.push(
      `Excessive subdomain nesting depth (${subdomainDepth} subdomain levels) often used to hide the true registrable domain.`
    );
  }

  const hyphenCount = (hostLower.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    signals.push(
      `Multiple hyphens (${hyphenCount}) in hostname — common in brand-impersonation domains (e.g., login-verify-account-...).`
    );
  }

  if (SHORTENER_DOMAINS.has(hostLower)) {
    signals.push(
      `Known URL shortener service (${hostLower}) — obscures the final redirect destination.`
    );
  }

  if (/\.(apk|exe|scr|bat|ps1|vbs|msi|iso|zip|rar)$/i.test(pathname)) {
    signals.push(
      `URL path ends with high-risk executable or archive extension (${pathname.split('.').pop()}).`
    );
  }

  const hostWithPort = port ? `${hostLower}:${port}` : hostLower;
  const defangedFull = defangUrlOrHost(
    `${protocol}//${hostWithPort}${pathname}${
      queryParamKeys.length > 0 ? `?${queryParamKeys.map((k) => `${k}=[REDACTED]`).join('&')}` : ''
    }`
  );
  const defangedHost = defangUrlOrHost(hostLower);

  // Match against configured threat feeds (comparing both defanged host and full defanged URL)
  const feedMatches: FeedMatchHit[] = [];
  for (const item of configuredFeedIndicators) {
    const normFeedVal = item.defangedOrRawValue
      .trim()
      .toLowerCase()
      .replace(/^hxxps?:\/\//, '')
      .replace(/^https?:\/\//, '')
      .replace(/\[\.\]/g, '.');

    if (!normFeedVal) continue;

    if (
      normFeedVal === hostLower ||
      normFeedVal.includes(hostLower) ||
      hostLower.includes(normFeedVal)
    ) {
      feedMatches.push({
        feedName: item.feedName,
        indicatorId: item.indicatorId,
        matchedValue: defangUrlOrHost(item.defangedOrRawValue),
        categoryOrThreat: item.categoryOrThreat,
        verificationStatus: item.verificationStatus,
      });
    }
  }

  return {
    validSyntax: true,
    rawInputLength: trimmed.length,
    defangedUrl: defangedFull,
    defangedHostname: defangedHost,
    normalizedHostname: hostLower,
    scheme: protocol.replace(':', '').toUpperCase(),
    port: port || 'Default',
    tld,
    subdomainDepth,
    path: pathname || '/',
    queryParamKeys,
    structuralRiskSignals: signals,
    feedMatches,
    matchCount: feedMatches.length,
    noMatchSafetyExplanation,
  };
}

// ============================================================================
// 5. SECURITY ADVISORIES PARSER & FILTER ENGINE
// ============================================================================

export interface VerifiedSecurityAdvisory {
  advisoryId: string;
  cveId: string;
  title: string;
  shortSummary: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'Unknown';
  publishedAt: string;
  sourceName: string;
  officialSourceUrl: string;
  retrievedAt: string;
}

export function validateAndParseGithubAdvisories(
  payload: unknown,
  retrievedAt = new Date().toISOString()
): {
  valid: boolean;
  error?: string;
  records: VerifiedSecurityAdvisory[];
} {
  if (!Array.isArray(payload)) {
    return {
      valid: false,
      error: 'Invalid GitHub Advisories payload: expected a JSON array.',
      records: [],
    };
  }

  const records: VerifiedSecurityAdvisory[] = [];
  for (const raw of payload) {
    if (typeof raw !== 'object' || raw === null) continue;
    const item = raw as Record<string, unknown>;
    const ghsaId =
      typeof item.ghsa_id === 'string' && item.ghsa_id.trim()
        ? item.ghsa_id.trim()
        : '';
    if (!ghsaId) continue;

    const cveId =
      typeof item.cve_id === 'string' && CVE_ID_REGEX.test(item.cve_id.trim())
        ? item.cve_id.trim().toUpperCase()
        : 'Unknown';

    const title = cleanFieldOrUnknown(item.summary);
    const rawDesc =
      typeof item.description === 'string' ? item.description.trim() : '';
    const shortSummary =
      rawDesc.length > 0
        ? rawDesc.replace(/\s+/g, ' ').slice(0, 360) +
          (rawDesc.length > 360 ? '...' : '')
        : title;

    let category = 'General Open Source';
    if (Array.isArray(item.vulnerabilities) && item.vulnerabilities.length > 0) {
      const firstVuln = item.vulnerabilities[0] as Record<string, unknown>;
      const pkg =
        typeof firstVuln?.package === 'object' && firstVuln.package !== null
          ? (firstVuln.package as Record<string, unknown>)
          : null;
      if (pkg && typeof pkg.ecosystem === 'string' && pkg.ecosystem.trim()) {
        category = pkg.ecosystem.trim();
      }
    }

    const rawSev =
      typeof item.severity === 'string' ? item.severity.trim().toUpperCase() : '';
    const severity: VerifiedSecurityAdvisory['severity'] =
      rawSev === 'CRITICAL' ||
      rawSev === 'HIGH' ||
      rawSev === 'MEDIUM' ||
      rawSev === 'LOW'
        ? rawSev
        : 'Unknown';

    const publishedAt =
      typeof item.published_at === 'string' && item.published_at.trim()
        ? item.published_at.trim()
        : 'Unknown';

    const officialSourceUrl =
      typeof item.html_url === 'string' && item.html_url.trim().startsWith('https://')
        ? item.html_url.trim()
        : `https://github.com/advisories/${ghsaId}`;

    records.push({
      advisoryId: ghsaId,
      cveId,
      title,
      shortSummary,
      category,
      severity,
      publishedAt,
      sourceName: 'GitHub Security Advisory Database (GHSA Official API)',
      officialSourceUrl,
      retrievedAt,
    });
  }

  return {
    valid: true,
    records,
  };
}

export function filterAndSortAdvisories(
  advisories: VerifiedSecurityAdvisory[],
  options: {
    searchQuery?: string;
    categoryFilter?: string;
    severityFilter?: string;
    sourceFilter?: string;
  }
): VerifiedSecurityAdvisory[] {
  const q = (options.searchQuery || '').trim().toLowerCase();
  const cat = (options.categoryFilter || 'ALL').toLowerCase();
  const sev = (options.severityFilter || 'ALL').toUpperCase();
  const src = (options.sourceFilter || 'ALL').toLowerCase();

  return [...advisories]
    .filter((adv) => {
      if (q) {
        const hay = `${adv.advisoryId} ${adv.cveId} ${adv.title} ${adv.shortSummary} ${adv.category} ${adv.sourceName}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (cat !== 'all' && adv.category.toLowerCase() !== cat) {
        return false;
      }
      if (sev !== 'ALL' && adv.severity !== sev) {
        return false;
      }
      if (src !== 'all' && !adv.sourceName.toLowerCase().includes(src)) {
        return false;
      }
      return true;
    })
    .sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));
}

// ============================================================================
// 6. GENERIC PAGINATION HELPER
// ============================================================================

export function paginateArray<T>(
  items: T[],
  page: number,
  pageSize: number
): {
  pageItems: T[];
  currentPage: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
  hasPrevPage: boolean;
  hasNextPage: boolean;
} {
  const safePageSize = Math.max(1, pageSize);
  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / safePageSize));
  const currentPage = Math.min(totalPages, Math.max(1, page));
  const start = (currentPage - 1) * safePageSize;
  const pageItems = items.slice(start, start + safePageSize);

  return {
    pageItems,
    currentPage,
    pageSize: safePageSize,
    totalItems,
    totalPages,
    hasPrevPage: currentPage > 1,
    hasNextPage: currentPage < totalPages,
  };
}
