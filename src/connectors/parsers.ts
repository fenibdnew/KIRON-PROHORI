/**
 * KIRON PROHORI — Phase 2 Public Threat Intelligence Schema Validators, Parsers & Deduplicators
 * Zero fabricated data. Strict schema validation, defanging, provenance tracking, and non-destructive upsert.
 */

export const CVE_ID_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export type ConnectorId =
  | 'cisa_kev'
  | 'nist_nvd'
  | 'first_epss'
  | 'urlhaus'
  | 'feodo_tracker';

export type ConnectorOperationalState =
  | 'CONNECTED'
  | 'NOT CONFIGURED'
  | 'NOT CONNECTED'
  | 'SYNCING'
  | 'ERROR'
  | 'STALE DATA';

export interface DataProvenance {
  connectorId: ConnectorId;
  sourceName: string;
  sourceUrl: string;
  retrievedAt: string;
  upstreamVersion?: string;
  upstreamReleaseDate?: string;
}

export interface DataFreshnessInfo {
  level: 'fresh' | 'aging' | 'stale' | 'never';
  ageMinutes: number | null;
  labelEn: string;
  labelBn: string;
  warningEn: string | null;
  warningBn: string | null;
}

export interface ParsedKevRecord {
  kevId: string;
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes: string;
  cwes: string[];
  catalogVersion: string;
  dateReleased: string;
  provenance: DataProvenance;
}

export interface ParsedKevCatalogResult {
  valid: boolean;
  error?: string;
  title: string;
  catalogVersion: string;
  dateReleased: string;
  declaredCount: number;
  totalParsed: number;
  uniqueCount: number;
  duplicatesCollapsed: number;
  invalidSkipped: number;
  records: ParsedKevRecord[];
  provenance: DataProvenance;
}

export interface ParsedNvdReference {
  url: string;
  source: string;
  tags: string[];
}

export interface ParsedNvdCvss {
  version: string;
  baseScore: number;
  baseSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NONE';
  vectorString: string;
  exploitabilityScore: number | null;
  impactScore: number | null;
}

export interface ParsedNvdCveRecord {
  cveId: string;
  title: string;
  description: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  vendor: string;
  product: string;
  cvss: ParsedNvdCvss;
  cwes: string[];
  references: ParsedNvdReference[];
  affectedConfigurations: string[];
  provenance: DataProvenance;
}

export interface ParsedNvdResult {
  valid: boolean;
  error?: string;
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  timestamp: string;
  duplicatesCollapsed: number;
  invalidSkipped: number;
  records: ParsedNvdCveRecord[];
  provenance: DataProvenance;
}

export interface ParsedEpssRecord {
  cveId: string;
  epssScore: number;
  epssPercentage: string;
  percentile: number;
  percentilePercentage: string;
  modelDate: string;
  estimateDisclaimer: string;
  provenance: DataProvenance;
}

export interface ParsedEpssResult {
  valid: boolean;
  error?: string;
  total: number;
  records: ParsedEpssRecord[];
  provenance: DataProvenance;
}

export interface ParsedUrlhausRecord {
  indicatorId: string;
  defangedUrl: string;
  defangedHost: string;
  urlStatus: string;
  dateAdded: string;
  threat: string;
  tags: string[];
  urlhausReference: string;
  reporter: string;
  provenance: DataProvenance;
}

export interface ParsedUrlhausResult {
  valid: boolean;
  error?: string;
  queryStatus: string;
  duplicatesCollapsed: number;
  records: ParsedUrlhausRecord[];
  provenance: DataProvenance;
}

export function defangUrlOrHost(raw: string): string {
  return String(raw || '')
    .trim()
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]');
}

export function normalizeSeverity(
  rawSeverity: unknown,
  score: number
): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  const upper = String(rawSeverity || '').toUpperCase();
  if (upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW') {
    return upper;
  }
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/**
 * 1. Validate & Parse CISA Known Exploited Vulnerabilities (KEV) Official JSON
 */
export function validateAndParseCisaKevCatalog(
  payload: unknown,
  retrievedAt = new Date().toISOString()
): ParsedKevCatalogResult {
  const provenance: DataProvenance = {
    connectorId: 'cisa_kev',
    sourceName: 'CISA Known Exploited Vulnerabilities Catalog',
    sourceUrl:
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    retrievedAt,
  };

  if (typeof payload !== 'object' || payload === null) {
    return {
      valid: false,
      error: 'Invalid CISA KEV response: Root payload must be a JSON object.',
      title: '',
      catalogVersion: '',
      dateReleased: '',
      declaredCount: 0,
      totalParsed: 0,
      uniqueCount: 0,
      duplicatesCollapsed: 0,
      invalidSkipped: 0,
      records: [],
      provenance,
    };
  }

  const root = payload as Record<string, unknown>;
  const catalogVersion =
    typeof root.catalogVersion === 'string' ? root.catalogVersion.trim() : '';
  const dateReleased =
    typeof root.dateReleased === 'string' ? root.dateReleased.trim() : '';
  const title =
    typeof root.title === 'string'
      ? root.title.trim()
      : 'CISA Known Exploited Vulnerabilities Catalog';
  const declaredCount =
    typeof root.count === 'number' ? root.count : 0;

  if (!catalogVersion || !dateReleased || !Array.isArray(root.vulnerabilities)) {
    return {
      valid: false,
      error:
        'Invalid CISA KEV schema: Missing required catalogVersion, dateReleased, or vulnerabilities array.',
      title,
      catalogVersion,
      dateReleased,
      declaredCount,
      totalParsed: 0,
      uniqueCount: 0,
      duplicatesCollapsed: 0,
      invalidSkipped: 0,
      records: [],
      provenance,
    };
  }

  provenance.upstreamVersion = catalogVersion;
  provenance.upstreamReleaseDate = dateReleased;

  const dedupMap = new Map<string, ParsedKevRecord>();
  let duplicatesCollapsed = 0;
  let invalidSkipped = 0;

  for (const item of root.vulnerabilities) {
    if (typeof item !== 'object' || item === null) {
      invalidSkipped++;
      continue;
    }
    const v = item as Record<string, unknown>;
    const rawCve = typeof v.cveID === 'string' ? v.cveID.trim().toUpperCase() : '';
    if (!CVE_ID_REGEX.test(rawCve)) {
      invalidSkipped++;
      continue;
    }

    const vendorProject =
      typeof v.vendorProject === 'string' && v.vendorProject.trim()
        ? v.vendorProject.trim().slice(0, 140)
        : 'Unspecified Vendor';
    const product =
      typeof v.product === 'string' && v.product.trim()
        ? v.product.trim().slice(0, 140)
        : 'Unspecified Product';
    const vulnerabilityName =
      typeof v.vulnerabilityName === 'string' && v.vulnerabilityName.trim()
        ? v.vulnerabilityName.trim().slice(0, 240)
        : `${vendorProject} ${product} Vulnerability`;
    const dateAdded =
      typeof v.dateAdded === 'string' && v.dateAdded.trim()
        ? v.dateAdded.trim().slice(0, 40)
        : 'Unknown';
    const shortDescription =
      typeof v.shortDescription === 'string' && v.shortDescription.trim()
        ? v.shortDescription.trim().slice(0, 2000)
        : 'No description provided in upstream catalog.';
    const requiredAction =
      typeof v.requiredAction === 'string' && v.requiredAction.trim()
        ? v.requiredAction.trim().slice(0, 1000)
        : 'Apply updates per vendor instructions.';
    const dueDate =
      typeof v.dueDate === 'string' && v.dueDate.trim()
        ? v.dueDate.trim().slice(0, 40)
        : 'Unknown';
    const ransomwareRaw =
      typeof v.knownRansomwareCampaignUse === 'string'
        ? v.knownRansomwareCampaignUse.trim()
        : 'Unknown';
    const knownRansomwareCampaignUse: 'Known' | 'Unknown' =
      ransomwareRaw.toLowerCase() === 'known' ? 'Known' : 'Unknown';
    const notes =
      typeof v.notes === 'string' ? v.notes.trim().slice(0, 1000) : '';
    const cwes = Array.isArray(v.cwes)
      ? v.cwes.filter((c): c is string => typeof c === 'string').slice(0, 10)
      : [];

    if (dedupMap.has(rawCve)) {
      duplicatesCollapsed++;
    }

    dedupMap.set(rawCve, {
      kevId: `KEV-${rawCve}`,
      cveId: rawCve,
      vendorProject,
      product,
      vulnerabilityName,
      dateAdded,
      shortDescription,
      requiredAction,
      dueDate,
      knownRansomwareCampaignUse,
      notes,
      cwes,
      catalogVersion,
      dateReleased,
      provenance,
    });
  }

  // Sort most recently added first
  const records = Array.from(dedupMap.values()).sort((a, b) =>
    b.dateAdded.localeCompare(a.dateAdded)
  );

  return {
    valid: true,
    title,
    catalogVersion,
    dateReleased,
    declaredCount,
    totalParsed: root.vulnerabilities.length,
    uniqueCount: records.length,
    duplicatesCollapsed,
    invalidSkipped,
    records,
    provenance,
  };
}

/**
 * Helper to extract CPE vendor/product and configuration criteria from NVD configurations
 */
function extractNvdConfigurations(configurations: unknown): {
  vendor: string;
  product: string;
  criteriaList: string[];
} {
  let vendor = 'Public Advisory / Multiple';
  let product = 'See Affected Configurations';
  const criteriaList: string[] = [];

  if (!Array.isArray(configurations)) {
    return { vendor, product, criteriaList };
  }

  for (const config of configurations) {
    if (typeof config !== 'object' || config === null) continue;
    const nodes = (config as Record<string, unknown>).nodes;
    if (!Array.isArray(nodes)) continue;

    for (const node of nodes) {
      if (typeof node !== 'object' || node === null) continue;
      const matches = (node as Record<string, unknown>).cpeMatch;
      if (!Array.isArray(matches)) continue;

      for (const m of matches) {
        if (typeof m !== 'object' || m === null) continue;
        const criteria = (m as Record<string, unknown>).criteria;
        if (typeof criteria === 'string' && criteria.startsWith('cpe:2.3:')) {
          if (criteriaList.length < 12) {
            criteriaList.push(criteria);
          }
          // cpe:2.3:a:vendor:product:version:...
          const parts = criteria.split(':');
          if (
            parts.length >= 5 &&
            vendor === 'Public Advisory / Multiple' &&
            parts[3] &&
            parts[4]
          ) {
            vendor = parts[3].replace(/_/g, ' ').slice(0, 120);
            product = parts[4].replace(/_/g, ' ').slice(0, 120);
          }
        }
      }
    }
  }

  return { vendor, product, criteriaList };
}

/**
 * 2. Validate & Parse NIST NVD API 2.0 CVE Response
 */
export function validateAndParseNvdResponse(
  payload: unknown,
  retrievedAt = new Date().toISOString()
): ParsedNvdResult {
  const provenance: DataProvenance = {
    connectorId: 'nist_nvd',
    sourceName: 'NIST National Vulnerability Database (NVD API 2.0)',
    sourceUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    retrievedAt,
  };

  if (typeof payload !== 'object' || payload === null) {
    return {
      valid: false,
      error: 'Invalid NVD API 2.0 response: Root payload must be a JSON object.',
      resultsPerPage: 0,
      startIndex: 0,
      totalResults: 0,
      format: '',
      version: '',
      timestamp: '',
      duplicatesCollapsed: 0,
      invalidSkipped: 0,
      records: [],
      provenance,
    };
  }

  const root = payload as Record<string, unknown>;
  if (!Array.isArray(root.vulnerabilities)) {
    return {
      valid: false,
      error: 'Invalid NVD API 2.0 schema: Missing required vulnerabilities array.',
      resultsPerPage: 0,
      startIndex: 0,
      totalResults: 0,
      format: '',
      version: '',
      timestamp: '',
      duplicatesCollapsed: 0,
      invalidSkipped: 0,
      records: [],
      provenance,
    };
  }

  const resultsPerPage =
    typeof root.resultsPerPage === 'number' ? root.resultsPerPage : root.vulnerabilities.length;
  const startIndex = typeof root.startIndex === 'number' ? root.startIndex : 0;
  const totalResults =
    typeof root.totalResults === 'number' ? root.totalResults : root.vulnerabilities.length;
  const format = typeof root.format === 'string' ? root.format : 'NVD_CVE';
  const version = typeof root.version === 'string' ? root.version : '2.0';
  const timestamp = typeof root.timestamp === 'string' ? root.timestamp : retrievedAt;

  provenance.upstreamVersion = `${format} v${version}`;
  provenance.upstreamReleaseDate = timestamp;

  const dedupMap = new Map<string, ParsedNvdCveRecord>();
  let duplicatesCollapsed = 0;
  let invalidSkipped = 0;

  for (const wrapper of root.vulnerabilities) {
    if (typeof wrapper !== 'object' || wrapper === null) {
      invalidSkipped++;
      continue;
    }
    const cveObj = (wrapper as Record<string, unknown>).cve;
    if (typeof cveObj !== 'object' || cveObj === null) {
      invalidSkipped++;
      continue;
    }
    const cve = cveObj as Record<string, unknown>;
    const rawId = typeof cve.id === 'string' ? cve.id.trim().toUpperCase() : '';
    if (!CVE_ID_REGEX.test(rawId)) {
      invalidSkipped++;
      continue;
    }

    // English description extraction
    let description = 'No English description provided in NVD record.';
    if (Array.isArray(cve.descriptions)) {
      const enDesc = cve.descriptions.find(
        (d): d is { lang: string; value: string } =>
          typeof d === 'object' &&
          d !== null &&
          (d as Record<string, unknown>).lang === 'en' &&
          typeof (d as Record<string, unknown>).value === 'string'
      );
      if (enDesc && enDesc.value.trim()) {
        description = enDesc.value.trim().slice(0, 4000);
      }
    }

    // CVSS Metric Extraction (prefer V3.1, then V4.0, then V3.0, then V2.0)
    let cvss: ParsedNvdCvss = {
      version: 'UNSCORED',
      baseScore: 0,
      baseSeverity: 'LOW',
      vectorString: 'N/A (Awaiting NVD CVSS Enrichment)',
      exploitabilityScore: null,
      impactScore: null,
    };

    if (typeof cve.metrics === 'object' && cve.metrics !== null) {
      const m = cve.metrics as Record<string, unknown>;
      const metricList =
        (Array.isArray(m.cvssMetricV31) && m.cvssMetricV31.length > 0 && m.cvssMetricV31) ||
        (Array.isArray(m.cvssMetricV40) && m.cvssMetricV40.length > 0 && m.cvssMetricV40) ||
        (Array.isArray(m.cvssMetricV30) && m.cvssMetricV30.length > 0 && m.cvssMetricV30) ||
        (Array.isArray(m.cvssMetricV2) && m.cvssMetricV2.length > 0 && m.cvssMetricV2) ||
        null;

      if (metricList) {
        const primary =
          metricList.find(
            (entry: unknown) =>
              typeof entry === 'object' &&
              entry !== null &&
              (entry as Record<string, unknown>).type === 'Primary'
          ) || metricList[0];

        if (typeof primary === 'object' && primary !== null) {
          const pObj = primary as Record<string, unknown>;
          const cvssData =
            typeof pObj.cvssData === 'object' && pObj.cvssData !== null
              ? (pObj.cvssData as Record<string, unknown>)
              : {};
          const score =
            typeof cvssData.baseScore === 'number' ? cvssData.baseScore : 0;
          const ver =
            typeof cvssData.version === 'string' ? cvssData.version : '3.1';
          const vec =
            typeof cvssData.vectorString === 'string'
              ? cvssData.vectorString.slice(0, 128)
              : 'CVSS:3.1/UNKNOWN';
          const rawSev =
            cvssData.baseSeverity || pObj.baseSeverity || 'LOW';

          cvss = {
            version: ver,
            baseScore: score,
            baseSeverity: normalizeSeverity(rawSev, score),
            vectorString: vec,
            exploitabilityScore:
              typeof pObj.exploitabilityScore === 'number'
                ? pObj.exploitabilityScore
                : null,
            impactScore:
              typeof pObj.impactScore === 'number' ? pObj.impactScore : null,
          };
        }
      }
    }

    // CWE Extraction
    const cwesSet = new Set<string>();
    if (Array.isArray(cve.weaknesses)) {
      for (const w of cve.weaknesses) {
        if (typeof w !== 'object' || w === null) continue;
        const descArr = (w as Record<string, unknown>).description;
        if (!Array.isArray(descArr)) continue;
        for (const d of descArr) {
          if (typeof d === 'object' && d !== null) {
            const val = (d as Record<string, unknown>).value;
            if (typeof val === 'string' && val.trim()) {
              cwesSet.add(val.trim());
            }
          }
        }
      }
    }

    // References Extraction
    const references: ParsedNvdReference[] = [];
    if (Array.isArray(cve.references)) {
      for (const ref of cve.references.slice(0, 10)) {
        if (typeof ref !== 'object' || ref === null) continue;
        const r = ref as Record<string, unknown>;
        if (typeof r.url === 'string' && r.url.trim()) {
          references.push({
            url: r.url.trim().slice(0, 512),
            source:
              typeof r.source === 'string' ? r.source.trim().slice(0, 120) : 'NVD Reference',
            tags: Array.isArray(r.tags)
              ? r.tags.filter((t): t is string => typeof t === 'string').slice(0, 6)
              : [],
          });
        }
      }
    }

    const { vendor, product, criteriaList } = extractNvdConfigurations(
      cve.configurations
    );

    const published =
      typeof cve.published === 'string' ? cve.published.slice(0, 64) : 'Unknown';
    const lastModified =
      typeof cve.lastModified === 'string'
        ? cve.lastModified.slice(0, 64)
        : published;
    const vulnStatus =
      typeof cve.vulnStatus === 'string' ? cve.vulnStatus : 'Published';

    if (dedupMap.has(rawId)) {
      duplicatesCollapsed++;
    }

    dedupMap.set(rawId, {
      cveId: rawId,
      title: `${rawId} (${vendor} — ${product})`.slice(0, 240),
      description,
      published,
      lastModified,
      vulnStatus,
      vendor,
      product,
      cvss,
      cwes: Array.from(cwesSet),
      references,
      affectedConfigurations: criteriaList,
      provenance,
    });
  }

  return {
    valid: true,
    resultsPerPage,
    startIndex,
    totalResults,
    format,
    version,
    timestamp,
    duplicatesCollapsed,
    invalidSkipped,
    records: Array.from(dedupMap.values()),
    provenance,
  };
}

/**
 * 3. Validate & Parse FIRST EPSS Public API Response
 */
export function validateAndParseEpssResponse(
  payload: unknown,
  retrievedAt = new Date().toISOString()
): ParsedEpssResult {
  const provenance: DataProvenance = {
    connectorId: 'first_epss',
    sourceName: 'FIRST Exploit Prediction Scoring System (EPSS)',
    sourceUrl: 'https://api.first.org/data/v1/epss',
    retrievedAt,
  };

  if (typeof payload !== 'object' || payload === null) {
    return {
      valid: false,
      error: 'Invalid FIRST EPSS response: Root payload must be a JSON object.',
      total: 0,
      records: [],
      provenance,
    };
  }

  const root = payload as Record<string, unknown>;
  if (!Array.isArray(root.data)) {
    return {
      valid: false,
      error: 'Invalid FIRST EPSS schema: Missing required data array.',
      total: 0,
      records: [],
      provenance,
    };
  }

  const version = typeof root.version === 'string' ? root.version : 'v1';
  provenance.upstreamVersion = version;

  const records: ParsedEpssRecord[] = [];
  for (const item of root.data) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    const rawCve =
      typeof row.cve === 'string' ? row.cve.trim().toUpperCase() : '';
    if (!CVE_ID_REGEX.test(rawCve)) continue;

    const epssNum = Number(row.epss);
    const pctNum = Number(row.percentile);
    if (Number.isNaN(epssNum) || epssNum < 0 || epssNum > 1) continue;

    const safePercentile =
      !Number.isNaN(pctNum) && pctNum >= 0 && pctNum <= 1 ? pctNum : 0;
    const modelDate =
      typeof row.date === 'string' ? row.date : retrievedAt.slice(0, 10);

    records.push({
      cveId: rawCve,
      epssScore: epssNum,
      epssPercentage: `${(Math.round(epssNum * 10000) / 100).toFixed(2)}%`,
      percentile: safePercentile,
      percentilePercentage: `${(Math.round(safePercentile * 1000) / 10).toFixed(1)}th`,
      modelDate,
      estimateDisclaimer:
        'Estimate of exploitation probability in the next 30 days (FIRST EPSS Statistical Model — Not a guarantee of safety or active exploitation).',
      provenance,
    });
  }

  return {
    valid: true,
    total: typeof root.total === 'number' ? root.total : records.length,
    records,
    provenance,
  };
}

/**
 * 4. Validate & Parse URLhaus Community API Response (Mandatory Defanging)
 */
export function validateAndParseUrlhausResponse(
  payload: unknown,
  retrievedAt = new Date().toISOString()
): ParsedUrlhausResult {
  const provenance: DataProvenance = {
    connectorId: 'urlhaus',
    sourceName: 'abuse.ch URLhaus Malware URL Feed',
    sourceUrl: 'https://urlhaus.abuse.ch/api/',
    retrievedAt,
  };

  if (typeof payload !== 'object' || payload === null) {
    return {
      valid: false,
      error: 'Invalid URLhaus response: Root payload must be a JSON object.',
      queryStatus: 'invalid_payload',
      duplicatesCollapsed: 0,
      records: [],
      provenance,
    };
  }

  const root = payload as Record<string, unknown>;
  const queryStatus =
    typeof root.query_status === 'string' ? root.query_status : 'unknown';

  if (!Array.isArray(root.urls)) {
    return {
      valid: false,
      error: `URLhaus response missing 'urls' array (query_status: ${queryStatus}).`,
      queryStatus,
      duplicatesCollapsed: 0,
      records: [],
      provenance,
    };
  }

  const dedupMap = new Map<string, ParsedUrlhausRecord>();
  let duplicatesCollapsed = 0;

  for (const u of root.urls) {
    if (typeof u !== 'object' || u === null) continue;
    const item = u as Record<string, unknown>;
    const rawId =
      typeof item.id === 'string' || typeof item.id === 'number'
        ? String(item.id).replace(/[^a-zA-Z0-9_\-]/g, '')
        : '';
    const rawUrl = typeof item.url === 'string' ? item.url.trim() : '';
    if (!rawId || !rawUrl) continue;

    const indicatorId = `urlhaus_${rawId}`.slice(0, 120);
    if (dedupMap.has(indicatorId)) {
      duplicatesCollapsed++;
    }

    const defangedUrl = defangUrlOrHost(rawUrl).slice(0, 512);
    const defangedHost =
      typeof item.host === 'string' && item.host.trim()
        ? defangUrlOrHost(item.host).slice(0, 255)
        : defangedUrl.slice(0, 120);

    dedupMap.set(indicatorId, {
      indicatorId,
      defangedUrl,
      defangedHost,
      urlStatus:
        typeof item.url_status === 'string' ? item.url_status : 'unknown',
      dateAdded:
        typeof item.date_added === 'string' ? item.date_added : retrievedAt,
      threat:
        typeof item.threat === 'string' && item.threat.trim()
          ? item.threat.trim().slice(0, 120)
          : 'malware_download',
      tags: Array.isArray(item.tags)
        ? item.tags.filter((t): t is string => typeof t === 'string').slice(0, 8)
        : [],
      urlhausReference:
        typeof item.urlhaus_reference === 'string'
          ? item.urlhaus_reference
          : 'https://urlhaus.abuse.ch/',
      reporter:
        typeof item.reporter === 'string' ? item.reporter : 'abuse.ch community',
      provenance,
    });
  }

  return {
    valid: true,
    queryStatus,
    duplicatesCollapsed,
    records: Array.from(dedupMap.values()),
    provenance,
  };
}

export interface ParsedFeodoTrackerRecord {
  indicatorId: string;
  rawIpAddress: string;
  defangedIpPort: string;
  defangedHostname: string;
  port: number;
  c2Status: 'online' | 'offline';
  malwareFamily: string;
  asNumber: number | null;
  asName: string;
  country: string;
  firstSeen: string;
  lastOnline: string;
  feodoReferenceUrl: string;
  provenance: DataProvenance;
}

export interface ParsedFeodoTrackerResult {
  valid: boolean;
  error?: string;
  totalParsed: number;
  uniqueCount: number;
  duplicatesCollapsed: number;
  invalidSkipped: number;
  onlineCount: number;
  records: ParsedFeodoTrackerRecord[];
  provenance: DataProvenance;
}

const IPV4_OR_IPV6_REGEX =
  /^(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})$/;

/**
 * 4B. Validate & Parse abuse.ch Feodo Tracker Botnet C2 IP Blocklist Official JSON
 * Official keyless endpoint: https://feodotracker.abuse.ch/downloads/ipblocklist.json
 * Governed by abuse.ch Feodo Tracker Blocklist Terms of Use (commercial & non-commercial defensive use permitted, 5m cache TTL).
 */
export function validateAndParseFeodoTrackerResponse(
  payload: unknown,
  retrievedAt = new Date().toISOString()
): ParsedFeodoTrackerResult {
  const provenance: DataProvenance = {
    connectorId: 'feodo_tracker',
    sourceName: 'abuse.ch Feodo Tracker Botnet C2 IP Blocklist',
    sourceUrl: 'https://feodotracker.abuse.ch/blocklist/',
    retrievedAt,
  };

  if (!Array.isArray(payload)) {
    return {
      valid: false,
      error:
        'Invalid Feodo Tracker response: Expected a JSON array of Botnet C2 IP blocklist entries.',
      totalParsed: 0,
      uniqueCount: 0,
      duplicatesCollapsed: 0,
      invalidSkipped: 0,
      onlineCount: 0,
      records: [],
      provenance,
    };
  }

  const dedupMap = new Map<string, ParsedFeodoTrackerRecord>();
  let duplicatesCollapsed = 0;
  let invalidSkipped = 0;

  for (const entry of payload) {
    if (typeof entry !== 'object' || entry === null) {
      invalidSkipped++;
      continue;
    }

    const row = entry as Record<string, unknown>;
    const rawIp =
      typeof row.ip_address === 'string' ? row.ip_address.trim() : '';
    const rawPort = Number(row.port);

    if (
      !rawIp ||
      !IPV4_OR_IPV6_REGEX.test(rawIp) ||
      Number.isNaN(rawPort) ||
      rawPort < 1 ||
      rawPort > 65535
    ) {
      invalidSkipped++;
      continue;
    }

    const sanitizedKeyIp = rawIp.replace(/[^a-zA-Z0-9_.\-:]/g, '_');
    const indicatorId = `feodo_${sanitizedKeyIp}_${rawPort}`.slice(0, 120);

    if (dedupMap.has(indicatorId)) {
      duplicatesCollapsed++;
    }

    const defangedIp = defangUrlOrHost(rawIp);
    const defangedIpPort = `${defangedIp}:${rawPort}`;
    const rawHostname =
      typeof row.hostname === 'string' && row.hostname.trim()
        ? row.hostname.trim()
        : '';
    const defangedHostname = rawHostname
      ? defangUrlOrHost(rawHostname).slice(0, 255)
      : 'Unknown';

    const rawStatus =
      typeof row.status === 'string' ? row.status.trim().toLowerCase() : '';
    const c2Status: 'online' | 'offline' =
      rawStatus === 'online' ? 'online' : 'offline';

    const malwareFamily =
      typeof row.malware === 'string' && row.malware.trim()
        ? row.malware.trim().slice(0, 80)
        : 'Unknown Botnet C2';

    const asNumber =
      typeof row.as_number === 'number' && !Number.isNaN(row.as_number)
        ? row.as_number
        : null;
    const asName =
      typeof row.as_name === 'string' && row.as_name.trim()
        ? row.as_name.trim().slice(0, 120)
        : 'Unknown ASN';
    const country =
      typeof row.country === 'string' && row.country.trim()
        ? row.country.trim().toUpperCase().slice(0, 8)
        : 'Unknown';

    const firstSeen =
      typeof row.first_seen === 'string' && row.first_seen.trim()
        ? row.first_seen.trim().replace(' ', 'T') +
          (row.first_seen.includes('Z') ? '' : 'Z')
        : retrievedAt;
    const lastOnline =
      typeof row.last_online === 'string' && row.last_online.trim()
        ? row.last_online.trim()
        : firstSeen.slice(0, 10);

    dedupMap.set(indicatorId, {
      indicatorId,
      rawIpAddress: rawIp,
      defangedIpPort,
      defangedHostname,
      port: rawPort,
      c2Status,
      malwareFamily,
      asNumber,
      asName,
      country,
      firstSeen,
      lastOnline,
      feodoReferenceUrl: `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(rawIp)}/`,
      provenance,
    });
  }

  const records = Array.from(dedupMap.values());
  const onlineCount = records.filter((r) => r.c2Status === 'online').length;

  return {
    valid: true,
    totalParsed: payload.length,
    uniqueCount: records.length,
    duplicatesCollapsed,
    invalidSkipped,
    onlineCount,
    records,
    provenance,
  };
}

/**
 * 5. Non-Destructive Upsert & Duplicate Detection Merger
 */
export function mergeNonDestructiveById<T>(
  existingRecords: T[],
  incomingRecords: T[],
  getKey: (item: T) => string
): {
  merged: T[];
  insertedCount: number;
  updatedCount: number;
} {
  if (!incomingRecords || incomingRecords.length === 0) {
    return {
      merged: existingRecords,
      insertedCount: 0,
      updatedCount: 0,
    };
  }

  const map = new Map<string, T>();
  for (const item of existingRecords) {
    map.set(getKey(item), item);
  }

  let insertedCount = 0;
  let updatedCount = 0;

  for (const inc of incomingRecords) {
    const key = getKey(inc);
    if (map.has(key)) {
      updatedCount++;
    } else {
      insertedCount++;
    }
    map.set(key, inc);
  }

  return {
    merged: Array.from(map.values()),
    insertedCount,
    updatedCount,
  };
}

/**
 * 6. Data Freshness & Staleness Evaluator
 */
export function evaluateDataFreshness(
  lastSuccessIso: string | null
): DataFreshnessInfo {
  if (!lastSuccessIso) {
    return {
      level: 'never',
      ageMinutes: null,
      labelEn: 'Not Yet Synced in Session',
      labelBn: 'এই সেশনে এখনো সিঙ্ক করা হয়নি',
      warningEn:
        'Feed has not been manually synchronized yet. Trigger a manual refresh to pull the latest public catalog.',
      warningBn:
        'ফিড এখনো ম্যানুয়ালি সিঙ্ক করা হয়নি। সর্বশেষ পাবলিক ডেটা পেতে ম্যানুয়াল রিফ্রেশ বাটনে ক্লিক করুন।',
    };
  }

  const parsedMs = Date.parse(lastSuccessIso);
  if (Number.isNaN(parsedMs)) {
    return {
      level: 'never',
      ageMinutes: null,
      labelEn: 'Unknown Timestamp',
      labelBn: 'অজানা সময়',
      warningEn: 'Timestamp format unrecognized.',
      warningBn: 'সময়ের ফরম্যাট শনাক্ত করা যায়নি।',
    };
  }

  const ageMinutes = Math.max(0, Math.round((Date.now() - parsedMs) / 60_000));

  if (ageMinutes <= 24 * 60) {
    return {
      level: 'fresh',
      ageMinutes,
      labelEn: `Fresh (${ageMinutes}m ago)`,
      labelBn: `তাজা (${ageMinutes} মিনিট আগে)`,
      warningEn: null,
      warningBn: null,
    };
  }

  if (ageMinutes <= 72 * 60) {
    const hours = Math.round(ageMinutes / 60);
    return {
      level: 'aging',
      ageMinutes,
      labelEn: `Aging (${hours}h old)`,
      labelBn: `পুরানো হচ্ছে (${hours} ঘণ্টা আগে)`,
      warningEn: `Data was synced ${hours} hours ago. Consider running a manual refresh before completing triage.`,
      warningBn: `ডেটা ${hours} ঘণ্টা আগে সিঙ্ক করা হয়েছে। বিশ্লেষণের আগে ম্যানুয়াল রিফ্রেশ করার পরামর্শ দেওয়া হচ্ছে।`,
    };
  }

  const days = Math.round(ageMinutes / (60 * 24));
  return {
    level: 'stale',
    ageMinutes,
    labelEn: `Stale (${days}d old)`,
    labelBn: `বাসি ডেটা (${days} দিন পুরানো)`,
    warningEn: `STALE DATA WARNING: Cached snapshot is ${days} days old. Newly disclosed CVEs or KEV additions may be missing.`,
    warningBn: `সতর্কতা: ক্যাশকৃত ডেটা ${days} দিনের পুরানো। সাম্প্রতিক প্রকাশিত ঝুঁকি অনুপস্থিত থাকতে পারে।`,
  };
}
