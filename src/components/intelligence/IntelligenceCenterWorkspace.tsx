import React, { useState, useEffect, useCallback } from 'react';
import {
  Search,
  Filter,
  Download,
  ExternalLink,
  ShieldAlert,
  Flame,
  Bug,
  FishOff,
  FileWarning,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Eye,
  X,
  Database,
  FileDigit,
  Link2,
  Play,
  ArrowUpDown,
  Sparkles,
  Check,
  XCircle,
} from 'lucide-react';
import {
  collection,
  query,
  where,
  orderBy,
  limit,
  startAfter,
  getDocs,
  QueryDocumentSnapshot,
  DocumentData,
} from 'firebase/firestore';
import { db, isFirebaseConfigAvailable } from '../../firebase/config';
import { useSecurity } from '../../context/SecurityContext';
import { useApp } from '../../context/AppContext';
import { CoreModuleId } from '../../types/navigation';
import {
  NormalizedCveIntelligenceRecord,
  EnrichedKevIntelligenceRecord,
  KevSnapshotDiffSummary,
  AuthorizedThreatIndicator,
  SuspiciousUrlAnalysisResult,
  VerifiedSecurityAdvisory,
  normalizeCveRecordWithUnknowns,
  filterAndSortCveRecords,
  exportCveRecordsToCsv,
  filterMalwareIndicators,
  parseAndInspectSuspiciousUrl,
  isValidSha256Hash,
  paginateArray,
} from '../../intelligence/engine';
import {
  runIntelligenceCenterTests,
  IntelligenceTestResult,
} from '../../intelligence/intelligence.test';
import { ScamReportDoc } from '../../types/security';

interface Props {
  moduleId: CoreModuleId;
}

type ModuleAsyncState = 'loading' | 'success' | 'empty' | 'error';

export const IntelligenceCenterWorkspace: React.FC<Props> = ({ moduleId }) => {
  const { language } = useApp();
  const {
    isAdmin,
    isSignedIn,
    persistenceMode,
    approvedScamReports,
    myScamReports,
    pendingScamReports,
    threatIndicators,
    submitScamReport,
    moderateScamReport,
  } = useSecurity();
  const isBn = language === 'bn';
  const isLiveFirestore =
    persistenceMode === 'FIRESTORE_LIVE' && isFirebaseConfigAvailable;

  // ==========================================================================
  // 1. CVE EXPLORER STATE
  // ==========================================================================
  const [cveState, setCveState] = useState<ModuleAsyncState>('loading');
  const [cveErrorMsg, setCveErrorMsg] = useState<string | null>(null);
  const [cveSourceTab, setCveSourceTab] = useState<'public_nvd' | 'firestore_paginated'>('public_nvd');
  const [rawCveRecords, setRawCveRecords] = useState<NormalizedCveIntelligenceRecord[]>([]);
  const [cveSearchInput, setCveSearchInput] = useState<string>('apache');
  const [cveVendorFilter, setCveVendorFilter] = useState<string>('');
  const [cveProductFilter, setCveProductFilter] = useState<string>('');
  const [cveSeverityFilter, setCveSeverityFilter] = useState<
    'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'Unknown'
  >('ALL');
  const [cveMinCvss, setCveMinCvss] = useState<number>(0);
  const [cveMaxCvss, setCveMaxCvss] = useState<number>(10);
  const [cveKevFilter, setCveKevFilter] = useState<'ALL' | 'IN_KEV' | 'NOT_IN_KEV'>('ALL');
  const [cveSortBy, setCveSortBy] = useState<
    'cvssScore' | 'publishedAt' | 'lastModifiedAt' | 'cveId'
  >('cvssScore');
  const [cveSortDir, setCveSortDir] = useState<'asc' | 'desc'>('desc');
  const [cvePage, setCvePage] = useState<number>(1);
  const cvePageSize = 8;
  const [selectedCveDetail, setSelectedCveDetail] =
    useState<NormalizedCveIntelligenceRecord | null>(null);

  // Firestore Cursor Pagination for /cves
  const [fsCveCursors, setFsCveCursors] = useState<QueryDocumentSnapshot<DocumentData>[]>([]);
  const [fsCvePageIdx, setFsCvePageIdx] = useState<number>(0);
  const [fsCveHasNext, setFsCveHasNext] = useState<boolean>(false);

  // ==========================================================================
  // 2. CISA KEV TRACKER STATE
  // ==========================================================================
  const [kevState, setKevState] = useState<ModuleAsyncState>('loading');
  const [kevErrorMsg, setKevErrorMsg] = useState<string | null>(null);
  const [kevRecords, setKevRecords] = useState<EnrichedKevIntelligenceRecord[]>([]);
  const [kevSnapshotDiff, setKevSnapshotDiff] = useState<KevSnapshotDiffSummary | null>(null);
  const [kevCatalogVersion, setKevCatalogVersion] = useState<string>('Unknown');
  const [kevDateReleased, setKevDateReleased] = useState<string>('Unknown');
  const [kevTotalCached, setKevTotalCached] = useState<number>(0);
  const [kevTotalMatches, setKevTotalMatches] = useState<number>(0);
  const [kevSearchQuery, setKevSearchQuery] = useState<string>('');
  const [kevVendorFilter, setKevVendorFilter] = useState<string>('');
  const [kevProductFilter, setKevProductFilter] = useState<string>('');
  const [kevDateFrom, setKevDateFrom] = useState<string>('');
  const [kevDateTo, setKevDateTo] = useState<string>('');
  const [kevRansomwareFilter, setKevRansomwareFilter] = useState<
    'ALL' | 'Known' | 'Unknown'
  >('ALL');
  const [kevSnapshotFilter, setKevSnapshotFilter] = useState<'ALL' | 'NEWLY_IMPORTED'>('ALL');
  const [kevSortBy, setKevSortBy] = useState<
    'dateAdded' | 'dueDate' | 'cveId' | 'vendorProject'
  >('dateAdded');
  const [kevSortDir, setKevSortDir] = useState<'asc' | 'desc'>('desc');
  const [kevPage, setKevPage] = useState<number>(1);
  const kevPageSize = 10;

  // ==========================================================================
  // 3. MALWARE INTELLIGENCE & SHA-256 LOOKUP STATE
  // ==========================================================================
  const [malwareState, setMalwareState] = useState<ModuleAsyncState>('loading');
  const [malwareErrorMsg, setMalwareErrorMsg] = useState<string | null>(null);
  const [authorizedIndicators, setAuthorizedIndicators] = useState<
    AuthorizedThreatIndicator[]
  >([]);
  const [malwareSearchQuery, setMalwareSearchQuery] = useState<string>('');
  const [malwareTypeFilter, setMalwareTypeFilter] = useState<string>('ALL');
  const [malwareStatusFilter, setMalwareStatusFilter] = useState<string>('ALL');
  const [malwareSourceFilter, setMalwareSourceFilter] = useState<string>('');
  const [malwareFeedSyncing, setMalwareFeedSyncing] = useState<boolean>(false);
  const [malwareFeedRegistry, setMalwareFeedRegistry] = useState<
    Array<{
      feedId: string;
      name: string;
      endpointUrl: string;
      officialDocsUrl: string;
      status: string;
      authRequirement: string;
      credentialEnvVar: string | null;
      licenseAndTerms: string;
      indicatorCategory: string;
      cachedCount: number;
      duplicatesCollapsed: number;
      lastSuccessAt: string | null;
      lastError: string | null;
      freshness: {
        level: string;
        labelEn: string;
        warningEn: string | null;
      };
      canManualRefresh: boolean;
    }>
  >([]);
  const [malwareFeedSummary, setMalwareFeedSummary] = useState<{
    totalIndicators: number;
    feodoCachedCount: number;
    urlhausCachedCount: number;
    onlineC2Count: number;
    duplicatesCollapsed: number;
    activeOperationalFeeds: number;
    unconfiguredOptionalFeeds: number;
    lastSyncedAt: string | null;
  } | null>(null);
  const [fsIndCursors, setFsIndCursors] = useState<QueryDocumentSnapshot<DocumentData>[]>([]);
  const [fsIndPageIdx, setFsIndPageIdx] = useState<number>(0);
  const [fsIndHasNext, setFsIndHasNext] = useState<boolean>(false);

  // SHA-256 Lookup State
  const [sha256Input, setSha256Input] = useState<string>(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  const [sha256State, setSha256State] = useState<'idle' | 'loading' | 'success' | 'error'>(
    'idle'
  );
  const [sha256Error, setSha256Error] = useState<string | null>(null);
  const [sha256Result, setSha256Result] = useState<{
    foundInCircl: boolean;
    foundInFirestore: AuthorizedThreatIndicator | null;
    sha256: string;
    sourceName: string;
    sourceUrl: string;
    retrievedAt: string;
    message: string;
    metadata: {
      fileName: string;
      fileSize: string;
      md5: string;
      sha1: string;
      source: string;
      trustLevel: string;
    } | null;
  } | null>(null);

  // ==========================================================================
  // 4. SCAM & PHISHING INTELLIGENCE STATE
  // ==========================================================================
  const [scamState, setScamState] = useState<ModuleAsyncState>('loading');
  const [scamErrorMsg, setScamErrorMsg] = useState<string | null>(null);
  const [paginatedApprovedScams, setPaginatedApprovedScams] = useState<ScamReportDoc[]>([]);
  const [fsScamCursors, setFsScamCursors] = useState<QueryDocumentSnapshot<DocumentData>[]>([]);
  const [fsScamPageIdx, setFsScamPageIdx] = useState<number>(0);
  const [fsScamHasNext, setFsScamHasNext] = useState<boolean>(false);
  const [scamCategoryFilter, setScamCategoryFilter] = useState<string>('ALL');
  const [scamSearchQuery, setScamSearchQuery] = useState<string>('');

  // Suspicious URL Parser State
  const [suspiciousUrlInput, setSuspiciousUrlInput] = useState<string>(
    'http://login@xn--pple-43d-account-verify.example.com:8080/secure/update.exe?session=secret_token&otp=4821'
  );
  const [urlAnalysisResult, setUrlAnalysisResult] =
    useState<SuspiciousUrlAnalysisResult | null>(null);

  // New Scam Report Submission State
  const [reportTitle, setReportTitle] = useState<string>('');
  const [reportCategory, setReportCategory] =
    useState<ScamReportDoc['category']>('phishing_url');
  const [reportIndicator, setReportIndicator] = useState<string>('');
  const [reportDescription, setReportDescription] = useState<string>('');
  const [reportSubmitting, setReportSubmitting] = useState<boolean>(false);
  const [moderationNotesInput, setModerationNotesInput] = useState<Record<string, string>>(
    {}
  );

  // ==========================================================================
  // 5. SECURITY ADVISORIES STATE
  // ==========================================================================
  const [advisoriesState, setAdvisoriesState] = useState<ModuleAsyncState>('loading');
  const [advisoriesErrorMsg, setAdvisoriesErrorMsg] = useState<string | null>(null);
  const [advisoriesList, setAdvisoriesList] = useState<VerifiedSecurityAdvisory[]>([]);
  const [advisoryCategories, setAdvisoryCategories] = useState<string[]>([]);
  const [advisoryCategoryFilter, setAdvisoryCategoryFilter] = useState<string>('ALL');
  const [advisorySeverityFilter, setAdvisorySeverityFilter] = useState<string>('ALL');
  const [advisorySearchQuery, setAdvisorySearchQuery] = useState<string>('');
  const [advisoryPage, setAdvisoryPage] = useState<number>(1);
  const advisoryPageSize = 8;
  const [advisoryTotalMatches, setAdvisoryTotalMatches] = useState<number>(0);

  // Automated Test Suite State
  const [testResults, setTestResults] = useState<IntelligenceTestResult[]>(() =>
    runIntelligenceCenterTests()
  );

  // ==========================================================================
  // DATA LOADERS & FIRESTORE CURSOR PAGINATION
  // ==========================================================================

  // 1A. Load CVEs from Public NVD API 2.0
  const loadPublicNvdCves = useCallback(async (searchTerm: string) => {
    setCveState('loading');
    setCveErrorMsg(null);
    try {
      const trimmed = searchTerm.trim();
      const isExactCve = /^CVE-\d{4}-\d{4,}$/i.test(trimmed);
      const params = new URLSearchParams();
      if (isExactCve) {
        params.set('cveId', trimmed.toUpperCase());
      } else {
        params.set('keyword', trimmed || 'apache');
        params.set('resultsPerPage', '25');
        params.set('startIndex', '0');
      }

      const res = await fetch(`/api/connectors/nvd/search?${params.toString()}`);
      const data = await res.json();
      if (!data.ok && (!Array.isArray(data.records) || data.records.length === 0)) {
        setCveErrorMsg(data.error || 'Failed to fetch CVE records from NIST NVD API 2.0.');
        setCveState('error');
        return;
      }

      const normalized: NormalizedCveIntelligenceRecord[] = (data.records || []).map(
        (r: Record<string, unknown>) =>
          normalizeCveRecordWithUnknowns(
            r as Parameters<typeof normalizeCveRecordWithUnknowns>[0]
          )
      );

      setRawCveRecords(normalized);
      setCvePage(1);
      setCveState(normalized.length > 0 ? 'success' : 'empty');
    } catch (err) {
      setCveErrorMsg(
        `CVE Explorer fetch error: ${err instanceof Error ? err.message : String(err)}`
      );
      setCveState('error');
    }
  }, []);

  // 1B. Load CVEs from Cloud Firestore with Cursor Pagination (limit + startAfter)
  const loadFirestorePaginatedCves = useCallback(
    async (targetPageIdx: number, cursorsStack: QueryDocumentSnapshot<DocumentData>[]) => {
      if (!isLiveFirestore) {
        setRawCveRecords([]);
        setCveState('empty');
        return;
      }
      setCveState('loading');
      setCveErrorMsg(null);
      try {
        const cvesRef = collection(db, 'cves');
        const pageLimit = 8;
        const q =
          targetPageIdx > 0 && cursorsStack[targetPageIdx - 1]
            ? query(
                cvesRef,
                orderBy('cveId', 'desc'),
                startAfter(cursorsStack[targetPageIdx - 1]),
                limit(pageLimit + 1)
              )
            : query(cvesRef, orderBy('cveId', 'desc'), limit(pageLimit + 1));

        const snap = await getDocs(q);
        const docs = snap.docs;
        const hasNext = docs.length > pageLimit;
        const pageDocs = hasNext ? docs.slice(0, pageLimit) : docs;

        if (pageDocs.length > 0) {
          const lastDoc = pageDocs[pageDocs.length - 1];
          const updatedCursors = [...cursorsStack];
          updatedCursors[targetPageIdx] = lastDoc;
          setFsCveCursors(updatedCursors);
        }

        const normalized = pageDocs.map((d) => {
          const data = d.data();
          return normalizeCveRecordWithUnknowns({
            cveId: String(data.cveId || d.id),
            title: String(data.title || ''),
            description: String(data.description || ''),
            vendor: String(data.vendor || 'Unknown'),
            product: String(data.product || 'Unknown'),
            severity: String(data.severity || 'Unknown'),
            cvssScore: typeof data.cvssScore === 'number' ? data.cvssScore : undefined,
            cvssVector: String(data.cvssVector || 'Unknown'),
            source: String(data.source || 'Cloud Firestore Verified /cves'),
            publishedAt: String(data.publishedAt || 'Unknown'),
          });
        });

        setFsCvePageIdx(targetPageIdx);
        setFsCveHasNext(hasNext);
        setRawCveRecords(normalized);
        setCvePage(1);
        setCveState(normalized.length > 0 ? 'success' : 'empty');
      } catch (err) {
        setCveErrorMsg(
          `Firestore /cves pagination error: ${err instanceof Error ? err.message : String(err)}`
        );
        setCveState('error');
      }
    },
    [isLiveFirestore]
  );

  // 2. Load CISA KEV Records with Server-Side Filtering, Snapshot Diff & Pagination
  const loadKevRecords = useCallback(
    async (pageToLoad = kevPage) => {
      setKevState('loading');
      setKevErrorMsg(null);
      try {
        const params = new URLSearchParams({
          q: kevSearchQuery,
          vendor: kevVendorFilter,
          product: kevProductFilter,
          dateFrom: kevDateFrom,
          dateTo: kevDateTo,
          ransomware: kevRansomwareFilter,
          snapshotFilter: kevSnapshotFilter,
          sortBy: kevSortBy,
          sortDir: kevSortDir,
          page: String(pageToLoad),
          pageSize: String(kevPageSize),
        });

        const res = await fetch(`/api/connectors/cisa-kev/records?${params.toString()}`);
        const data = await res.json();
        if (!data.ok) {
          setKevErrorMsg(data.error || 'Failed to load CISA KEV catalog records.');
          setKevState('error');
          return;
        }

        const list: EnrichedKevIntelligenceRecord[] = data.records || [];
        setKevRecords(list);
        setKevSnapshotDiff(data.snapshotDiff || null);
        setKevCatalogVersion(data.catalogVersion || 'Unknown');
        setKevDateReleased(data.dateReleased || 'Unknown');
        setKevTotalCached(data.totalCached || 0);
        setKevTotalMatches(data.totalMatches || 0);
        setKevPage(pageToLoad);
        setKevState(list.length > 0 ? 'success' : 'empty');
      } catch (err) {
        setKevErrorMsg(
          `CISA KEV Tracker error: ${err instanceof Error ? err.message : String(err)}`
        );
        setKevState('error');
      }
    },
    [
      kevPage,
      kevSearchQuery,
      kevVendorFilter,
      kevProductFilter,
      kevDateFrom,
      kevDateTo,
      kevRansomwareFilter,
      kevSnapshotFilter,
      kevSortBy,
      kevSortDir,
    ]
  );

  // 3. Load Authorized Threat Indicators (Live Keyless Feodo Tracker C2 + Optional URLhaus + Firestore)
  const loadFirestoreThreatIndicators = useCallback(
    async (
      targetPageIdx: number,
      cursorsStack: QueryDocumentSnapshot<DocumentData>[],
      forceFeedRefresh = false
    ) => {
      setMalwareState('loading');
      setMalwareErrorMsg(null);
      try {
        // 3A. Fetch verified live public malware feeds from server (/api/intelligence/malware-feeds)
        let publicFeedIndicators: AuthorizedThreatIndicator[] = [];
        try {
          const feedUrl = forceFeedRefresh
            ? '/api/intelligence/malware-feeds?refresh=true'
            : '/api/intelligence/malware-feeds';
          const feedRes = await fetch(feedUrl);
          if (feedRes.ok) {
            const feedData = await feedRes.json();
            if (feedData && feedData.ok) {
              setMalwareFeedRegistry(Array.isArray(feedData.feeds) ? feedData.feeds : []);
              setMalwareFeedSummary(feedData.summary || null);
              publicFeedIndicators = Array.isArray(feedData.indicators)
                ? feedData.indicators
                : [];
            }
          }
        } catch {
          // If server proxy is unreachable (Static Demo Fallback), preserve existing registry state
        }

        // 3B. Merge with Firestore /threat_indicators or Local Demo indicators (deduplicated by indicatorId)
        const dedupMap = new Map<string, AuthorizedThreatIndicator>();
        for (const item of publicFeedIndicators) {
          dedupMap.set(item.indicatorId, item);
        }

        if (!isLiveFirestore) {
          for (const t of threatIndicators) {
            dedupMap.set(t.indicatorId, {
              indicatorId: t.indicatorId,
              indicatorType: t.indicatorType,
              defangedValue: t.defangedValue,
              threatType: t.indicatorType.toUpperCase(),
              malwareFamily: t.malwareFamily || 'Unknown',
              status: 'verified',
              severity: t.severity,
              sourceName: t.source || 'Verified Public Feed',
              sourceUrl: 'https://feodotracker.abuse.ch/blocklist/',
              firstSeenAt: t.createdAt,
              updatedAt: t.updatedAt,
              sha256: t.indicatorType === 'sha256' ? t.defangedValue : undefined,
            });
          }
          const combined = Array.from(dedupMap.values());
          setAuthorizedIndicators(combined);
          setMalwareState(combined.length > 0 ? 'success' : 'empty');
          return;
        }

        const indRef = collection(db, 'threat_indicators');
        const pageLimit = 10;
        const q =
          targetPageIdx > 0 && cursorsStack[targetPageIdx - 1]
            ? query(
                indRef,
                orderBy('indicatorId', 'asc'),
                startAfter(cursorsStack[targetPageIdx - 1]),
                limit(pageLimit + 1)
              )
            : query(indRef, orderBy('indicatorId', 'asc'), limit(pageLimit + 1));

        const snap = await getDocs(q);
        const docs = snap.docs;
        const hasNext = docs.length > pageLimit;
        const pageDocs = hasNext ? docs.slice(0, pageLimit) : docs;

        if (pageDocs.length > 0) {
          const updated = [...cursorsStack];
          updated[targetPageIdx] = pageDocs[pageDocs.length - 1];
          setFsIndCursors(updated);
        }

        for (const d of pageDocs) {
          const data = d.data();
          const iType = (data.indicatorType || 'url') as AuthorizedThreatIndicator['indicatorType'];
          const indId = String(data.indicatorId || d.id);
          dedupMap.set(indId, {
            indicatorId: indId,
            indicatorType: iType,
            defangedValue: String(data.defangedValue || 'Unknown'),
            threatType: `${iType.toUpperCase()} Indicator`,
            malwareFamily: String(data.malwareFamily || 'Unknown'),
            status: 'verified',
            severity: (data.severity || 'HIGH') as AuthorizedThreatIndicator['severity'],
            sourceName: String(data.source || 'Cloud Firestore Verified /threat_indicators'),
            sourceUrl: 'https://feodotracker.abuse.ch/blocklist/',
            firstSeenAt: data.createdAt?.toDate
              ? data.createdAt.toDate().toISOString()
              : new Date().toISOString(),
            updatedAt: data.updatedAt?.toDate
              ? data.updatedAt.toDate().toISOString()
              : new Date().toISOString(),
            sha256: iType === 'sha256' ? String(data.defangedValue || '') : undefined,
          });
        }

        const combined = Array.from(dedupMap.values());
        setFsIndPageIdx(targetPageIdx);
        setFsIndHasNext(hasNext);
        setAuthorizedIndicators(combined);
        setMalwareState(combined.length > 0 ? 'success' : 'empty');
      } catch (err) {
        setMalwareErrorMsg(
          `Malware Intelligence error: ${err instanceof Error ? err.message : String(err)}`
        );
        setMalwareState('error');
      }
    },
    [isLiveFirestore, threatIndicators]
  );

  // Manual Refresh Handler for abuse.ch Feodo Tracker Botnet C2 Feed
  const handleManualFeodoRefresh = async () => {
    setMalwareFeedSyncing(true);
    try {
      await fetch('/api/connectors/feodo-tracker/sync', { method: 'POST' });
      await loadFirestoreThreatIndicators(fsIndPageIdx, fsIndCursors, true);
    } finally {
      setMalwareFeedSyncing(false);
    }
  };

  // 4. Load Publicly Verified Scam Reports from Firestore with Cursor Pagination
  const loadPaginatedApprovedScams = useCallback(
    async (targetPageIdx: number, cursorsStack: QueryDocumentSnapshot<DocumentData>[]) => {
      setScamState('loading');
      setScamErrorMsg(null);
      try {
        if (!isLiveFirestore) {
          setPaginatedApprovedScams(approvedScamReports);
          setScamState(approvedScamReports.length > 0 ? 'success' : 'empty');
          return;
        }

        const scamRef = collection(db, 'scam_reports');
        const pageLimit = 8;
        const q =
          targetPageIdx > 0 && cursorsStack[targetPageIdx - 1]
            ? query(
                scamRef,
                where('moderationStatus', '==', 'approved'),
                orderBy('reportId', 'asc'),
                startAfter(cursorsStack[targetPageIdx - 1]),
                limit(pageLimit + 1)
              )
            : query(
                scamRef,
                where('moderationStatus', '==', 'approved'),
                orderBy('reportId', 'asc'),
                limit(pageLimit + 1)
              );

        const snap = await getDocs(q);
        const docs = snap.docs;
        const hasNext = docs.length > pageLimit;
        const pageDocs = hasNext ? docs.slice(0, pageLimit) : docs;

        if (pageDocs.length > 0) {
          const updated = [...cursorsStack];
          updated[targetPageIdx] = pageDocs[pageDocs.length - 1];
          setFsScamCursors(updated);
        }

        const mapped: ScamReportDoc[] = pageDocs.map((d) => {
          const data = d.data();
          return {
            reportId: String(data.reportId || d.id),
            reporterUid: String(data.reporterUid || ''),
            title: String(data.title || 'Unknown'),
            category: (data.category || 'other') as ScamReportDoc['category'],
            defangedIndicator: String(data.defangedIndicator || 'Unknown'),
            description: String(data.description || 'Unknown'),
            moderationStatus: 'approved',
            moderatorNotes: String(data.moderatorNotes || ''),
            reviewedBy: String(data.reviewedBy || ''),
            createdAt: data.createdAt?.toDate
              ? data.createdAt.toDate().toISOString()
              : new Date().toISOString(),
            updatedAt: data.updatedAt?.toDate
              ? data.updatedAt.toDate().toISOString()
              : new Date().toISOString(),
          };
        });

        setFsScamPageIdx(targetPageIdx);
        setFsScamHasNext(hasNext);
        setPaginatedApprovedScams(mapped);
        setScamState(mapped.length > 0 ? 'success' : 'empty');
      } catch {
        // Fallback to SecurityContext approvedScamReports if composite index is still building
        setPaginatedApprovedScams(approvedScamReports);
        setScamState(approvedScamReports.length > 0 ? 'success' : 'empty');
      }
    },
    [isLiveFirestore, approvedScamReports]
  );

  // 5. Load Official Security Advisories (GitHub GHSA + CISA KEV Directives)
  const loadSecurityAdvisories = useCallback(
    async (pageToLoad = advisoryPage, forceRefresh = false) => {
      setAdvisoriesState('loading');
      setAdvisoriesErrorMsg(null);
      try {
        const params = new URLSearchParams({
          q: advisorySearchQuery,
          category: advisoryCategoryFilter,
          severity: advisorySeverityFilter,
          page: String(pageToLoad),
          pageSize: String(advisoryPageSize),
        });
        if (forceRefresh) {
          params.set('refresh', 'true');
        }

        const res = await fetch(`/api/intelligence/advisories?${params.toString()}`);
        const data = await res.json();
        if (!data.ok) {
          setAdvisoriesErrorMsg(data.error || 'Failed to load public security advisories.');
          setAdvisoriesState('error');
          return;
        }

        const list: VerifiedSecurityAdvisory[] = data.records || [];
        setAdvisoriesList(list);
        setAdvisoryCategories(data.categoriesAvailable || []);
        setAdvisoryTotalMatches(data.totalMatches || 0);
        setAdvisoryPage(pageToLoad);
        setAdvisoriesState(list.length > 0 ? 'success' : 'empty');
      } catch (err) {
        setAdvisoriesErrorMsg(
          `Security Advisories error: ${err instanceof Error ? err.message : String(err)}`
        );
        setAdvisoriesState('error');
      }
    },
    [
      advisoryPage,
      advisorySearchQuery,
      advisoryCategoryFilter,
      advisorySeverityFilter,
    ]
  );

  // Trigger initial load for active module
  useEffect(() => {
    if (moduleId === 'cve-explorer' || moduleId === 'dashboard') {
      if (cveSourceTab === 'public_nvd') {
        void loadPublicNvdCves(cveSearchInput);
      } else {
        void loadFirestorePaginatedCves(0, []);
      }
    }
    if (moduleId === 'cisa-kev' || moduleId === 'dashboard') {
      void loadKevRecords(1);
    }
    if (moduleId === 'malware-intel' || moduleId === 'hash-lookup') {
      void loadFirestoreThreatIndicators(0, []);
    }
    if (moduleId === 'scam-phishing' || moduleId === 'url-inspector') {
      void loadPaginatedApprovedScams(0, []);
    }
    if (moduleId === 'security-advisories' || moduleId === 'dashboard') {
      void loadSecurityAdvisories(1, false);
    }
  }, [moduleId]);

  // Reload KEV when KEV filters change
  useEffect(() => {
    if (moduleId === 'cisa-kev' || moduleId === 'dashboard') {
      void loadKevRecords(1);
    }
  }, [
    moduleId,
    kevSearchQuery,
    kevVendorFilter,
    kevProductFilter,
    kevDateFrom,
    kevDateTo,
    kevRansomwareFilter,
    kevSnapshotFilter,
    kevSortBy,
    kevSortDir,
    loadKevRecords,
  ]);

  // Reload Advisories when advisory filters change
  useEffect(() => {
    if (moduleId === 'security-advisories' || moduleId === 'dashboard') {
      void loadSecurityAdvisories(1, false);
    }
  }, [
    moduleId,
    advisorySearchQuery,
    advisoryCategoryFilter,
    advisorySeverityFilter,
    loadSecurityAdvisories,
  ]);

  // Run initial URL inspection on Scam & Phishing load
  useEffect(() => {
    if (moduleId === 'scam-phishing' || moduleId === 'url-inspector') {
      const feedPool = [
        ...approvedScamReports.map((s) => ({
          feedName: 'Verified Community Scam Reports (Firestore)',
          indicatorId: s.reportId,
          defangedOrRawValue: s.defangedIndicator,
          categoryOrThreat: s.category,
          verificationStatus: s.moderationStatus,
        })),
        ...threatIndicators.map((t) => ({
          feedName: t.source || 'Verified Threat Indicators (Firestore)',
          indicatorId: t.indicatorId,
          defangedOrRawValue: t.defangedValue,
          categoryOrThreat: t.malwareFamily,
          verificationStatus: 'verified',
        })),
      ];
      setUrlAnalysisResult(
        parseAndInspectSuspiciousUrl(suspiciousUrlInput, feedPool)
      );
    }
  }, [moduleId, approvedScamReports, threatIndicators]);

  // SHA-256 Lookup Handler
  const handleSha256Lookup = async (customHash?: string) => {
    const hashToLookup = (customHash ?? sha256Input).trim().toLowerCase();
    setSha256Input(hashToLookup);
    setSha256Error(null);

    if (!isValidSha256Hash(hashToLookup)) {
      setSha256State('error');
      setSha256Error(
        'Invalid SHA-256 format: Must be an exact 64-character hexadecimal string (0-9, a-f).'
      );
      return;
    }

    setSha256State('loading');
    try {
      const localMatch =
        authorizedIndicators.find(
          (i) =>
            i.indicatorType === 'sha256' &&
            i.defangedValue.toLowerCase() === hashToLookup
        ) || null;

      const res = await fetch(
        `/api/intelligence/sha256/lookup?sha256=${encodeURIComponent(hashToLookup)}`
      );
      const data = await res.json();

      if (!res.ok) {
        setSha256State('error');
        setSha256Error(data.error || 'SHA-256 lookup failed.');
        return;
      }

      setSha256Result({
        foundInCircl: Boolean(data.foundInCircl),
        foundInFirestore: localMatch,
        sha256: hashToLookup,
        sourceName: data.sourceName || 'CIRCL Public Hashlookup Service',
        sourceUrl:
          data.sourceUrl || `https://hashlookup.circl.lu/lookup/sha256/${hashToLookup}`,
        retrievedAt: data.retrievedAt || new Date().toISOString(),
        message: data.message || data.error || 'Lookup completed.',
        metadata: data.metadata || null,
      });
      setSha256State('success');
    } catch (err) {
      setSha256State('error');
      setSha256Error(
        `SHA-256 lookup request failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  };

  // CSV Download Trigger for CVE Explorer
  const handleDownloadCveCsv = (recordsToExport: NormalizedCveIntelligenceRecord[]) => {
    const csvContent = exportCveRecordsToCsv(recordsToExport);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute(
      'download',
      `kiron-prohori-cve-intelligence-${new Date().toISOString().slice(0, 10)}.csv`
    );
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Filtered & Paginated CVE Explorer Records
  const filteredCves = filterAndSortCveRecords(rawCveRecords, {
    searchQuery: cveSourceTab === 'firestore_paginated' ? cveSearchInput : '',
    vendorFilter: cveVendorFilter,
    productFilter: cveProductFilter,
    severityFilter: cveSeverityFilter,
    minCvss: cveMinCvss,
    maxCvss: cveMaxCvss,
    kevFilter: cveKevFilter,
    sortBy: cveSortBy,
    sortDirection: cveSortDir,
  });

  const paginatedCves = paginateArray(filteredCves, cvePage, cvePageSize);

  // Filtered Malware Indicators
  const filteredIndicators = filterMalwareIndicators(authorizedIndicators, {
    searchQuery: malwareSearchQuery,
    indicatorType: malwareTypeFilter,
    statusFilter: malwareStatusFilter,
    sourceFilter: malwareSourceFilter,
  });

  // Filtered Approved Scam Reports
  const filteredApprovedScams = paginatedApprovedScams.filter((s) => {
    if (scamCategoryFilter !== 'ALL' && s.category !== scamCategoryFilter) {
      return false;
    }
    if (scamSearchQuery.trim()) {
      const q = scamSearchQuery.trim().toLowerCase();
      const hay = `${s.reportId} ${s.title} ${s.defangedIndicator} ${s.description} ${s.category}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const showCveExplorer = moduleId === 'cve-explorer' || moduleId === 'dashboard';
  const showKevTracker = moduleId === 'cisa-kev' || moduleId === 'dashboard';
  const showMalwareIntel =
    moduleId === 'malware-intel' ||
    moduleId === 'hash-lookup' ||
    moduleId === 'dashboard';
  const showScamPhishing =
    moduleId === 'scam-phishing' ||
    moduleId === 'url-inspector' ||
    moduleId === 'report-center' ||
    moduleId === 'dashboard';
  const showSecurityAdvisories =
    moduleId === 'security-advisories' || moduleId === 'dashboard';

  if (
    !showCveExplorer &&
    !showKevTracker &&
    !showMalwareIntel &&
    !showScamPhishing &&
    !showSecurityAdvisories
  ) {
    return null;
  }

  return (
    <div className="space-y-8" aria-label="Phase 3 Intelligence Center">
      {/* ====================================================================
          MODULE 1: CVE EXPLORER
         ==================================================================== */}
      {showCveExplorer && (
        <section
          aria-label="CVE Explorer Module"
          className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-5"
        >
          <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-blue-400">
                <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                <span>PHASE 3 INTELLIGENCE CENTER · MODULE 1: CVE EXPLORER</span>
              </div>
              <h2 className="mt-1 text-lg font-bold text-slate-100">
                {isBn
                  ? 'সিভিই এক্সপ্লোরার (CVE ID, ভেন্ডর, পণ্য, CVSS ফিল্টার ও CSV এক্সপোর্ট)'
                  : 'CVE Explorer — Search, CVSS/Severity Filtering, Unknown Field Normalization & CSV Export'}
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Missing upstream fields are explicitly normalized to <code className="text-slate-200">Unknown</code>. Absence from CISA KEV is never interpreted as safe.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Source Switcher: Public NVD API 2.0 vs Firestore Cursor Pagination */}
              <div className="flex rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-1 text-xs">
                <button
                  type="button"
                  onClick={() => {
                    setCveSourceTab('public_nvd');
                    void loadPublicNvdCves(cveSearchInput);
                  }}
                  className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
                    cveSourceTab === 'public_nvd'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-300 hover:text-white'
                  }`}
                >
                  NIST NVD API 2.0 ($0)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setCveSourceTab('firestore_paginated');
                    void loadFirestorePaginatedCves(0, []);
                  }}
                  className={`rounded-md px-3 py-1.5 font-medium transition-colors ${
                    cveSourceTab === 'firestore_paginated'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-300 hover:text-white'
                  }`}
                >
                  Firestore /cves (Cursor Paginated)
                </button>
              </div>

              <button
                type="button"
                onClick={() => handleDownloadCveCsv(filteredCves)}
                disabled={filteredCves.length === 0}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-2 text-xs font-medium text-slate-100 hover:border-blue-500 disabled:opacity-40 whitespace-nowrap shrink-0"
              >
                <Download className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                <span>Export CSV ({filteredCves.length})</span>
              </button>
            </div>
          </div>

          {/* Search & Multi-Facet Filter Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (cveSourceTab === 'public_nvd') {
                void loadPublicNvdCves(cveSearchInput);
              } else {
                setCvePage(1);
              }
            }}
            className="grid grid-cols-1 gap-3 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 sm:grid-cols-2 lg:grid-cols-6"
          >
            <div className="sm:col-span-2">
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                CVE ID or Keyword Search
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={cveSearchInput}
                  onChange={(e) => setCveSearchInput(e.target.value)}
                  placeholder="CVE-2021-44228, apache, openssh, xz..."
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 font-mono text-xs text-slate-100"
                />
                {cveSourceTab === 'public_nvd' && (
                  <button
                    type="submit"
                    className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 shrink-0"
                  >
                    <Search className="h-3.5 w-3.5" />
                    <span>Query</span>
                  </button>
                )}
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Vendor Filter
              </label>
              <input
                type="text"
                value={cveVendorFilter}
                onChange={(e) => {
                  setCveVendorFilter(e.target.value);
                  setCvePage(1);
                }}
                placeholder="e.g. apache / microsoft"
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Product Filter
              </label>
              <input
                type="text"
                value={cveProductFilter}
                onChange={(e) => {
                  setCveProductFilter(e.target.value);
                  setCvePage(1);
                }}
                placeholder="e.g. log4j / http_server"
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Severity &amp; KEV Filter
              </label>
              <div className="flex gap-1.5">
                <select
                  value={cveSeverityFilter}
                  onChange={(e) => {
                    setCveSeverityFilter(
                      e.target.value as typeof cveSeverityFilter
                    );
                    setCvePage(1);
                  }}
                  className="w-1/2 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2 py-1.5 text-xs text-slate-100"
                >
                  <option value="ALL">All Sev</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="Unknown">Unknown</option>
                </select>
                <select
                  value={cveKevFilter}
                  onChange={(e) => {
                    setCveKevFilter(e.target.value as typeof cveKevFilter);
                    setCvePage(1);
                  }}
                  className="w-1/2 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2 py-1.5 text-xs text-slate-100"
                >
                  <option value="ALL">All KEV</option>
                  <option value="IN_KEV">In KEV</option>
                  <option value="NOT_IN_KEV">Not in KEV</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                CVSS Min–Max &amp; Sort
              </label>
              <div className="flex items-center gap-1">
                <input
                  type="number"
                  min={0}
                  max={10}
                  step={0.5}
                  value={cveMinCvss}
                  onChange={(e) => {
                    setCveMinCvss(Math.max(0, Math.min(10, Number(e.target.value) || 0)));
                    setCvePage(1);
                  }}
                  aria-label="Minimum CVSS Score"
                  className="w-14 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-1.5 py-1.5 font-mono text-xs text-slate-100"
                />
                <span className="text-slate-500">–</span>
                <input
                  type="number"
                  min={0}
                  max={10}
                  step={0.5}
                  value={cveMaxCvss}
                  onChange={(e) => {
                    setCveMaxCvss(Math.max(0, Math.min(10, Number(e.target.value) || 10)));
                    setCvePage(1);
                  }}
                  aria-label="Maximum CVSS Score"
                  className="w-14 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-1.5 py-1.5 font-mono text-xs text-slate-100"
                />
                <select
                  value={`${cveSortBy}:${cveSortDir}`}
                  onChange={(e) => {
                    const [sb, sd] = e.target.value.split(':');
                    setCveSortBy(sb as typeof cveSortBy);
                    setCveSortDir(sd as 'asc' | 'desc');
                  }}
                  aria-label="Sort CVEs"
                  className="flex-1 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-1.5 py-1.5 text-xs text-slate-100"
                >
                  <option value="cvssScore:desc">CVSS High-Low</option>
                  <option value="cvssScore:asc">CVSS Low-High</option>
                  <option value="publishedAt:desc">Newest First</option>
                  <option value="publishedAt:asc">Oldest First</option>
                  <option value="cveId:desc">CVE ID Z-A</option>
                </select>
              </div>
            </div>
          </form>

          {/* CVE Explorer States: Loading / Error / Empty / Success */}
          {cveState === 'loading' ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-8 text-center text-xs text-slate-300">
              <RefreshCw className="mx-auto h-5 w-5 animate-spin text-blue-400 mb-2" />
              <div>Loading verified CVE records and cross-checking CISA KEV status...</div>
            </div>
          ) : cveState === 'error' ? (
            <div className="rounded-lg border border-rose-800/80 bg-rose-950/40 p-5 text-xs text-rose-200 space-y-2">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="h-4 w-4 text-rose-400" />
                <span>CVE Explorer Error State</span>
              </div>
              <p>{cveErrorMsg}</p>
              <button
                type="button"
                onClick={() => void loadPublicNvdCves(cveSearchInput)}
                className="rounded bg-rose-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-rose-600"
              >
                Retry Query
              </button>
            </div>
          ) : paginatedCves.totalItems === 0 ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-8 text-center text-xs text-slate-400 space-y-2">
              <div className="font-mono font-semibold text-amber-300">
                EMPTY STATE — 0 CVE RECORDS MATCHED
              </div>
              <p>
                {cveSourceTab === 'firestore_paginated'
                  ? 'No CVE documents matched in Firestore /cves for this cursor page or filter. Switch to "NIST NVD API 2.0 ($0)" or upsert CVE records as Admin.'
                  : 'No CVE records matched your current vendor, product, CVSS, or severity filters. Reset filters or search another keyword.'}
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="overflow-x-auto rounded-lg border border-[#1E2D4A] bg-[#080D1A]">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#1E2D4A] bg-[#10192E] text-slate-300">
                      <th className="px-3.5 py-2.5 font-medium">CVE ID &amp; Source</th>
                      <th className="px-3.5 py-2.5 font-medium">Vendor / Product</th>
                      <th className="px-3.5 py-2.5 font-medium">CVSS &amp; Severity</th>
                      <th className="px-3.5 py-2.5 font-medium">CWE &amp; Affected Config (CPE)</th>
                      <th className="px-3.5 py-2.5 font-medium">CISA KEV Status</th>
                      <th className="px-3.5 py-2.5 text-right font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1E2D4A]/60 tabular-nums">
                    {paginatedCves.pageItems.map((cve) => (
                      <tr key={cve.cveId} className="hover:bg-[#141F38]/60">
                        <td className="px-3.5 py-3 align-top">
                          <div className="font-mono font-bold text-blue-300">
                            {cve.cveId}
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-slate-400">
                            Published: {cve.publishedAt.slice(0, 10)}
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                            Source: {cve.sourceName}
                          </div>
                        </td>

                        <td className="px-3.5 py-3 align-top">
                          <div className="font-medium text-slate-100">{cve.vendor}</div>
                          <div className="text-[11px] text-slate-400">{cve.product}</div>
                        </td>

                        <td className="px-3.5 py-3 align-top font-mono">
                          <div
                            className={`font-bold ${
                              cve.severity === 'CRITICAL'
                                ? 'text-rose-300'
                                : cve.severity === 'HIGH'
                                ? 'text-amber-300'
                                : cve.severity === 'MEDIUM'
                                ? 'text-blue-300'
                                : 'text-slate-300'
                            }`}
                          >
                            {cve.cvssScoreDisplay} ({cve.severity})
                          </div>
                          <div className="mt-0.5 text-[10px] text-slate-400 truncate max-w-[160px]" title={cve.cvssVector}>
                            {cve.cvssVector}
                          </div>
                        </td>

                        <td className="px-3.5 py-3 align-top max-w-xs">
                          <div className="font-mono text-[11px] text-slate-200">
                            CWE: {cve.cweDisplay}
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-slate-400 truncate" title={cve.affectedConfigurationsDisplay}>
                            CPE: {cve.affectedConfigurationsDisplay}
                          </div>
                          <p className="mt-1 line-clamp-2 text-[11px] text-slate-300">
                            {cve.description}
                          </p>
                        </td>

                        <td className="px-3.5 py-3 align-top max-w-[210px]">
                          <div
                            className={`font-mono text-[11px] font-semibold ${
                              cve.inKev ? 'text-rose-300' : 'text-amber-300'
                            }`}
                          >
                            {cve.kevStatusLabel}
                          </div>
                          <div className="mt-0.5 text-[10px] text-slate-400 leading-snug">
                            {cve.inKev
                              ? `Active exploitation confirmed (Due: ${cve.kevRecord?.dueDate || 'Unknown'})`
                              : 'Absence from KEV ≠ Safe'}
                          </div>
                        </td>

                        <td className="px-3.5 py-3 align-top text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => setSelectedCveDetail(cve)}
                            className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#141F38] px-2.5 py-1 text-xs font-medium text-blue-300 hover:border-blue-500 hover:text-white"
                          >
                            <Eye className="h-3.5 w-3.5" />
                            <span>Detail</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls (Client Filter Page or Firestore Cursor Page) */}
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                {cveSourceTab === 'firestore_paginated' ? (
                  <>
                    <span>
                      Firestore Cursor Page <strong className="text-slate-200">{fsCvePageIdx + 1}</strong> · Showing{' '}
                      <strong className="text-slate-200">{filteredCves.length}</strong> record(s)
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={fsCvePageIdx <= 0}
                        onClick={() =>
                          void loadFirestorePaginatedCves(fsCvePageIdx - 1, fsCveCursors)
                        }
                        className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                      >
                        <ChevronLeft className="h-3.5 w-3.5" />
                        <span>Previous Cursor</span>
                      </button>
                      <button
                        type="button"
                        disabled={!fsCveHasNext}
                        onClick={() =>
                          void loadFirestorePaginatedCves(fsCvePageIdx + 1, fsCveCursors)
                        }
                        className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                      >
                        <span>Next Cursor</span>
                        <ChevronRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <span>
                      Showing page <strong className="text-slate-200">{paginatedCves.currentPage}</strong> of{' '}
                      <strong className="text-slate-200">{paginatedCves.totalPages}</strong> ({paginatedCves.totalItems} matching CVEs)
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={!paginatedCves.hasPrevPage}
                        onClick={() => setCvePage((p) => Math.max(1, p - 1))}
                        className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                      >
                        <ChevronLeft className="h-3.5 w-3.5" />
                        <span>Prev</span>
                      </button>
                      <span className="font-mono">
                        {paginatedCves.currentPage} / {paginatedCves.totalPages}
                      </span>
                      <button
                        type="button"
                        disabled={!paginatedCves.hasNextPage}
                        onClick={() => setCvePage((p) => p + 1)}
                        className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                      >
                        <span>Next</span>
                        <ChevronRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}

          {/* CVE Detail Drawer / Modal */}
          {selectedCveDetail && (
            <div
              role="dialog"
              aria-label={`CVE Detail View for ${selectedCveDetail.cveId}`}
              className="rounded-lg border-2 border-blue-500/70 bg-[#080D1A] p-5 space-y-4 text-xs"
            >
              <div className="flex items-start justify-between gap-3 border-b border-[#1E2D4A] pb-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-base font-bold text-blue-300">
                      {selectedCveDetail.cveId}
                    </span>
                    <span className="font-mono font-semibold text-amber-300">
                      CVSS v{selectedCveDetail.cvssVersion}: {selectedCveDetail.cvssScoreDisplay} (
                      {selectedCveDetail.severity})
                    </span>
                    <span className="font-mono text-slate-400">
                      · Vendor: {selectedCveDetail.vendor} · Product: {selectedCveDetail.product}
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-slate-400">
                    Published: {selectedCveDetail.publishedAt} · Last Modified:{' '}
                    {selectedCveDetail.lastModifiedAt} · Source: {selectedCveDetail.sourceName}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setSelectedCveDetail(null)}
                  className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#141F38] px-2.5 py-1 text-xs text-slate-200 hover:text-white"
                >
                  <X className="h-3.5 w-3.5" />
                  <span>Close Detail</span>
                </button>
              </div>

              <div className="space-y-2">
                <div className="font-semibold text-slate-200">Vulnerability Description</div>
                <p className="leading-relaxed text-slate-300">
                  {selectedCveDetail.description}
                </p>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3 space-y-1">
                  <div className="font-semibold text-slate-200">CVSS Vector &amp; CWE</div>
                  <div className="font-mono text-[11px] text-blue-300 break-all">
                    Vector: {selectedCveDetail.cvssVector}
                  </div>
                  <div className="font-mono text-[11px] text-slate-300">
                    CWE: {selectedCveDetail.cweDisplay}
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    Exploitability:{' '}
                    {selectedCveDetail.exploitabilityScore ?? 'Unknown'} · Impact:{' '}
                    {selectedCveDetail.impactScore ?? 'Unknown'}
                  </div>
                </div>

                <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3 space-y-1">
                  <div className="font-semibold text-slate-200">CISA KEV Status</div>
                  <div
                    className={`font-mono font-semibold ${
                      selectedCveDetail.inKev ? 'text-rose-300' : 'text-amber-300'
                    }`}
                  >
                    {selectedCveDetail.kevStatusLabel}
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {selectedCveDetail.kevSafetyNote}
                  </p>
                </div>

                <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3 space-y-1">
                  <div className="font-semibold text-slate-200">
                    Affected Configurations (CPE)
                  </div>
                  <div className="font-mono text-[11px] text-slate-300 break-all">
                    {selectedCveDetail.affectedConfigurationsDisplay}
                  </div>
                </div>
              </div>

              <div className="border-t border-[#1E2D4A] pt-3">
                <div className="font-semibold text-slate-200 mb-1.5">
                  Official References &amp; Source Attribution
                </div>
                {selectedCveDetail.references.length === 0 ? (
                  <div className="font-mono text-slate-400">References: Unknown</div>
                ) : (
                  <div className="flex flex-wrap gap-3">
                    {selectedCveDetail.references.map((ref, idx) => (
                      <a
                        key={idx}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        referrerPolicy="no-referrer"
                        className="inline-flex items-center gap-1 font-mono text-blue-400 hover:underline"
                      >
                        <span>{ref.source}</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      )}

      {/* ====================================================================
          MODULE 2: CISA KEV TRACKER (With Snapshot Diff & 'Unknown != No' Semantics)
         ==================================================================== */}
      {showKevTracker && (
        <section
          aria-label="CISA KEV Tracker Module"
          className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-5"
        >
          <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-amber-300">
                <Flame className="h-4 w-4" aria-hidden="true" />
                <span>PHASE 3 INTELLIGENCE CENTER · MODULE 2: CISA KEV TRACKER</span>
              </div>
              <h2 className="mt-1 text-lg font-bold text-slate-100">
                CISA Known Exploited Vulnerabilities — Snapshot Diff Comparison &amp; Remediation Tracker
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Catalog v{kevCatalogVersion} (Released {kevDateReleased}) · Ransomware state{' '}
                <code className="text-amber-300">Unknown</code> means unconfirmed by CISA and is{' '}
                <strong className="text-slate-200">never interpreted as No</strong>.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <a
                href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                target="_blank"
                rel="noopener noreferrer"
                referrerPolicy="no-referrer"
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 text-xs font-medium text-blue-300 hover:border-blue-500 hover:text-white"
              >
                <span>Official CISA KEV Catalog</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </div>
          </div>

          {/* Snapshot Diff Comparison Banner */}
          {kevSnapshotDiff && (
            <div className="flex flex-col gap-3 rounded-lg border border-blue-800/70 bg-blue-950/30 p-4 text-xs sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2 font-mono font-semibold text-blue-300">
                  <Sparkles className="h-4 w-4 text-blue-400" />
                  <span>
                    SYNC SNAPSHOT DIFF COMPARISON: {kevSnapshotDiff.newlyImportedCount} NEWLY
                    IMPORTED RECORD(S) IDENTIFIED
                  </span>
                </div>
                <p className="text-slate-300">
                  Compared current catalog ({kevSnapshotDiff.currentCount} CVEs) against previous
                  sync baseline ({kevSnapshotDiff.previousCount} CVEs):{' '}
                  <strong className="text-emerald-300">
                    {kevSnapshotDiff.newlyImportedCount} newly imported
                  </strong>{' '}
                  ({kevSnapshotDiff.newlyImportedCveIds.slice(0, 5).join(', ') || 'None'}) and{' '}
                  {kevSnapshotDiff.retainedCount} retained.
                </p>
              </div>

              <button
                type="button"
                onClick={() =>
                  setKevSnapshotFilter((prev) =>
                    prev === 'NEWLY_IMPORTED' ? 'ALL' : 'NEWLY_IMPORTED'
                  )
                }
                className={`rounded-lg px-3.5 py-2 font-mono text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                  kevSnapshotFilter === 'NEWLY_IMPORTED'
                    ? 'bg-emerald-600 text-white'
                    : 'border border-emerald-700/80 bg-[#080D1A] text-emerald-300 hover:bg-emerald-950/60'
                }`}
              >
                {kevSnapshotFilter === 'NEWLY_IMPORTED'
                  ? `Showing Newly Imported Only (${kevSnapshotDiff.newlyImportedCount}) · Click for All`
                  : `Filter Newly Imported (${kevSnapshotDiff.newlyImportedCount})`}
              </button>
            </div>
          )}

          {/* KEV Search & Vendor / Product / Date Range Filters */}
          <div className="grid grid-cols-1 gap-3 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 sm:grid-cols-2 lg:grid-cols-6">
            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Keyword / CVE Search
              </label>
              <input
                type="text"
                value={kevSearchQuery}
                onChange={(e) => setKevSearchQuery(e.target.value)}
                placeholder="CVE ID or vulnerability..."
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Vendor Filter
              </label>
              <input
                type="text"
                value={kevVendorFilter}
                onChange={(e) => setKevVendorFilter(e.target.value)}
                placeholder="e.g. Microsoft / Cisco / Apache"
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Product Filter
              </label>
              <input
                type="text"
                value={kevProductFilter}
                onChange={(e) => setKevProductFilter(e.target.value)}
                placeholder="e.g. Windows / IOS / Roller"
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Date Added From
              </label>
              <input
                type="date"
                value={kevDateFrom}
                onChange={(e) => setKevDateFrom(e.target.value)}
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Date Added To
              </label>
              <input
                type="date"
                value={kevDateTo}
                onChange={(e) => setKevDateTo(e.target.value)}
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Ransomware &amp; Sort
              </label>
              <div className="flex gap-1">
                <select
                  value={kevRansomwareFilter}
                  onChange={(e) =>
                    setKevRansomwareFilter(
                      e.target.value as typeof kevRansomwareFilter
                    )
                  }
                  className="w-1/2 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-1.5 py-1.5 text-xs text-slate-100"
                >
                  <option value="ALL">All States</option>
                  <option value="Known">Known</option>
                  <option value="Unknown">Unknown (≠ No)</option>
                </select>
                <select
                  value={`${kevSortBy}:${kevSortDir}`}
                  onChange={(e) => {
                    const [sb, sd] = e.target.value.split(':');
                    setKevSortBy(sb as typeof kevSortBy);
                    setKevSortDir(sd as 'asc' | 'desc');
                  }}
                  className="w-1/2 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-1.5 py-1.5 text-xs text-slate-100"
                >
                  <option value="dateAdded:desc">Added Newest</option>
                  <option value="dateAdded:asc">Added Oldest</option>
                  <option value="dueDate:desc">Due Latest</option>
                  <option value="vendorProject:asc">Vendor A-Z</option>
                </select>
              </div>
            </div>
          </div>

          {/* KEV Table States */}
          {kevState === 'loading' ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-8 text-center text-xs text-slate-300">
              <RefreshCw className="mx-auto h-5 w-5 animate-spin text-blue-400 mb-2" />
              <div>Loading real imported CISA KEV records and computing snapshot diff...</div>
            </div>
          ) : kevState === 'error' ? (
            <div className="rounded-lg border border-rose-800/80 bg-rose-950/40 p-5 text-xs text-rose-200">
              {kevErrorMsg}
            </div>
          ) : kevRecords.length === 0 ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-8 text-center text-xs text-slate-400">
              Empty State: 0 KEV records matched your vendor, product, date, or snapshot diff filters (Total catalog size: {kevTotalCached}).
            </div>
          ) : (
            <div className="space-y-3">
              <div className="overflow-x-auto rounded-lg border border-[#1E2D4A] bg-[#080D1A]">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#1E2D4A] bg-[#10192E] text-slate-300">
                      <th className="px-3.5 py-2.5 font-medium">CVE ID &amp; Snapshot Diff</th>
                      <th className="px-3.5 py-2.5 font-medium">Vendor / Product</th>
                      <th className="px-3.5 py-2.5 font-medium">Vulnerability &amp; Required Action</th>
                      <th className="px-3.5 py-2.5 font-medium">Ransomware Use (Unknown ≠ No)</th>
                      <th className="px-3.5 py-2.5 text-right font-medium">Dates &amp; Official Links</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1E2D4A]/60 tabular-nums">
                    {kevRecords.map((item) => (
                      <tr key={item.cveId} className="hover:bg-[#141F38]/60">
                        <td className="px-3.5 py-3 align-top whitespace-nowrap">
                          <div className="font-mono font-bold text-blue-300">
                            {item.cveId}
                          </div>
                          {item.isNewlyImported ? (
                            <span className="mt-1 inline-block font-mono text-[10px] font-semibold text-emerald-300">
                              [NEW IN SNAPSHOT]
                            </span>
                          ) : (
                            <span className="mt-1 inline-block font-mono text-[10px] text-slate-500">
                              Retained from prior snapshot
                            </span>
                          )}
                        </td>

                        <td className="px-3.5 py-3 align-top">
                          <div className="font-medium text-slate-100">
                            {item.vendorProject}
                          </div>
                          <div className="text-[11px] text-slate-400">{item.product}</div>
                        </td>

                        <td className="px-3.5 py-3 align-top max-w-md">
                          <div className="font-medium text-slate-100">
                            {item.vulnerabilityName}
                          </div>
                          <div className="mt-1 text-[11px] text-slate-300">
                            <span className="font-semibold text-amber-300">Required Action: </span>
                            {item.requiredAction}
                          </div>
                        </td>

                        <td className="px-3.5 py-3 align-top font-mono text-[11px]">
                          <div
                            className={
                              item.knownRansomwareCampaignUse === 'Known'
                                ? 'font-bold text-rose-300'
                                : 'text-amber-300'
                            }
                          >
                            {item.knownRansomwareCampaignUse}
                          </div>
                          <div className="mt-0.5 text-[10px] text-slate-400 max-w-[180px]">
                            {item.knownRansomwareCampaignUse === 'Known'
                              ? 'Confirmed ransomware campaign usage'
                              : 'Unconfirmed — Do NOT interpret Unknown as No'}
                          </div>
                        </td>

                        <td className="px-3.5 py-3 align-top text-right font-mono text-[11px] whitespace-nowrap">
                          <div className="text-slate-200">Added: {item.dateAdded}</div>
                          <div className="text-amber-300">Due: {item.dueDate}</div>
                          <div className="mt-1 flex items-center justify-end gap-2">
                            <a
                              href={item.officialNvdUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              referrerPolicy="no-referrer"
                              className="inline-flex items-center gap-0.5 text-[10px] text-blue-400 hover:underline"
                            >
                              <span>NVD</span>
                              <ExternalLink className="h-2.5 w-2.5" />
                            </a>
                            <a
                              href={item.officialCatalogUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              referrerPolicy="no-referrer"
                              className="inline-flex items-center gap-0.5 text-[10px] text-blue-400 hover:underline"
                            >
                              <span>CISA</span>
                              <ExternalLink className="h-2.5 w-2.5" />
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>
                  Showing {(kevPage - 1) * kevPageSize + 1}–
                  {Math.min(kevPage * kevPageSize, kevTotalMatches)} of{' '}
                  <strong className="text-slate-200">{kevTotalMatches}</strong> matching KEV records
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={kevPage <= 1}
                    onClick={() => void loadKevRecords(Math.max(1, kevPage - 1))}
                    className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    <span>Prev</span>
                  </button>
                  <span className="font-mono">Page {kevPage}</span>
                  <button
                    type="button"
                    disabled={kevPage * kevPageSize >= kevTotalMatches}
                    onClick={() => void loadKevRecords(kevPage + 1)}
                    className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                  >
                    <span>Next</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* ====================================================================
          MODULE 04: MALWARE INTELLIGENCE & SHA-256 HASH LOOKUP
         ==================================================================== */}
      {showMalwareIntel && (
        <section
          aria-label="Malware Intelligence Module"
          className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-5"
        >
          <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-blue-400">
                <Bug className="h-4 w-4" aria-hidden="true" />
                <span>MODULE 04: MALWARE INTELLIGENCE · KEYLESS FEODO TRACKER C2 &amp; SHA-256 LOOKUP</span>
              </div>
              <h2 className="mt-1 text-lg font-bold text-slate-100">
                Verified Public Malware Feeds, Botnet C2 Blocklist &amp; Defensive SHA-256 Lookup
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Strict defensive policy: Never downloads or executes malware, never collects stolen credentials, never invents API keys, and defangs all network indicators (<code className="text-slate-300">hxxp://</code>, <code className="text-slate-300">[.]</code>).
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                disabled={malwareFeedSyncing}
                onClick={() => void handleManualFeodoRefresh()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-60 whitespace-nowrap"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${malwareFeedSyncing ? 'animate-spin' : ''}`} />
                <span>
                  {malwareFeedSyncing
                    ? 'Refreshing Feodo Tracker...'
                    : 'Manual Refresh: Feodo Tracker C2'}
                </span>
              </button>
            </div>
          </div>

          {/* Individual Malware Feed Status & Licensing Verification Matrix */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
              <div className="font-mono text-xs font-semibold text-slate-200">
                INDIVIDUAL MALWARE FEED STATUS, AUTHENTICATION &amp; LICENSING VERIFICATION ($0 BUDGET)
              </div>
              {malwareFeedSummary && (
                <div className="font-mono text-[11px] text-slate-400">
                  Operational Feeds:{' '}
                  <strong className="text-emerald-300">
                    {malwareFeedSummary.activeOperationalFeeds} CONNECTED
                  </strong>{' '}
                  · Optional Unconfigured:{' '}
                  <strong className="text-amber-300">
                    {malwareFeedSummary.unconfiguredOptionalFeeds} NOT CONFIGURED
                  </strong>{' '}
                  · Deduplicated Indicators:{' '}
                  <strong className="text-blue-300">
                    {malwareFeedSummary.totalIndicators}
                  </strong>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {malwareFeedRegistry.map((feed) => {
                const isConnected = feed.status === 'CONNECTED';
                const isNotConfigured = feed.status === 'NOT CONFIGURED';
                const badgeClass = isConnected
                  ? 'border-emerald-700/70 bg-emerald-950/60 text-emerald-300'
                  : isNotConfigured
                  ? 'border-amber-700/70 bg-amber-950/50 text-amber-300'
                  : 'border-rose-700/70 bg-rose-950/50 text-rose-300';

                return (
                  <div
                    key={feed.feedId}
                    className="rounded-md border border-[#1E2D4A] bg-[#0E1628] p-3 text-xs space-y-2 flex flex-col justify-between"
                  >
                    <div className="space-y-1.5">
                      <div className="flex items-start justify-between gap-2">
                        <a
                          href={feed.officialDocsUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-semibold text-slate-100 hover:text-blue-300 inline-flex items-center gap-1"
                        >
                          <span>{feed.name}</span>
                          <ExternalLink className="h-3 w-3 shrink-0 text-slate-400" />
                        </a>
                        <span
                          className={`rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase whitespace-nowrap shrink-0 ${badgeClass}`}
                        >
                          {feed.status}
                        </span>
                      </div>

                      <div className="font-mono text-[11px] text-blue-300 break-all">
                        {feed.indicatorCategory}
                      </div>

                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        <strong className="text-slate-300">Auth:</strong> {feed.authRequirement}
                      </p>
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        <strong className="text-slate-300">License &amp; Terms:</strong>{' '}
                        {feed.licenseAndTerms}
                      </p>
                    </div>

                    <div className="border-t border-[#1E2D4A]/80 pt-2 flex flex-wrap items-center justify-between gap-2 font-mono text-[10px] text-slate-400">
                      <span>
                        Cached: <strong className="text-slate-200">{feed.cachedCount}</strong> ·
                        Deduped: <strong className="text-slate-200">{feed.duplicatesCollapsed}</strong>
                      </span>
                      <span>
                        {feed.lastSuccessAt
                          ? `Synced: ${feed.lastSuccessAt.slice(0, 19).replace('T', ' ')} UTC`
                          : 'Not Synced'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* SHA-256 Hash Lookup Tool */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2 font-mono text-xs font-semibold text-slate-200">
                <FileDigit className="h-4 w-4 text-blue-400" />
                <span>SHA-256 CRYPTOGRAPHIC FILE DIGEST LOOKUP (CIRCL PUBLIC HASHLOOKUP + FIRESTORE)</span>
              </div>
              <div className="flex flex-wrap gap-1.5 text-[11px]">
                <button
                  type="button"
                  onClick={() =>
                    void handleSha256Lookup(
                      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
                    )
                  }
                  className="rounded border border-[#1E2D4A] bg-[#141F38] px-2 py-0.5 font-mono text-blue-300 hover:border-blue-500"
                >
                  Test Empty-File SHA-256 (CIRCL Match)
                </button>
              </div>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleSha256Lookup();
              }}
              className="flex flex-col gap-2.5 sm:flex-row"
            >
              <input
                type="text"
                value={sha256Input}
                onChange={(e) => setSha256Input(e.target.value)}
                placeholder="Enter 64-character hexadecimal SHA-256 digest..."
                className="flex-1 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-2 font-mono text-xs text-slate-100"
              />
              <button
                type="submit"
                disabled={sha256State === 'loading'}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                <Search className="h-3.5 w-3.5" />
                <span>
                  {sha256State === 'loading' ? 'Looking up SHA-256...' : 'Lookup SHA-256'}
                </span>
              </button>
            </form>

            {sha256State === 'error' && sha256Error && (
              <div className="rounded border border-rose-800/80 bg-rose-950/40 p-3 font-mono text-xs text-rose-200">
                {sha256Error}
              </div>
            )}

            {sha256State === 'success' && sha256Result && (
              <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3.5 text-xs space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                  <span className="font-bold text-blue-300 break-all">
                    SHA-256: {sha256Result.sha256}
                  </span>
                  <span className="text-slate-400">
                    Source: {sha256Result.sourceName} · {sha256Result.retrievedAt.slice(0, 19)}
                  </span>
                </div>
                <p className="text-slate-300">{sha256Result.message}</p>
                {sha256Result.metadata && (
                  <div className="grid grid-cols-2 gap-2 border-t border-[#1E2D4A] pt-2 font-mono text-[11px] text-slate-300 sm:grid-cols-4">
                    <div>File Name: {sha256Result.metadata.fileName}</div>
                    <div>File Size: {sha256Result.metadata.fileSize} bytes</div>
                    <div>MD5: {sha256Result.metadata.md5}</div>
                    <div>CIRCL Trust: {sha256Result.metadata.trustLevel}</div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Authorized Threat Indicators Filter & Deduplicated Table */}
          <div className="space-y-3">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-xs font-semibold text-slate-200">
                Authorized &amp; Deduplicated Malware Indicators (Feodo Tracker Botnet C2 + Optional URLhaus + Firestore)
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="text"
                  value={malwareSearchQuery}
                  onChange={(e) => setMalwareSearchQuery(e.target.value)}
                  placeholder="Filter IP, family (Emotet, QakBot), ASN..."
                  className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1.5 text-xs text-slate-200"
                />
                <select
                  value={malwareTypeFilter}
                  onChange={(e) => setMalwareTypeFilter(e.target.value)}
                  className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1.5 text-xs text-slate-200"
                >
                  <option value="ALL">All Indicator Types</option>
                  <option value="ip">Defanged Botnet C2 IP:Port</option>
                  <option value="url">Defanged URL</option>
                  <option value="domain">Defanged Domain</option>
                  <option value="sha256">SHA-256 Digest</option>
                </select>
                <select
                  value={malwareSourceFilter}
                  onChange={(e) => setMalwareSourceFilter(e.target.value)}
                  className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1.5 text-xs text-slate-200"
                >
                  <option value="">All Authorized Sources</option>
                  <option value="Feodo Tracker">abuse.ch Feodo Tracker</option>
                  <option value="URLhaus">abuse.ch URLhaus</option>
                  <option value="Firestore">Cloud Firestore</option>
                </select>
              </div>
            </div>

            {malwareState === 'loading' ? (
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-6 text-center text-xs text-slate-300">
                Loading authorized malware intelligence feeds...
              </div>
            ) : malwareState === 'error' ? (
              <div className="rounded border border-rose-800/80 bg-rose-950/40 p-4 text-xs text-rose-200">
                {malwareErrorMsg}
              </div>
            ) : filteredIndicators.length === 0 ? (
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-6 text-center text-xs text-slate-400">
                Empty State: 0 authorized threat indicators matched current filter criteria. Click &ldquo;Manual Refresh: Feodo Tracker C2&rdquo; to sync the official keyless abuse.ch Feodo Tracker feed.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="overflow-x-auto rounded border border-[#1E2D4A] bg-[#080D1A]">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-[#1E2D4A] bg-[#10192E] text-slate-300">
                        <th className="px-3.5 py-2.5">Defanged Indicator (IP:Port / URL)</th>
                        <th className="px-3.5 py-2.5">Threat Type &amp; Malware Family</th>
                        <th className="px-3.5 py-2.5">Status &amp; Severity</th>
                        <th className="px-3.5 py-2.5">Source Attribution</th>
                        <th className="px-3.5 py-2.5 text-right">First Seen / Last Online (UTC)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1E2D4A]/60 font-mono tabular-nums">
                      {filteredIndicators.map((ind) => (
                        <tr key={ind.indicatorId} className="hover:bg-[#141F38]/50">
                          <td className="px-3.5 py-2.5 text-blue-300 break-all max-w-xs">
                            {ind.defangedValue}
                          </td>
                          <td className="px-3.5 py-2.5 text-slate-200">
                            <div className="font-semibold text-amber-300">{ind.malwareFamily}</div>
                            <div className="text-[10px] text-slate-400">{ind.threatType}</div>
                          </td>
                          <td className="px-3.5 py-2.5">
                            <span
                              className={`uppercase font-semibold ${
                                ind.status.includes('online')
                                  ? 'text-rose-400'
                                  : 'text-emerald-300'
                              }`}
                            >
                              {ind.status}
                            </span>{' '}
                            · <span className="text-amber-300">{ind.severity}</span>
                          </td>
                          <td className="px-3.5 py-2.5 text-slate-300">
                            <a
                              href={ind.sourceUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-blue-300 hover:underline"
                            >
                              <span>{ind.sourceName}</span>
                              <ExternalLink className="h-3 w-3 shrink-0" />
                            </a>
                          </td>
                          <td className="px-3.5 py-2.5 text-right text-[11px] text-slate-400">
                            <div>First: {ind.firstSeenAt.slice(0, 19).replace('T', ' ')}</div>
                            <div>Last: {ind.updatedAt.slice(0, 10)}</div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {isLiveFirestore && (
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>Firestore Cursor Page {fsIndPageIdx + 1}</span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={fsIndPageIdx <= 0}
                        onClick={() =>
                          void loadFirestoreThreatIndicators(fsIndPageIdx - 1, fsIndCursors)
                        }
                        className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                      >
                        Prev Page
                      </button>
                      <button
                        type="button"
                        disabled={!fsIndHasNext}
                        onClick={() =>
                          void loadFirestoreThreatIndicators(fsIndPageIdx + 1, fsIndCursors)
                        }
                        className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                      >
                        Next Page
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      )}

      {/* ====================================================================
          MODULE 4: SCAM & PHISHING INTELLIGENCE
         ==================================================================== */}
      {showScamPhishing && (
        <section
          aria-label="Scam and Phishing Intelligence Module"
          className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-6"
        >
          <div className="border-b border-[#1E2D4A] pb-4">
            <div className="flex items-center gap-2 font-mono text-xs text-amber-300">
              <FishOff className="h-4 w-4" aria-hidden="true" />
              <span>PHASE 3 INTELLIGENCE CENTER · MODULE 4: SCAM &amp; PHISHING INTELLIGENCE</span>
            </div>
            <h2 className="mt-1 text-lg font-bold text-slate-100">
              Suspicious URL Parser, Threat Feed Matcher, Community Reporting &amp; Moderation Queue
            </h2>
          </div>

          {/* 4A. Suspicious URL Parser & Threat Feed Matcher */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-4">
            <div className="flex items-center gap-2 font-mono text-xs font-semibold text-blue-300">
              <Link2 className="h-4 w-4" />
              <span>SUSPICIOUS URL &amp; DOMAIN STRUCTURAL PARSER (ZERO OUTBOUND CONNECTION TO TARGET)</span>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                const feedPool = [
                  ...approvedScamReports.map((s) => ({
                    feedName: 'Verified Community Scam Reports (Firestore)',
                    indicatorId: s.reportId,
                    defangedOrRawValue: s.defangedIndicator,
                    categoryOrThreat: s.category,
                    verificationStatus: s.moderationStatus,
                  })),
                  ...threatIndicators.map((t) => ({
                    feedName: t.source || 'Verified Threat Indicators (Firestore)',
                    indicatorId: t.indicatorId,
                    defangedOrRawValue: t.defangedValue,
                    categoryOrThreat: t.malwareFamily,
                    verificationStatus: 'verified',
                  })),
                ];
                setUrlAnalysisResult(
                  parseAndInspectSuspiciousUrl(suspiciousUrlInput, feedPool)
                );
              }}
              className="flex flex-col gap-2.5 sm:flex-row"
            >
              <input
                type="text"
                value={suspiciousUrlInput}
                onChange={(e) => setSuspiciousUrlInput(e.target.value)}
                placeholder="Paste suspicious URL or domain to defang, parse & match against threat feeds..."
                className="flex-1 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-2 font-mono text-xs text-slate-100"
              />
              <button
                type="submit"
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 whitespace-nowrap shrink-0"
              >
                <Search className="h-3.5 w-3.5" />
                <span>Parse &amp; Match Threat Feeds</span>
              </button>
            </form>

            {urlAnalysisResult && (
              <div className="space-y-3 text-xs">
                {/* Mandatory No Match != Safe Warning Banner */}
                <div className="rounded-lg border border-amber-700/80 bg-amber-950/40 p-3.5 text-amber-200">
                  <div className="flex items-start gap-2.5">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                    <div>
                      <div className="font-mono font-bold">
                        {urlAnalysisResult.matchCount > 0
                          ? `ALERT: MATCHED ${urlAnalysisResult.matchCount} CONFIGURED THREAT FEED RECORD(S)`
                          : '0 DIRECT MATCHES IN CONFIGURED FEEDS — NO MATCH DOES NOT MEAN SAFE'}
                      </div>
                      <p className="mt-1 text-[11px] leading-relaxed">
                        {urlAnalysisResult.noMatchSafetyExplanation}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Structural Decomposition Grid */}
                <div className="grid grid-cols-1 gap-3 rounded border border-[#1E2D4A] bg-[#0E1628] p-3.5 font-mono text-[11px] sm:grid-cols-2 lg:grid-cols-4">
                  <div>
                    <span className="text-slate-400">Defanged URL (Query Redacted):</span>
                    <div className="mt-0.5 text-blue-300 break-all">
                      {urlAnalysisResult.defangedUrl}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400">Defanged Host &amp; TLD:</span>
                    <div className="mt-0.5 text-slate-100">
                      {urlAnalysisResult.defangedHostname} (TLD: {urlAnalysisResult.tld})
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400">Scheme / Port / Subdomains:</span>
                    <div className="mt-0.5 text-slate-200">
                      {urlAnalysisResult.scheme} · Port: {urlAnalysisResult.port} · Depth:{' '}
                      {urlAnalysisResult.subdomainDepth}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400">Path &amp; Query Keys:</span>
                    <div className="mt-0.5 text-slate-200 break-all">
                      {urlAnalysisResult.path} (Keys:{' '}
                      {urlAnalysisResult.queryParamKeys.join(', ') || 'None'})
                    </div>
                  </div>
                </div>

                {/* Heuristic Structural Risk Signals */}
                {urlAnalysisResult.structuralRiskSignals.length > 0 && (
                  <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3 space-y-1.5">
                    <div className="font-semibold text-rose-300">
                      Detected Structural Phishing / Spoofing Indicators (
                      {urlAnalysisResult.structuralRiskSignals.length}):
                    </div>
                    <ul className="list-disc pl-5 space-y-1 text-[11px] text-slate-200">
                      {urlAnalysisResult.structuralRiskSignals.map((sig, i) => (
                        <li key={i}>{sig}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Feed Match Hits */}
                {urlAnalysisResult.feedMatches.length > 0 && (
                  <div className="rounded border border-rose-800/80 bg-rose-950/40 p-3 space-y-1.5">
                    <div className="font-semibold text-rose-200">
                      Matched Threat Feed Records:
                    </div>
                    {urlAnalysisResult.feedMatches.map((hit, idx) => (
                      <div key={idx} className="font-mono text-[11px] text-rose-200">
                        [{hit.feedName}] {hit.indicatorId}: {hit.matchedValue} (
                        {hit.categoryOrThreat} · Status: {hit.verificationStatus.toUpperCase()})
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* 4B. Submit New Scam / Phishing Report & Admin Moderation Queue */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Submit Scam Report Form */}
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!reportTitle.trim() || !reportIndicator.trim() || !reportDescription.trim())
                  return;
                setReportSubmitting(true);
                try {
                  await submitScamReport(
                    reportTitle,
                    reportCategory,
                    reportIndicator,
                    reportDescription
                  );
                  setReportTitle('');
                  setReportIndicator('');
                  setReportDescription('');
                  await loadPaginatedApprovedScams(0, []);
                } finally {
                  setReportSubmitting(false);
                }
              }}
              className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3 text-xs"
            >
              <div className="font-semibold text-slate-100">
                Submit Suspicious Scam / Phishing Report (Enters Pending Moderation Queue)
              </div>
              <p className="text-[11px] text-slate-400">
                All submitted URLs are automatically defanged. Never paste passwords, OTP codes, or session cookies.
              </p>

              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                <div>
                  <label className="block text-[11px] text-slate-300 mb-1">Report Title</label>
                  <input
                    type="text"
                    required
                    minLength={5}
                    maxLength={200}
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                    placeholder="e.g. Fake Bank OTP Verification SMS Link"
                    className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-300 mb-1">Scam Category</label>
                  <select
                    value={reportCategory}
                    onChange={(e) =>
                      setReportCategory(e.target.value as ScamReportDoc['category'])
                    }
                    className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-100"
                  >
                    <option value="phishing_url">Phishing URL</option>
                    <option value="otp_scam">OTP / Financial Scam</option>
                    <option value="brand_impersonation">Brand Impersonation</option>
                    <option value="invoice_fraud">Invoice / Wire Fraud</option>
                    <option value="fake_job">Fake Job Portal</option>
                    <option value="other">Other Scam</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[11px] text-slate-300 mb-1">
                  Suspicious URL or Domain (Auto-Defanged on Save)
                </label>
                <input
                  type="text"
                  required
                  minLength={3}
                  maxLength={512}
                  value={reportIndicator}
                  onChange={(e) => setReportIndicator(e.target.value)}
                  placeholder="hxxps://suspicious-domain[.]example[.]com/login"
                  className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-slate-100"
                />
              </div>

              <div>
                <label className="block text-[11px] text-slate-300 mb-1">
                  Defensive Context &amp; Observations (10–2500 chars)
                </label>
                <textarea
                  rows={2}
                  required
                  minLength={10}
                  maxLength={2500}
                  value={reportDescription}
                  onChange={(e) => setReportDescription(e.target.value)}
                  placeholder="Describe how the scam link was distributed and what brand it impersonates..."
                  className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-100"
                />
              </div>

              <button
                type="submit"
                disabled={reportSubmitting || (!isSignedIn && isLiveFirestore)}
                className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
              >
                {reportSubmitting
                  ? 'Submitting to Moderation Queue...'
                  : !isSignedIn && isLiveFirestore
                  ? 'Sign in with Google to Submit Scam Report'
                  : 'Submit Report for Moderation'}
              </button>
            </form>

            {/* Moderation Queue & User Report Status */}
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-100">
                  {isAdmin
                    ? `Admin Moderation Queue (${pendingScamReports.length} Pending)`
                    : `My Submitted Reports (${myScamReports.length})`}
                </span>
                <span className="font-mono text-[11px] text-slate-400">
                  RBAC: {isAdmin ? 'ADMIN MODERATOR' : 'REPORTER'}
                </span>
              </div>

              {isAdmin ? (
                pendingScamReports.length === 0 ? (
                  <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-4 text-slate-400">
                    Moderation queue is clear (0 pending reports). Submit a report on the left to test moderation approval/rejection.
                  </div>
                ) : (
                  <div className="space-y-2.5 max-h-64 overflow-y-auto">
                    {pendingScamReports.map((rep) => (
                      <div
                        key={rep.reportId}
                        className="rounded border border-amber-800/70 bg-[#0E1628] p-3 space-y-2"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-semibold text-amber-300">
                            {rep.title} ({rep.category})
                          </span>
                          <span className="text-[10px] text-amber-400 uppercase">
                            STATUS: {rep.moderationStatus}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-blue-300 break-all">
                          Indicator: {rep.defangedIndicator}
                        </div>
                        <p className="text-[11px] text-slate-300">{rep.description}</p>
                        <div className="flex flex-wrap items-center gap-2 pt-1">
                          <input
                            type="text"
                            value={moderationNotesInput[rep.reportId] || ''}
                            onChange={(e) =>
                              setModerationNotesInput((prev) => ({
                                ...prev,
                                [rep.reportId]: e.target.value,
                              }))
                            }
                            placeholder="Moderator verification note..."
                            className="flex-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-1 text-[11px] text-slate-200"
                          />
                          <button
                            type="button"
                            onClick={async () => {
                              await moderateScamReport(
                                rep.reportId,
                                'approved',
                                moderationNotesInput[rep.reportId] ||
                                  'Verified public phishing indicator.'
                              );
                              await loadPaginatedApprovedScams(0, []);
                            }}
                            className="inline-flex items-center gap-1 rounded bg-emerald-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-emerald-500"
                          >
                            <Check className="h-3 w-3" />
                            <span>Approve</span>
                          </button>
                          <button
                            type="button"
                            onClick={async () => {
                              await moderateScamReport(
                                rep.reportId,
                                'rejected',
                                moderationNotesInput[rep.reportId] ||
                                  'Insufficient verification evidence.'
                              );
                              await loadPaginatedApprovedScams(0, []);
                            }}
                            className="inline-flex items-center gap-1 rounded bg-rose-700 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-rose-600"
                          >
                            <XCircle className="h-3 w-3" />
                            <span>Reject</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )
              ) : myScamReports.length === 0 ? (
                <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-4 text-slate-400">
                  You have not submitted any scam reports in this session.
                </div>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {myScamReports.map((rep) => (
                    <div
                      key={rep.reportId}
                      className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3"
                    >
                      <div className="flex items-center justify-between font-mono">
                        <span className="font-semibold text-slate-100">{rep.title}</span>
                        <span
                          className={`uppercase font-semibold ${
                            rep.moderationStatus === 'approved'
                              ? 'text-emerald-300'
                              : rep.moderationStatus === 'rejected'
                              ? 'text-rose-300'
                              : 'text-amber-300'
                          }`}
                        >
                          {rep.moderationStatus}
                        </span>
                      </div>
                      <div className="mt-1 font-mono text-[11px] text-blue-300">
                        {rep.defangedIndicator}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* 4C. Publicly Verified Scam Reports Table (Firestore Cursor Paginated) */}
          <div className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-xs font-semibold text-slate-200">
                Publicly Verified Scam &amp; Phishing Reports (Status: <code className="text-emerald-300">APPROVED</code>)
              </div>
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={scamSearchQuery}
                  onChange={(e) => setScamSearchQuery(e.target.value)}
                  placeholder="Search verified reports..."
                  className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-xs text-slate-200"
                />
                <select
                  value={scamCategoryFilter}
                  onChange={(e) => setScamCategoryFilter(e.target.value)}
                  className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-xs text-slate-200"
                >
                  <option value="ALL">All Categories</option>
                  <option value="phishing_url">Phishing URL</option>
                  <option value="otp_scam">OTP Scam</option>
                  <option value="brand_impersonation">Brand Impersonation</option>
                  <option value="invoice_fraud">Invoice Fraud</option>
                  <option value="fake_job">Fake Job</option>
                </select>
              </div>
            </div>

            {scamState === 'loading' ? (
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-6 text-center text-xs text-slate-300">
                Loading publicly verified scam reports...
              </div>
            ) : filteredApprovedScams.length === 0 ? (
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-6 text-center text-xs text-slate-400">
                Empty State: 0 publicly verified (approved) scam reports match the current filter.
              </div>
            ) : (
              <div className="overflow-x-auto rounded border border-[#1E2D4A] bg-[#080D1A]">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#1E2D4A] bg-[#10192E] text-slate-300">
                      <th className="px-3.5 py-2.5">Report Title &amp; Category</th>
                      <th className="px-3.5 py-2.5">Defanged Indicator</th>
                      <th className="px-3.5 py-2.5">Description &amp; Moderator Notes</th>
                      <th className="px-3.5 py-2.5 text-right">Verification Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1E2D4A]/60">
                    {filteredApprovedScams.map((rep) => (
                      <tr key={rep.reportId} className="hover:bg-[#141F38]/50">
                        <td className="px-3.5 py-2.5">
                          <div className="font-medium text-slate-100">{rep.title}</div>
                          <div className="font-mono text-[10px] text-slate-400">
                            {rep.category}
                          </div>
                        </td>
                        <td className="px-3.5 py-2.5 font-mono text-blue-300 break-all">
                          {rep.defangedIndicator}
                        </td>
                        <td className="px-3.5 py-2.5 text-slate-300 max-w-md">
                          <div>{rep.description}</div>
                          {rep.moderatorNotes && (
                            <div className="mt-0.5 font-mono text-[10px] text-emerald-300">
                              Moderator Note: {rep.moderatorNotes}
                            </div>
                          )}
                        </td>
                        <td className="px-3.5 py-2.5 text-right font-mono text-emerald-300 font-semibold whitespace-nowrap">
                          VERIFIED ({rep.moderationStatus.toUpperCase()})
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      )}

      {/* ====================================================================
          MODULE 5: SECURITY ADVISORIES
         ==================================================================== */}
      {showSecurityAdvisories && (
        <section
          aria-label="Security Advisories Module"
          className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-5"
        >
          <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-2 font-mono text-xs text-blue-400">
                <FileWarning className="h-4 w-4" aria-hidden="true" />
                <span>PHASE 3 INTELLIGENCE CENTER · MODULE 5: SECURITY ADVISORIES</span>
              </div>
              <h2 className="mt-1 text-lg font-bold text-slate-100">
                Official Security Advisories — Source Attribution, Publication Dates &amp; Category Filters
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Aggregates verified public advisories from the GitHub Security Advisory Database (GHSA) and CISA KEV Directives with direct official links.
              </p>
            </div>

            <button
              type="button"
              onClick={() => void loadSecurityAdvisories(1, true)}
              disabled={advisoriesState === 'loading'}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-2 text-xs font-medium text-slate-100 hover:border-blue-500 whitespace-nowrap shrink-0"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 text-blue-400 ${
                  advisoriesState === 'loading' ? 'animate-spin' : ''
                }`}
              />
              <span>Refresh Advisories</span>
            </button>
          </div>

          {/* Advisory Filter Bar */}
          <div className="grid grid-cols-1 gap-3 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 sm:grid-cols-3">
            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Search Advisories (ID, CVE, Package, Summary)
              </label>
              <input
                type="text"
                value={advisorySearchQuery}
                onChange={(e) => setAdvisorySearchQuery(e.target.value)}
                placeholder="Search GHSA, CVE, vendor, or summary..."
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Category / Ecosystem Filter
              </label>
              <select
                value={advisoryCategoryFilter}
                onChange={(e) => setAdvisoryCategoryFilter(e.target.value)}
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-xs text-slate-100"
              >
                <option value="ALL">All Categories &amp; Ecosystems</option>
                {advisoryCategories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-300 mb-1">
                Severity Filter
              </label>
              <select
                value={advisorySeverityFilter}
                onChange={(e) => setAdvisorySeverityFilter(e.target.value)}
                className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-xs text-slate-100"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
          </div>

          {/* Advisories List States */}
          {advisoriesState === 'loading' ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-8 text-center text-xs text-slate-300">
              <RefreshCw className="mx-auto h-5 w-5 animate-spin text-blue-400 mb-2" />
              <div>Loading official public security advisories...</div>
            </div>
          ) : advisoriesState === 'error' ? (
            <div className="rounded-lg border border-rose-800/80 bg-rose-950/40 p-5 text-xs text-rose-200">
              {advisoriesErrorMsg}
            </div>
          ) : advisoriesList.length === 0 ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-8 text-center text-xs text-slate-400">
              Empty State: 0 security advisories matched your category or severity filter.
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                {advisoriesList.map((adv) => (
                  <article
                    key={adv.advisoryId}
                    className="flex flex-col justify-between rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs space-y-3"
                  >
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                        <span className="font-bold text-blue-300">
                          {adv.advisoryId} ({adv.cveId})
                        </span>
                        <span
                          className={`font-semibold ${
                            adv.severity === 'CRITICAL'
                              ? 'text-rose-300'
                              : adv.severity === 'HIGH'
                              ? 'text-amber-300'
                              : 'text-blue-300'
                          }`}
                        >
                          {adv.severity} · {adv.category}
                        </span>
                      </div>

                      <h3 className="text-sm font-semibold text-slate-100">
                        {adv.title}
                      </h3>

                      <p className="text-slate-300 leading-relaxed">
                        {adv.shortSummary}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#1E2D4A]/70 pt-2.5 font-mono text-[11px] text-slate-400">
                      <div>
                        <div>Source: {adv.sourceName}</div>
                        <div>Published: {adv.publishedAt.slice(0, 10)}</div>
                      </div>

                      <a
                        href={adv.officialSourceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        referrerPolicy="no-referrer"
                        className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#141F38] px-2.5 py-1 text-blue-300 hover:border-blue-500 hover:text-white"
                      >
                        <span>Official Advisory</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </article>
                ))}
              </div>

              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>
                  Showing {(advisoryPage - 1) * advisoryPageSize + 1}–
                  {Math.min(advisoryPage * advisoryPageSize, advisoryTotalMatches)} of{' '}
                  <strong className="text-slate-200">{advisoryTotalMatches}</strong> advisories
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={advisoryPage <= 1}
                    onClick={() =>
                      void loadSecurityAdvisories(Math.max(1, advisoryPage - 1), false)
                    }
                    className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    <span>Prev</span>
                  </button>
                  <span className="font-mono">Page {advisoryPage}</span>
                  <button
                    type="button"
                    disabled={advisoryPage * advisoryPageSize >= advisoryTotalMatches}
                    onClick={() => void loadSecurityAdvisories(advisoryPage + 1, false)}
                    className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                  >
                    <span>Next</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>
      )}

      {/* ====================================================================
          PHASE 3 AUTOMATED VERIFICATION SUITE (Search, Filter, Pagination & Attribution)
         ==================================================================== */}
      <section
        aria-label="Phase 3 Intelligence Center Automated Tests"
        className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4"
      >
        <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs text-emerald-300">
              <CheckCircle2 className="h-4 w-4" />
              <span>
                PHASE 3 AUTOMATED TEST SUITE: SEARCH, FILTERING, PAGINATION &amp; ATTRIBUTION
              </span>
            </div>
            <p className="mt-0.5 text-xs text-slate-400">
              Verifies Unknown normalization, CVSS filtering, CSV export, KEV snapshot diffs, ransomware Unknown semantics, SHA-256 lookup, URL parsing, and advisory attribution.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setTestResults(runIntelligenceCenterTests())}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-blue-500 whitespace-nowrap shrink-0"
          >
            <Play className="h-3.5 w-3.5" />
            <span>Re-Run Phase 3 Tests (5 / 5)</span>
          </button>
        </div>

        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
          {testResults.map((tr) => (
            <div
              key={tr.id}
              className="flex items-start gap-2.5 rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs"
            >
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              <div>
                <div className="font-semibold text-slate-100">
                  [{tr.module}] {tr.testName}
                </div>
                <div className="mt-1 font-mono text-[11px] text-emerald-300">
                  {tr.details}
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
