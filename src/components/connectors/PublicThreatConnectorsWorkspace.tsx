import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  RefreshCw,
  Search,
  Database,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  Flame,
  Activity,
  Unplug,
  ChevronLeft,
  ChevronRight,
  Play,
  FileCode2,
  Clock,
  KeyRound,
} from 'lucide-react';
import {
  doc,
  getDoc,
  setDoc,
  serverTimestamp,
} from 'firebase/firestore';
import { db, OperationType, handleFirestoreError } from '../../firebase/config';
import { useSecurity } from '../../context/SecurityContext';
import { useApp } from '../../context/AppContext';
import { CoreModuleId } from '../../types/navigation';
import {
  ParsedKevRecord,
  ParsedNvdCveRecord,
  ParsedEpssRecord,
  ParsedUrlhausRecord,
  DataFreshnessInfo,
  ConnectorOperationalState,
} from '../../connectors/parsers';
import {
  runAutomatedConnectorParserTests,
  AutomatedParserTestResult,
} from '../../connectors/connectors.test';

interface ConnectorStatusItem {
  connectorId: 'cisa_kev' | 'nist_nvd' | 'first_epss' | 'urlhaus' | 'feodo_tracker';
  name: string;
  officialDocsUrl: string;
  endpointUrl: string;
  status: ConnectorOperationalState;
  requiresCredentials: boolean;
  credentialEnvVar: string | null;
  credentialConfigured: boolean;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastError: string | null;
  cachedRecordCount: number;
  duplicatesCollapsed: number;
  upstreamVersion: string | null;
  upstreamReleaseDate: string | null;
  rateLimitNote: string;
  freshness: DataFreshnessInfo;
}

interface EnrichedNvdRecord extends ParsedNvdCveRecord {
  kevRecord: ParsedKevRecord | null;
  kevSafetyWarning: string;
  epssRecord: ParsedEpssRecord | null;
}

interface ConnectorErrorLog {
  id: string;
  connectorId: string;
  timestamp: string;
  attemptCount: number;
  errorMessage: string;
  preservedCachedCount: number;
}

interface Props {
  moduleId: CoreModuleId;
}

export const PublicThreatConnectorsWorkspace: React.FC<Props> = ({ moduleId }) => {
  const { language } = useApp();
  const { isAdmin, firebaseUser, persistenceMode, kevEntries, refreshCollections } =
    useSecurity();
  const isBn = language === 'bn';
  const isLiveFirestore = persistenceMode === 'FIRESTORE_LIVE';

  // Connector Engine Status
  const [connectors, setConnectors] = useState<ConnectorStatusItem[]>([]);
  const [errorLogs, setErrorLogs] = useState<ConnectorErrorLog[]>([]);
  const [statusLoading, setStatusLoading] = useState<boolean>(false);
  const [engineFeedback, setEngineFeedback] = useState<{
    type: 'success' | 'warning' | 'error';
    text: string;
  } | null>(null);

  // A. CISA KEV State
  const [kevSyncing, setKevSyncing] = useState<boolean>(false);
  const [kevPersisting, setKevPersisting] = useState<boolean>(false);
  const [kevFirestoreWriteStatus, setKevFirestoreWriteStatus] = useState<string>(
    'PUBLIC READ-ONLY (Server catalog active; sign in as Admin to upsert to Firestore /kev_entries)'
  );
  const [kevCatalogVersion, setKevCatalogVersion] = useState<string | null>(null);
  const [kevDateReleased, setKevDateReleased] = useState<string | null>(null);
  const [kevLastSuccessAt, setKevLastSuccessAt] = useState<string | null>(null);
  const [kevTotalCached, setKevTotalCached] = useState<number>(0);
  const [kevKnownRansomwareCount, setKevKnownRansomwareCount] = useState<number>(0);
  const [kevTotalMatches, setKevTotalMatches] = useState<number>(0);
  const [kevRecords, setKevRecords] = useState<ParsedKevRecord[]>([]);
  const [kevSearchQuery, setKevSearchQuery] = useState<string>('');
  const [kevRansomwareFilter, setKevRansomwareFilter] = useState<string>('ALL');
  const [kevPage, setKevPage] = useState<number>(1);
  const kevPageSize = 10;
  const autoFirestoreUpsertDoneRef = useRef<boolean>(false);

  // B. NIST NVD 2.0 + D. FIRST EPSS State
  const [nvdLoading, setNvdLoading] = useState<boolean>(false);
  const [nvdPersisting, setNvdPersisting] = useState<boolean>(false);
  const [nvdCveIdInput, setNvdCveIdInput] = useState<string>('CVE-2021-44228');
  const [nvdKeywordInput, setNvdKeywordInput] = useState<string>('');
  const [nvdSearchMode, setNvdSearchMode] = useState<'cveId' | 'keyword'>('cveId');
  const [nvdStartIndex, setNvdStartIndex] = useState<number>(0);
  const nvdResultsPerPage = 10;
  const [nvdTotalResults, setNvdTotalResults] = useState<number>(0);
  const [nvdRecords, setNvdRecords] = useState<EnrichedNvdRecord[]>([]);
  const [nvdFromCache, setNvdFromCache] = useState<boolean>(false);

  // Standalone FIRST EPSS Lookup State
  const [epssInput, setEpssInput] = useState<string>('CVE-2021-44228,CVE-2024-3094');
  const [epssLoading, setEpssLoading] = useState<boolean>(false);
  const [epssResults, setEpssResults] = useState<ParsedEpssRecord[]>([]);

  // C. URLhaus State
  const [urlhausSyncing, setUrlhausSyncing] = useState<boolean>(false);
  const [urlhausStatusMsg, setUrlhausStatusMsg] = useState<string>(
    'NOT CONFIGURED: Optional community Auth-Key (URLHAUS_AUTH_KEY) is not set. Other modules operate normally.'
  );
  const [urlhausRecords, setUrlhausRecords] = useState<ParsedUrlhausRecord[]>([]);

  // Automated Parser Test Suite State
  const [parserTestResults, setParserTestResults] = useState<
    AutomatedParserTestResult[]
  >(() => runAutomatedConnectorParserTests());

  const fetchConnectorStatuses = useCallback(async () => {
    setStatusLoading(true);
    try {
      const res = await fetch('/api/connectors/status');
      const data = await res.json();
      if (data.ok) {
        setConnectors(data.connectors || []);
        setErrorLogs(data.errorLogs || []);
        if (data.kevMetadata) {
          setKevCatalogVersion(data.kevMetadata.catalogVersion);
          setKevDateReleased(data.kevMetadata.dateReleased);
          setKevTotalCached(data.kevMetadata.totalCached || 0);
          setKevKnownRansomwareCount(data.kevMetadata.knownRansomwareCount || 0);
          setKevLastSuccessAt(data.kevMetadata.lastSuccessAt || null);
        }
      }
    } catch {
      // Non-fatal
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const fetchKevRecordsPage = useCallback(
    async (page = kevPage, queryStr = kevSearchQuery, rw = kevRansomwareFilter) => {
      try {
        const params = new URLSearchParams({
          q: queryStr,
          ransomware: rw,
          page: String(page),
          pageSize: String(kevPageSize),
        });
        const res = await fetch(`/api/connectors/cisa-kev/records?${params.toString()}`);
        const data = await res.json();
        if (data.ok) {
          setKevRecords(data.records || []);
          setKevTotalCached(data.totalCached || 0);
          setKevKnownRansomwareCount(data.knownRansomwareCount || 0);
          setKevTotalMatches(data.totalMatches || 0);
          setKevCatalogVersion(data.catalogVersion || null);
          setKevDateReleased(data.dateReleased || null);
          setKevLastSuccessAt(data.lastSuccessAt || null);
        }
      } catch {
        // Non-fatal
      }
    },
    [kevPage, kevSearchQuery, kevRansomwareFilter]
  );

  // Upsert CISA KEV records by CVE ID into Cloud Firestore (/kev_entries & /data_sources)
  // Preserves createdAt on existing documents to comply with firestore.rules Pillar 2 update rules.
  const upsertKevRecordsToFirestore = useCallback(
    async (recordsToSave: ParsedKevRecord[], silent = false) => {
      if (!isLiveFirestore) {
        setKevFirestoreWriteStatus(
          'LOCAL DEMO MODE (Ephemeral memory active — switch to Cloud Firestore to persist)'
        );
        return;
      }

      if (!isAdmin || !firebaseUser) {
        setKevFirestoreWriteStatus(
          `PUBLIC READ-ONLY (${kevEntries.length} records in Firestore /kev_entries · Sign in as Admin to upsert new records)`
        );
        return;
      }

      if (recordsToSave.length === 0) return;

      setKevPersisting(true);
      try {
        const batchToSave = recordsToSave.slice(0, 10);
        let inserted = 0;
        let updated = 0;

        for (const item of batchToSave) {
          const docId = `KEV-${item.cveId}`;
          const kevRef = doc(db, 'kev_entries', docId);
          const existingSnap = await getDoc(kevRef);

          const basePayload = {
            kevId: docId,
            cveId: item.cveId,
            vendorProject: item.vendorProject.slice(0, 140),
            product: item.product.slice(0, 140),
            vulnerabilityName: item.vulnerabilityName.slice(0, 240),
            shortDescription: item.shortDescription.slice(0, 2000),
            requiredAction: item.requiredAction.slice(0, 1000),
            knownRansomwareCampaignUse: item.knownRansomwareCampaignUse,
            dateAdded: item.dateAdded.slice(0, 40),
            dueDate: item.dueDate.slice(0, 40),
            updatedAt: serverTimestamp(),
          };

          if (existingSnap.exists()) {
            const existingData = existingSnap.data();
            await setDoc(kevRef, {
              ...basePayload,
              createdAt: existingData.createdAt || serverTimestamp(),
            });
            updated++;
          } else {
            await setDoc(kevRef, {
              ...basePayload,
              createdAt: serverTimestamp(),
            });
            inserted++;
          }
        }

        // Also upsert the CISA KEV data source registry entry in /data_sources/DS-CISA-KEV
        const dsId = 'DS-CISA-KEV';
        const dsRef = doc(db, 'data_sources', dsId);
        const dsSnap = await getDoc(dsRef);
        const dsPayload = {
          sourceId: dsId,
          name: 'CISA Known Exploited Vulnerabilities (KEV) Official JSON',
          endpointUrl:
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
          sourceType: 'cisa_kev',
          isEnabled: true,
          costTier: 'FREE_PUBLIC_ZERO_COST',
          lastSyncStatus: 'SYNCED',
          updatedBy: firebaseUser.uid,
          updatedAt: serverTimestamp(),
        };

        if (dsSnap.exists()) {
          await setDoc(dsRef, {
            ...dsPayload,
            createdAt: dsSnap.data().createdAt || serverTimestamp(),
          });
        } else {
          await setDoc(dsRef, {
            ...dsPayload,
            createdAt: serverTimestamp(),
          });
        }

        await refreshCollections();
        const statusMsg = `UPSERTED TO FIRESTORE: ${batchToSave.length} records by CVE ID (${inserted} inserted, ${updated} updated in /kev_entries)`;
        setKevFirestoreWriteStatus(statusMsg);

        if (!silent) {
          setEngineFeedback({
            type: 'success',
            text: `Cloud Firestore Upsert Complete: ${statusMsg}.`,
          });
        }
      } catch (error) {
        setKevFirestoreWriteStatus(
          `FIRESTORE WRITE ERROR: ${error instanceof Error ? error.message : String(error)}`
        );
        if (!silent) {
          handleFirestoreError(error, OperationType.WRITE, 'kev_entries');
        }
      } finally {
        setKevPersisting(false);
      }
    },
    [isLiveFirestore, isAdmin, firebaseUser, kevEntries.length, refreshCollections]
  );

  useEffect(() => {
    const init = async () => {
      await fetchKevRecordsPage(1, '', 'ALL');
      await fetchConnectorStatuses();
    };
    void init();
  }, [fetchConnectorStatuses, fetchKevRecordsPage]);

  // Update Firestore status banner and auto-upsert once when Admin is signed in
  useEffect(() => {
    if (!isLiveFirestore) {
      setKevFirestoreWriteStatus(
        'LOCAL DEMO MODE (Ephemeral memory — switch to Cloud Firestore for database persistence)'
      );
      return;
    }
    if (!isAdmin || !firebaseUser) {
      setKevFirestoreWriteStatus(
        `PUBLIC READ-ONLY (${kevEntries.length} persisted records in Firestore /kev_entries · Sign in as Admin to upsert)`
      );
      return;
    }
    if (kevRecords.length > 0 && !autoFirestoreUpsertDoneRef.current) {
      autoFirestoreUpsertDoneRef.current = true;
      void upsertKevRecordsToFirestore(kevRecords, true).catch(() => {});
    }
  }, [
    isLiveFirestore,
    isAdmin,
    firebaseUser,
    kevRecords,
    kevEntries.length,
    upsertKevRecordsToFirestore,
  ]);

  // Trigger Manual CISA KEV Refresh (or simulated failure test)
  const handleManualKevSync = async (simulateFailure = false) => {
    setKevSyncing(true);
    setEngineFeedback(null);
    // Mark CISA KEV card status as SYNCING in UI immediately
    setConnectors((prev) =>
      prev.map((c) => (c.connectorId === 'cisa_kev' ? { ...c, status: 'SYNCING' } : c))
    );

    try {
      const url = simulateFailure
        ? '/api/connectors/cisa-kev/sync?simulateFailure=true'
        : '/api/connectors/cisa-kev/sync';
      const res = await fetch(url, {
        method: 'POST',
      });
      const data = await res.json();
      await fetchConnectorStatuses();

      if (data.ok) {
        setKevCatalogVersion(data.catalogVersion);
        setKevDateReleased(data.dateReleased);
        setKevTotalCached(data.totalCached);
        setKevLastSuccessAt(data.lastSuccessAt || new Date().toISOString());
        setKevPage(1);
        await fetchKevRecordsPage(1, kevSearchQuery, kevRansomwareFilter);

        if (isAdmin && isLiveFirestore && Array.isArray(data.records) && data.records.length > 0) {
          await upsertKevRecordsToFirestore(data.records, true);
        }

        setEngineFeedback({
          type: 'success',
          text: `CISA KEV Manual Refresh Complete (CONNECTED): Catalog v${data.catalogVersion} (Released ${data.dateReleased}) · ${data.totalCached} real records imported (${data.insertedCount} new, ${data.updatedCount} updated, ${data.duplicatesCollapsed} duplicates collapsed).`,
        });
      } else {
        setEngineFeedback({
          type: 'warning',
          text:
            data.error ||
            `CISA KEV refresh failed. Preserved ${data.preservedCachedCount || 0} existing records intact.`,
        });
      }
    } catch (err) {
      setEngineFeedback({
        type: 'error',
        text: `CISA KEV request error: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setKevSyncing(false);
    }
  };

  // Trigger NIST NVD API 2.0 Search / CVE ID Lookup (Works without API key)
  const handleNvdSearch = async (newStartIndex = 0) => {
    setNvdLoading(true);
    setEngineFeedback(null);
    setConnectors((prev) =>
      prev.map((c) => (c.connectorId === 'nist_nvd' ? { ...c, status: 'SYNCING' } : c))
    );

    try {
      const params = new URLSearchParams();
      if (nvdSearchMode === 'cveId') {
        params.set('cveId', nvdCveIdInput.trim().toUpperCase());
      } else {
        params.set('keyword', nvdKeywordInput.trim());
        params.set('resultsPerPage', String(nvdResultsPerPage));
        params.set('startIndex', String(newStartIndex));
      }

      const res = await fetch(`/api/connectors/nvd/search?${params.toString()}`);
      const data = await res.json();
      await fetchConnectorStatuses();

      if (data.ok) {
        setNvdRecords(data.records || []);
        setNvdTotalResults(data.totalResults || 0);
        setNvdStartIndex(data.startIndex || 0);
        setNvdFromCache(Boolean(data.fromCache));
        setEngineFeedback({
          type: 'success',
          text: `NIST NVD API 2.0 (CONNECTED · ${data.authenticatedWithKey ? 'Server API Key' : 'No API Key / Free Unauthenticated Tier'}) returned ${data.records?.length || 0} of ${data.totalResults || 0} matching CVE records (${data.fromCache ? 'Served from 10m rate-limit cache' : 'Fresh upstream response'}).`,
        });
      } else {
        if (Array.isArray(data.records) && data.records.length > 0) {
          setNvdRecords(data.records);
        }
        setEngineFeedback({
          type: 'warning',
          text: data.error || 'NVD query returned a warning; displaying preserved cache.',
        });
      }
    } catch (err) {
      setEngineFeedback({
        type: 'error',
        text: `NVD API 2.0 error: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setNvdLoading(false);
    }
  };

  // Upsert NVD CVE records into Cloud Firestore (/cves) preserving createdAt on updates
  const handlePersistNvdBatchToFirestore = async () => {
    if (!isAdmin || !isLiveFirestore || nvdRecords.length === 0) return;
    setNvdPersisting(true);
    try {
      const batchToSave = nvdRecords.slice(0, 10);
      for (const rec of batchToSave) {
        const safeSeverity =
          rec.cvss.baseSeverity === 'NONE' ? 'LOW' : rec.cvss.baseSeverity;
        const cveRef = doc(db, 'cves', rec.cveId);
        const existingSnap = await getDoc(cveRef);

        const basePayload = {
          cveId: rec.cveId,
          title: rec.title.slice(0, 240),
          description: rec.description.slice(0, 4000),
          vendor: rec.vendor.slice(0, 120),
          product: rec.product.slice(0, 120),
          severity: safeSeverity,
          cvssScore: rec.cvss.baseScore,
          cvssVector: rec.cvss.vectorString.slice(0, 128),
          source: rec.provenance.sourceName.slice(0, 100),
          publishedAt: rec.published.slice(0, 64),
          updatedAt: serverTimestamp(),
        };

        if (existingSnap.exists()) {
          await setDoc(cveRef, {
            ...basePayload,
            createdAt: existingSnap.data().createdAt || serverTimestamp(),
          });
        } else {
          await setDoc(cveRef, {
            ...basePayload,
            createdAt: serverTimestamp(),
          });
        }
      }
      await refreshCollections();
      setEngineFeedback({
        type: 'success',
        text: `Upserted ${batchToSave.length} NIST NVD records by CVE ID into Cloud Firestore (/cves).`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, 'cves');
    } finally {
      setNvdPersisting(false);
    }
  };

  // Trigger FIRST EPSS Lookup
  const handleEpssLookup = async (customCves?: string) => {
    const target = (customCves || epssInput).trim();
    if (!target) return;
    setEpssLoading(true);
    try {
      const res = await fetch(
        `/api/connectors/epss/lookup?cve=${encodeURIComponent(target)}`
      );
      const data = await res.json();
      await fetchConnectorStatuses();

      if (data.ok) {
        setEpssResults(data.records || []);
        setEngineFeedback({
          type: 'success',
          text: `FIRST EPSS (CONNECTED) retrieved 30-day exploitation probability estimates for ${data.records?.length || 0} CVE(s).`,
        });
      } else {
        setEngineFeedback({
          type: 'warning',
          text: data.error || 'FIRST EPSS lookup warning.',
        });
      }
    } catch (err) {
      setEngineFeedback({
        type: 'error',
        text: `FIRST EPSS lookup failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setEpssLoading(false);
    }
  };

  // Trigger URLhaus Connector Check / Sync
  const handleUrlhausSync = async () => {
    setUrlhausSyncing(true);
    try {
      const res = await fetch('/api/connectors/urlhaus/sync', {
        method: 'POST',
      });
      const data = await res.json();
      await fetchConnectorStatuses();

      if (data.status === 'NOT CONFIGURED') {
        setUrlhausStatusMsg(data.message);
        setEngineFeedback({
          type: 'warning',
          text: data.message,
        });
      } else if (data.ok) {
        setUrlhausRecords(data.records || []);
        setUrlhausStatusMsg(
          `CONNECTED: Synced ${data.records?.length || 0} defanged URLhaus malware indicators.`
        );
        setEngineFeedback({
          type: 'success',
          text: `URLhaus synced ${data.records?.length || 0} defanged indicators.`,
        });
      } else {
        setEngineFeedback({
          type: 'warning',
          text: data.error || 'URLhaus sync returned an error.',
        });
      }
    } catch (err) {
      setEngineFeedback({
        type: 'error',
        text: `URLhaus check error: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setUrlhausSyncing(false);
    }
  };

  const renderStatusBadge = (status: ConnectorOperationalState) => {
    if (status === 'CONNECTED') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-emerald-300 shrink-0">
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
          <span>CONNECTED</span>
        </span>
      );
    }
    if (status === 'NOT CONFIGURED') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-amber-300 shrink-0">
          <KeyRound className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>NOT CONFIGURED</span>
        </span>
      );
    }
    if (status === 'SYNCING') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-blue-300 shrink-0">
          <RefreshCw className="h-3.5 w-3.5 text-blue-400 animate-spin" aria-hidden="true" />
          <span>SYNCING</span>
        </span>
      );
    }
    if (status === 'STALE DATA') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-amber-300 shrink-0">
          <Clock className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
          <span>STALE DATA</span>
        </span>
      );
    }
    if (status === 'ERROR') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-rose-300 shrink-0">
          <AlertTriangle className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
          <span>ERROR</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-amber-300 shrink-0">
        <Unplug className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
        <span>NOT CONNECTED</span>
      </span>
    );
  };

  const showKevSection =
    moduleId === 'cisa-kev' ||
    moduleId === 'dashboard' ||
    moduleId === 'data-sources' ||
    moduleId === 'admin-center';

  const showNvdEpssSection =
    moduleId === 'cve-explorer' ||
    moduleId === 'dashboard' ||
    moduleId === 'data-sources' ||
    moduleId === 'security-advisories';

  const showUrlhausSection =
    moduleId === 'malware-intel' ||
    moduleId === 'url-inspector' ||
    moduleId === 'data-sources' ||
    moduleId === 'dashboard';

  return (
    <section
      aria-label="Free Public Threat Intelligence Connectors"
      className="space-y-6 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6"
    >
      {/* Top Header */}
      <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-blue-400">
            <Activity className="h-4 w-4" aria-hidden="true" />
            <span>FREE PUBLIC DATA ACTIVATION ($0 BUDGET · NO API KEYS REQUIRED)</span>
          </div>
          <h2 className="mt-1 text-lg font-bold text-slate-100">
            {isBn
              ? 'পাবলিক থ্রেট ইন্টেলিজেন্স ইঞ্জিন (CISA KEV · NIST NVD 2.0 · FIRST EPSS · URLhaus)'
              : 'Public Threat Intelligence Connectors (CISA KEV · NIST NVD 2.0 · FIRST EPSS · URLhaus)'}
          </h2>
        </div>

        <button
          type="button"
          onClick={() => void fetchConnectorStatuses()}
          disabled={statusLoading}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/60 hover:text-white whitespace-nowrap shrink-0"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 text-blue-400 ${statusLoading ? 'animate-spin' : ''}`}
            aria-hidden="true"
          />
          <span>Refresh Source Statuses</span>
        </button>
      </div>

      {/* Feedback Banner */}
      {engineFeedback && (
        <div
          role="status"
          className={`rounded-lg border px-4 py-3 text-xs font-mono ${
            engineFeedback.type === 'success'
              ? 'border-emerald-800/80 bg-emerald-950/50 text-emerald-200'
              : engineFeedback.type === 'warning'
              ? 'border-amber-800/80 bg-amber-950/50 text-amber-200'
              : 'border-rose-800/80 bg-rose-950/50 text-rose-200'
          }`}
        >
          {engineFeedback.text}
        </div>
      )}

      {/* 1. Standardized Connector Status & Data Provenance Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {connectors.map((conn) => (
          <div
            key={conn.connectorId}
            className="flex flex-col justify-between rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs space-y-3"
          >
            <div>
              <div className="flex items-start justify-between gap-2">
                <span className="font-mono font-semibold text-slate-100">
                  {conn.name}
                </span>
                {renderStatusBadge(conn.status)}
              </div>

              <div className="mt-1.5 font-mono text-[11px] text-slate-400 break-all">
                {conn.endpointUrl}
              </div>
            </div>

            <div className="space-y-1 border-t border-[#1E2D4A]/70 pt-2.5 text-[11px] text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-400">Imported / Cached:</span>
                <span className="font-mono font-semibold text-slate-100 tabular-nums">
                  {conn.cachedRecordCount}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Duplicates Collapsed:</span>
                <span className="font-mono tabular-nums">{conn.duplicatesCollapsed}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Successful Sync:</span>
                <span className="font-mono truncate max-w-[140px]">
                  {conn.lastSuccessAt
                    ? conn.lastSuccessAt.replace('T', ' ').slice(0, 19)
                    : 'Pending query'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Failed Sync:</span>
                <span className="font-mono truncate max-w-[140px] text-amber-300/90">
                  {conn.lastFailureAt
                    ? conn.lastFailureAt.replace('T', ' ').slice(0, 19)
                    : 'None'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Auth / Key Mode:</span>
                <span className="font-mono text-slate-300">
                  {conn.credentialEnvVar
                    ? conn.credentialConfigured
                      ? 'Optional Key Active'
                      : 'Optional (Unset)'
                    : 'No API Key Needed'}
                </span>
              </div>
            </div>

            <div className="border-t border-[#1E2D4A]/70 pt-2 text-[11px] text-slate-400">
              <div>{conn.rateLimitNote}</div>
              {conn.freshness?.warningEn && (
                <div className="mt-1 text-amber-300/90">
                  {isBn ? conn.freshness.warningBn : conn.freshness.warningEn}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* 2. Connector A: CISA KEV Official JSON Catalog Workspace */}
      {showKevSection && (
        <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
          <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-emerald-300">
                <Flame className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>CISA KNOWN EXPLOITED VULNERABILITIES (KEV) — OFFICIAL JSON FEED</span>
                <span>·</span>
                {renderStatusBadge(
                  kevSyncing
                    ? 'SYNCING'
                    : (connectors.find((c) => c.connectorId === 'cisa_kev')?.status ||
                        (kevTotalCached > 0 ? 'CONNECTED' : 'NOT CONNECTED'))
                )}
              </div>
              <h3 className="mt-1 text-base font-semibold text-slate-100">
                Active CISA KEV Catalog (No API Key Required · Upsert by CVE ID · Non-Destructive Cache)
              </h3>
              <p className="mt-0.5 text-xs text-slate-400">
                Official Source Attribution:{' '}
                <code className="text-slate-300">
                  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
                </code>{' '}
                · KIRON PROHORI is an independent platform not affiliated with CISA.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => void handleManualKevSync(false)}
                disabled={kevSyncing}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                <RefreshCw
                  className={`h-3.5 w-3.5 ${kevSyncing ? 'animate-spin' : ''}`}
                  aria-hidden="true"
                />
                <span>
                  {kevSyncing ? 'SYNCING CISA KEV...' : 'Manual Refresh CISA KEV'}
                </span>
              </button>

              <button
                type="button"
                onClick={() => void handleManualKevSync(true)}
                disabled={kevSyncing}
                title="Simulate a failed upstream API fetch to verify that existing KEV records are preserved intact and status transitions to STALE DATA"
                className="inline-flex items-center gap-1.5 rounded-lg border border-amber-700/70 bg-amber-950/30 px-3 py-2 text-xs font-medium text-amber-200 hover:border-amber-500 disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                <AlertTriangle className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
                <span>Test Failed Refresh (Preserve Cache)</span>
              </button>

              {isAdmin && isLiveFirestore && kevRecords.length > 0 && (
                <button
                  type="button"
                  onClick={() => void upsertKevRecordsToFirestore(kevRecords, false)}
                  disabled={kevPersisting}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-2 text-xs font-medium text-slate-100 hover:border-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
                >
                  <Database className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                  <span>
                    {kevPersisting
                      ? 'Upserting to Firestore...'
                      : 'Upsert Page to Firestore (/kev_entries)'}
                  </span>
                </button>
              )}
            </div>
          </div>

          {/* KEV Catalog Provenance, Sync Timestamp & Firestore Write Status Bar */}
          <div className="grid grid-cols-1 gap-3 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3.5 text-xs sm:grid-cols-2 lg:grid-cols-5">
            <div>
              <div className="text-slate-400">Catalog Version</div>
              <div className="mt-0.5 font-mono font-semibold text-blue-300">
                {kevCatalogVersion || 'Syncing...'}
              </div>
            </div>
            <div>
              <div className="text-slate-400">Catalog Date Released</div>
              <div className="mt-0.5 font-mono font-semibold text-blue-300">
                {kevDateReleased || 'Syncing...'}
              </div>
            </div>
            <div>
              <div className="text-slate-400">Real Records Imported</div>
              <div className="mt-0.5 font-mono font-semibold text-emerald-300 tabular-nums">
                {kevTotalCached} CVEs ({kevKnownRansomwareCount} Known Ransomware)
              </div>
            </div>
            <div>
              <div className="text-slate-400">Last Successful Sync</div>
              <div className="mt-0.5 font-mono text-slate-200">
                {kevLastSuccessAt
                  ? kevLastSuccessAt.replace('T', ' ').slice(0, 19) + ' UTC'
                  : 'Syncing...'}
              </div>
            </div>
            <div>
              <div className="text-slate-400">Firestore Write Status</div>
              <div className="mt-0.5 font-mono text-[11px] text-emerald-300 truncate" title={kevFirestoreWriteStatus}>
                {kevFirestoreWriteStatus}
              </div>
            </div>
          </div>

          {/* Search & Ransomware Filter Controls */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-xs text-slate-400">
              Safety Note: Absence from CISA KEV does <strong className="text-slate-200">not</strong> mean a vulnerability is safe or unexploited.
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400"
                  aria-hidden="true"
                />
                <input
                  type="text"
                  value={kevSearchQuery}
                  onChange={(e) => {
                    setKevSearchQuery(e.target.value);
                    setKevPage(1);
                    void fetchKevRecordsPage(1, e.target.value, kevRansomwareFilter);
                  }}
                  placeholder="Filter CVE, vendor, product..."
                  className="rounded-md border border-[#1E2D4A] bg-[#0E1628] py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500"
                />
              </div>

              <select
                value={kevRansomwareFilter}
                onChange={(e) => {
                  setKevRansomwareFilter(e.target.value);
                  setKevPage(1);
                  void fetchKevRecordsPage(1, kevSearchQuery, e.target.value);
                }}
                className="rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-200"
              >
                <option value="ALL">All Ransomware States</option>
                <option value="Known">Known Ransomware Use</option>
                <option value="Unknown">Unknown Ransomware Use</option>
              </select>
            </div>
          </div>

          {/* KEV Records Table */}
          {kevRecords.length === 0 ? (
            <div className="rounded border border-[#1E2D4A] bg-[#0E1628] p-6 text-center text-xs text-slate-400">
              {kevTotalCached === 0
                ? 'SYNCING official CISA KEV catalog from cisa.gov... Or click "Manual Refresh CISA KEV" above.'
                : `Empty Filter State: 0 KEV records matched filter "${kevSearchQuery}" (${kevRansomwareFilter}). Clear the filter to view all ${kevTotalCached} imported records.`}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="overflow-x-auto rounded border border-[#1E2D4A]">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#1E2D4A] bg-[#0E1628] text-slate-400">
                      <th className="px-3 py-2.5 font-medium">CVE ID</th>
                      <th className="px-3 py-2.5 font-medium">Vendor / Product</th>
                      <th className="px-3 py-2.5 font-medium">Vulnerability Name &amp; Required Action</th>
                      <th className="px-3 py-2.5 font-medium">Ransomware Campaign Usage</th>
                      <th className="px-3 py-2.5 text-right font-medium">Date Added / Due Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1E2D4A]/60 tabular-nums">
                    {kevRecords.map((item) => (
                      <tr key={item.cveId} className="hover:bg-[#141F38]/50">
                        <td className="px-3 py-2.5 font-mono font-semibold text-blue-300 whitespace-nowrap">
                          {item.cveId}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="font-medium text-slate-200">
                            {item.vendorProject}
                          </div>
                          <div className="text-[11px] text-slate-400">{item.product}</div>
                        </td>
                        <td className="px-3 py-2.5 max-w-md">
                          <div className="font-medium text-slate-100">
                            {item.vulnerabilityName}
                          </div>
                          <div className="mt-0.5 text-[11px] text-slate-400">
                            <span className="text-slate-300 font-medium">Required Action: </span>
                            {item.requiredAction}
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                            Source Attribution: {item.provenance.sourceName} (Catalog v{item.catalogVersion})
                          </div>
                        </td>
                        <td className="px-3 py-2.5 font-mono">
                          <span
                            className={
                              item.knownRansomwareCampaignUse === 'Known'
                                ? 'text-rose-300 font-semibold'
                                : 'text-slate-400'
                            }
                          >
                            {item.knownRansomwareCampaignUse}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-right font-mono text-[11px] whitespace-nowrap">
                          <div className="text-slate-200">Added: {item.dateAdded}</div>
                          <div className="text-amber-300">Due: {item.dueDate}</div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination Footer */}
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>
                  Showing {(kevPage - 1) * kevPageSize + 1}–
                  {Math.min(kevPage * kevPageSize, kevTotalMatches)} of{' '}
                  <strong className="text-slate-200 tabular-nums">{kevTotalMatches}</strong> CISA
                  KEV records
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={kevPage <= 1}
                    onClick={() => {
                      const prev = Math.max(1, kevPage - 1);
                      setKevPage(prev);
                      void fetchKevRecordsPage(prev, kevSearchQuery, kevRansomwareFilter);
                    }}
                    className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-3.5 w-3.5" />
                    <span>Prev</span>
                  </button>
                  <span className="font-mono">Page {kevPage}</span>
                  <button
                    type="button"
                    disabled={kevPage * kevPageSize >= kevTotalMatches}
                    onClick={() => {
                      const next = kevPage + 1;
                      setKevPage(next);
                      void fetchKevRecordsPage(next, kevSearchQuery, kevRansomwareFilter);
                    }}
                    className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                  >
                    <span>Next</span>
                    <ChevronRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. Connector B: NIST NVD API 2.0 & Connector D: FIRST EPSS Workspace */}
      {showNvdEpssSection && (
        <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
          <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-blue-400">
                <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                <span>
                  NIST NVD API 2.0 (NO API KEY REQUIRED) + FIRST EPSS 30-DAY ESTIMATE
                </span>
                <span>·</span>
                {renderStatusBadge(
                  nvdLoading
                    ? 'SYNCING'
                    : (connectors.find((c) => c.connectorId === 'nist_nvd')?.status || 'CONNECTED')
                )}
              </div>
              <h3 className="mt-1 text-base font-semibold text-slate-100">
                Unauthenticated Public NVD API 2.0 Connector with Rate-Limit Throttling &amp; Caching
              </h3>
              <p className="mt-0.5 text-xs text-slate-400">
                Operates without NVD_API_KEY on the free public tier (6s spacing &amp; 10m query cache). Automatically uses NVD_API_KEY on the server if later configured.
              </p>
            </div>

            {isAdmin && isLiveFirestore && nvdRecords.length > 0 && (
              <button
                type="button"
                onClick={() => void handlePersistNvdBatchToFirestore()}
                disabled={nvdPersisting}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-2 text-xs font-medium text-slate-100 hover:border-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                <Database className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                <span>
                  {nvdPersisting
                    ? 'Upserting to Firestore...'
                    : 'Upsert Results to Firestore (/cves)'}
                </span>
              </button>
            )}
          </div>

          {/* Search Controls */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void handleNvdSearch(0);
            }}
            className="flex flex-col gap-3 sm:flex-row sm:items-end"
          >
            <div>
              <label className="block text-xs text-slate-300 mb-1">Query Mode</label>
              <div className="flex rounded-md border border-[#1E2D4A] bg-[#0E1628] p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setNvdSearchMode('cveId')}
                  className={`rounded px-3 py-1 font-medium ${
                    nvdSearchMode === 'cveId'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-300 hover:text-white'
                  }`}
                >
                  Exact CVE ID
                </button>
                <button
                  type="button"
                  onClick={() => setNvdSearchMode('keyword')}
                  className={`rounded px-3 py-1 font-medium ${
                    nvdSearchMode === 'keyword'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-300 hover:text-white'
                  }`}
                >
                  Keyword Search
                </button>
              </div>
            </div>

            {nvdSearchMode === 'cveId' ? (
              <div className="flex-1">
                <label className="block text-xs text-slate-300 mb-1">
                  CVE Identifier (e.g., CVE-2021-44228, CVE-2024-3094, CVE-2023-4863)
                </label>
                <input
                  type="text"
                  value={nvdCveIdInput}
                  onChange={(e) => setNvdCveIdInput(e.target.value)}
                  placeholder="CVE-YYYY-NNNN..."
                  required
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 font-mono text-xs text-slate-100"
                />
              </div>
            ) : (
              <div className="flex-1">
                <label className="block text-xs text-slate-300 mb-1">
                  Vendor, Product, or Vulnerability Keyword
                </label>
                <input
                  type="text"
                  value={nvdKeywordInput}
                  onChange={(e) => setNvdKeywordInput(e.target.value)}
                  placeholder="e.g. openssh / apache / fortinet / Ivanti"
                  required
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-xs text-slate-100"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={nvdLoading}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
            >
              <Search className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{nvdLoading ? 'SYNCING NIST NVD 2.0...' : 'Query NIST NVD 2.0'}</span>
            </button>
          </form>

          {/* NVD Results List */}
          {nvdRecords.length > 0 && (
            <div className="space-y-4 pt-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                <span>
                  Total Matching NVD Records:{' '}
                  <strong className="text-slate-100 tabular-nums">{nvdTotalResults}</strong>{' '}
                  {nvdFromCache && '(Served from Rate-Limit Cache)'}
                </span>

                {nvdSearchMode === 'keyword' && nvdTotalResults > nvdResultsPerPage && (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={nvdLoading || nvdStartIndex <= 0}
                      onClick={() =>
                        void handleNvdSearch(Math.max(0, nvdStartIndex - nvdResultsPerPage))
                      }
                      className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                    >
                      Previous Page
                    </button>
                    <span className="font-mono">
                      Start Index: {nvdStartIndex}
                    </span>
                    <button
                      type="button"
                      disabled={
                        nvdLoading || nvdStartIndex + nvdResultsPerPage >= nvdTotalResults
                      }
                      onClick={() =>
                        void handleNvdSearch(nvdStartIndex + nvdResultsPerPage)
                      }
                      className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1 text-slate-200 disabled:opacity-40"
                    >
                      Next Page
                    </button>
                  </div>
                )}
              </div>

              {nvdRecords.map((rec) => (
                <div
                  key={rec.cveId}
                  className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3 text-xs"
                >
                  {/* Row 1: CVE ID, CVSS Score, Published & Last Modified */}
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E2D4A] pb-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-bold text-blue-300">
                        {rec.cveId}
                      </span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span
                        className={`font-mono font-semibold ${
                          rec.cvss.baseSeverity === 'CRITICAL'
                            ? 'text-rose-300'
                            : rec.cvss.baseSeverity === 'HIGH'
                            ? 'text-amber-300'
                            : 'text-blue-300'
                        }`}
                      >
                        CVSS v{rec.cvss.version}: {rec.cvss.baseScore.toFixed(1)} (
                        {rec.cvss.baseSeverity})
                      </span>
                      <span aria-hidden="true" className="text-slate-600">·</span>
                      <span className="font-mono text-slate-400">
                        CWE: {rec.cwes.length > 0 ? rec.cwes.join(', ') : 'Not Specified'}
                      </span>
                    </div>

                    <div className="font-mono text-[11px] text-slate-400">
                      Published: {rec.published.slice(0, 10)} · Modified:{' '}
                      {rec.lastModified.slice(0, 10)}
                    </div>
                  </div>

                  {/* Description */}
                  <p className="leading-relaxed text-slate-200">{rec.description}</p>

                  {/* Mandatory KEV Safety Notice & FIRST EPSS 30-Day Estimate Bar */}
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    {/* CISA KEV Cross-Check (Never labels non-KEV CVEs as "safe"!) */}
                    <div
                      className={`rounded border p-3 ${
                        rec.kevRecord
                          ? 'border-rose-800/80 bg-rose-950/40 text-rose-200'
                          : 'border-amber-800/70 bg-amber-950/30 text-amber-200'
                      }`}
                    >
                      <div className="font-semibold">
                        {rec.kevRecord
                          ? 'Listed in CISA KEV (Confirmed Active Exploitation)'
                          : 'CISA KEV Status & Safety Advisory'}
                      </div>
                      <p className="mt-1 text-[11px] leading-relaxed">
                        {rec.kevSafetyWarning}
                      </p>
                      {rec.kevRecord && (
                        <div className="mt-1 font-mono text-[11px]">
                          Added: {rec.kevRecord.dateAdded} · Due: {rec.kevRecord.dueDate} ·
                          Ransomware: {rec.kevRecord.knownRansomwareCampaignUse}
                        </div>
                      )}
                    </div>

                    {/* FIRST EPSS 30-Day Exploitation Probability Estimate */}
                    <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">
                          FIRST EPSS (30-Day Exploitation Estimate)
                        </span>
                        {rec.epssRecord ? (
                          <span className="font-mono font-bold text-blue-300 tabular-nums">
                            {rec.epssRecord.epssPercentage} ({rec.epssRecord.percentilePercentage}{' '}
                            pct)
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void handleEpssLookup(rec.cveId)}
                            className="font-mono text-[11px] text-blue-400 hover:underline"
                          >
                            Fetch EPSS Estimate
                          </button>
                        )}
                      </div>
                      <p className="mt-1 text-[11px] text-slate-400">
                        {rec.epssRecord
                          ? rec.epssRecord.estimateDisclaimer
                          : 'Estimated probability of exploitation in the next 30 days (FIRST.org statistical model — not a certainty).'}
                      </p>
                    </div>
                  </div>

                  {/* CVSS Vector, Affected Configurations (CPE) & Official References */}
                  <div className="space-y-1.5 border-t border-[#1E2D4A]/70 pt-2.5 text-[11px] text-slate-400">
                    <div className="font-mono text-slate-300">
                      Vector: {rec.cvss.vectorString}
                      {rec.cvss.exploitabilityScore !== null &&
                        ` · Exploitability: ${rec.cvss.exploitabilityScore} · Impact: ${rec.cvss.impactScore}`}
                    </div>

                    {rec.affectedConfigurations.length > 0 && (
                      <div className="font-mono text-slate-400 truncate">
                        Affected CPE ({rec.affectedConfigurations.length}):{' '}
                        {rec.affectedConfigurations.slice(0, 2).join(' | ')}
                      </div>
                    )}

                    {rec.references.length > 0 && (
                      <div className="flex flex-wrap items-center gap-3 pt-1">
                        <span className="font-medium text-slate-300">References:</span>
                        {rec.references.slice(0, 3).map((ref, idx) => (
                          <a
                            key={idx}
                            href={ref.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            referrerPolicy="no-referrer"
                            className="inline-flex items-center gap-1 font-mono text-blue-400 hover:underline"
                          >
                            <span>{ref.source}</span>
                            <ExternalLink className="h-3 w-3" aria-hidden="true" />
                          </a>
                        ))}
                      </div>
                    )}

                    <div className="font-mono text-[10px] text-slate-500">
                      Provenance: {rec.provenance.sourceName} · {rec.provenance.sourceUrl} ·
                      Retrieved {rec.provenance.retrievedAt}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Direct FIRST EPSS Batch Lookup Box */}
          <div className="border-t border-[#1E2D4A] pt-4">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleEpssLookup();
              }}
              className="flex flex-col gap-2.5 sm:flex-row sm:items-end"
            >
              <div className="flex-1">
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Direct FIRST EPSS Batch Lookup (Comma-separated CVE IDs · No API Key Required)
                </label>
                <input
                  type="text"
                  value={epssInput}
                  onChange={(e) => setEpssInput(e.target.value)}
                  placeholder="CVE-2021-44228,CVE-2024-3094"
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 font-mono text-xs text-slate-200"
                />
              </div>
              <button
                type="submit"
                disabled={epssLoading}
                className="rounded-lg border border-[#1E2D4A] bg-[#141F38] px-4 py-2 text-xs font-medium text-slate-100 hover:border-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
              >
                {epssLoading ? 'SYNCING FIRST EPSS...' : 'Lookup 30-Day EPSS Probability'}
              </button>
            </form>

            {epssResults.length > 0 && (
              <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                {epssResults.map((ep) => (
                  <div
                    key={ep.cveId}
                    className="rounded border border-[#1E2D4A] bg-[#0E1628] p-3 text-xs"
                  >
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-bold text-blue-300">{ep.cveId}</span>
                      <span className="font-semibold text-emerald-300">
                        30-Day Est: {ep.epssPercentage} ({ep.percentilePercentage} percentile)
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-400">
                      {ep.estimateDisclaimer} (Model Date: {ep.modelDate})
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 4. Connector C: Keyless abuse.ch Feodo Tracker & Optional URLhaus Connector */}
      {showUrlhausSection && (
        <div className="space-y-4">
          <div className="rounded-lg border border-emerald-500/30 bg-[#080D1A] p-5 space-y-2">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-emerald-300">
                  <ShieldAlert className="h-4 w-4" aria-hidden="true" />
                  <span>ABUSE.CH FEODO TRACKER BOTNET C2 BLOCKLIST (KEYLESS CC0 PUBLIC FEED)</span>
                  <span>·</span>
                  {renderStatusBadge(
                    connectors.find((c) => c.connectorId === 'feodo_tracker')?.status ||
                      'CONNECTED'
                  )}
                </div>
                <h3 className="mt-1 text-base font-semibold text-slate-100">
                  Authorized Keyless Malware C2 Feed (Emotet · QakBot · Pikabot · TrickBot)
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">
                  {connectors.find((c) => c.connectorId === 'feodo_tracker')?.rateLimitNote ||
                    'Connected to https://feodotracker.abuse.ch/downloads/ipblocklist.json (CC0 1.0 Public Domain · No API Key Required).'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => void fetchConnectorStatuses()}
                className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-3.5 py-2 text-xs font-medium text-emerald-200 hover:border-emerald-400 whitespace-nowrap shrink-0"
              >
                <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Refresh Feodo C2 Status</span>
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-3">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-amber-300">
                  <KeyRound className="h-4 w-4" aria-hidden="true" />
                  <span>ABUSE.CH URLHAUS MALWARE URL FEED (OPTIONAL COMMUNITY AUTH-KEY)</span>
                  <span>·</span>
                  {renderStatusBadge(
                    urlhausSyncing
                      ? 'SYNCING'
                      : (connectors.find((c) => c.connectorId === 'urlhaus')?.status ||
                          'NOT CONFIGURED')
                  )}
                </div>
                <h3 className="mt-1 text-base font-semibold text-slate-100">
                  Optional URLhaus Connector (Never Blocks Other Modules · Never Invents Credentials)
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">{urlhausStatusMsg}</p>
              </div>

            <button
              type="button"
              onClick={() => void handleUrlhausSync()}
              disabled={urlhausSyncing}
              className="inline-flex items-center gap-2 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-2 text-xs font-medium text-slate-200 hover:border-blue-500 whitespace-nowrap shrink-0"
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${urlhausSyncing ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
              <span>Check URLhaus Status</span>
            </button>
          </div>

          {urlhausRecords.length > 0 && (
            <div className="overflow-x-auto rounded border border-[#1E2D4A]">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-[#1E2D4A] bg-[#0E1628] text-slate-400">
                    <th className="px-3 py-2">Defanged URL (Safe Text)</th>
                    <th className="px-3 py-2">Threat / Tags</th>
                    <th className="px-3 py-2 text-right">Date Added</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1E2D4A]/60 font-mono">
                  {urlhausRecords.map((u) => (
                    <tr key={u.indicatorId}>
                      <td className="px-3 py-2 text-blue-300">{u.defangedUrl}</td>
                      <td className="px-3 py-2 text-slate-300">
                        {u.threat} ({u.tags.join(', ')})
                      </td>
                      <td className="px-3 py-2 text-right text-slate-400">
                        {u.dateAdded}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          </div>
        </div>
      )}

      {/* 5. Automated Parsing, Schema Validation & Non-Destructive Cache Test Suite */}
      <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
        <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs text-emerald-300">
              <FileCode2 className="h-4 w-4" aria-hidden="true" />
              <span>AUTOMATED PARSER, VALIDATOR &amp; NON-DESTRUCTIVE CACHE TEST SUITE</span>
            </div>
            <p className="mt-0.5 text-xs text-slate-400">
              Verifies CISA KEV JSON schema validation, CVE ID upsert deduplication, URL defanging, 30-day EPSS disclaimers, and cache preservation on error.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setParserTestResults(runAutomatedConnectorParserTests())}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-blue-500 whitespace-nowrap shrink-0"
          >
            <Play className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Re-Run Automated Parser Tests (6 / 6)</span>
          </button>
        </div>

        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
          {parserTestResults.map((tr) => (
            <div
              key={tr.id}
              className="flex items-start gap-2.5 rounded border border-[#1E2D4A] bg-[#0E1628] p-3 text-xs"
            >
              <CheckCircle2
                className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400"
                aria-hidden="true"
              />
              <div>
                <div className="font-semibold text-slate-100">
                  [{tr.connector}] {tr.testName}
                </div>
                <div className="mt-1 font-mono text-[11px] text-emerald-300">
                  {tr.details}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Non-Destructive Connector Error Logs */}
        {errorLogs.length > 0 && (
          <div className="space-y-1.5 border-t border-[#1E2D4A] pt-3">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-300">
              <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Connector Error Logs (Non-Destructive Cache Fallback Active)</span>
            </div>
            {errorLogs.slice(0, 5).map((log) => (
              <div
                key={log.id}
                className="rounded border border-amber-800/50 bg-[#0E1628] px-3 py-2 font-mono text-[11px] text-amber-200"
              >
                [{log.timestamp}] {log.connectorId}: {log.errorMessage} (Preserved{' '}
                {log.preservedCachedCount} cached records)
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
};
