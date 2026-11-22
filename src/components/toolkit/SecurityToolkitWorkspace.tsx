import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Link2,
  FileDigit,
  ClipboardCheck,
  BookmarkCheck,
  Bell,
  FileText,
  Settings,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Download,
  Trash2,
  Plus,
  Search,
  Lock,
  Eye,
  Upload,
  RefreshCw,
  Sun,
  Moon,
  Globe,
  UserCheck,
  FlaskConical,
  ExternalLink,
  Copy,
} from 'lucide-react';
import { RouteId } from '../../types/navigation';
import { useApp } from '../../context/AppContext';
import { useSecurity } from '../../context/SecurityContext';
import { ParsedKevRecord } from '../../connectors/parsers';
import {
  inspectUrlSafely,
  SafeUrlInspectionReport,
  validateCryptographicHashFormat,
  computeSha256HexFromBytes,
  SECURITY_CHECKLIST_TRACKS,
  SecurityChecklistTrackId,
  calculateChecklistProgress,
  buildPersonalizedWatchlistDashboard,
  filterNotifications,
  MANDATORY_REPORT_DISCLAIMER,
  generateReportCsv,
  generateValidPdfDocument,
  DefensiveReportPayload,
} from '../../toolkit/engine';
import {
  runSecurityToolkitTests,
  ToolkitTestResult,
} from '../../toolkit/toolkit.test';

interface SecurityToolkitWorkspaceProps {
  moduleId: RouteId;
}

const CHECKLIST_STORAGE_KEY = 'kiron_prohori_checklist_v1';

const TOOLKIT_MODULES = new Set<RouteId>([
  'dashboard',
  'url-inspector',
  'hash-lookup',
  'security-checklist',
  'my-watchlist',
  'notifications',
  'report-center',
  'settings',
  'help-docs',
]);

export const SecurityToolkitWorkspace: React.FC<SecurityToolkitWorkspaceProps> = ({
  moduleId,
}) => {
  const {
    language,
    setLanguage,
    themePreference,
    setThemePreference,
    setActiveRoute,
  } = useApp();
  const {
    persistenceMode,
    isSignedIn,
    userProfile,
    authoritativeRole,
    watchlists,
    notifications,
    cves,
    threatIndicators,
    approvedScamReports,
    addWatchlistItem,
    deleteWatchlistItem,
    markNotificationRead,
    markAllNotificationsRead,
    createInAppNotification,
    updateUserProfile,
    signInWithGoogle,
  } = useSecurity();

  const isBn = language === 'bn';

  // Active tab automatically syncs with moduleId
  const [activeTab, setActiveTab] = useState<
    | 'url'
    | 'hash'
    | 'checklist'
    | 'watchlist'
    | 'notifications'
    | 'reports'
    | 'preferences'
  >(() => {
    if (moduleId === 'url-inspector') return 'url';
    if (moduleId === 'hash-lookup') return 'hash';
    if (moduleId === 'security-checklist') return 'checklist';
    if (moduleId === 'my-watchlist' || moduleId === 'dashboard') return 'watchlist';
    if (moduleId === 'notifications') return 'notifications';
    if (moduleId === 'report-center') return 'reports';
    return 'preferences';
  });

  useEffect(() => {
    if (moduleId === 'url-inspector') setActiveTab('url');
    else if (moduleId === 'hash-lookup') setActiveTab('hash');
    else if (moduleId === 'security-checklist') setActiveTab('checklist');
    else if (moduleId === 'my-watchlist' || moduleId === 'dashboard')
      setActiveTab('watchlist');
    else if (moduleId === 'notifications') setActiveTab('notifications');
    else if (moduleId === 'report-center') setActiveTab('reports');
    else if (moduleId === 'settings' || moduleId === 'help-docs')
      setActiveTab('preferences');
  }, [moduleId]);

  // =========================================================================
  // LIVE CISA KEV RECORDS FOR PERSONALIZED WATCHLIST DASHBOARD & REPORTS
  // =========================================================================
  const [liveKevRecords, setLiveKevRecords] = useState<ParsedKevRecord[]>([]);
  const [kevLastUpdated, setKevLastUpdated] = useState<string>('');

  const fetchKevSnapshotForWatchlist = useCallback(async () => {
    try {
      const res = await fetch('/api/connectors/cisa-kev/records?limit=150');
      const data = await res.json();
      if (res.ok && data.ok && Array.isArray(data.records)) {
        setLiveKevRecords(data.records);
        setKevLastUpdated(data.lastSuccessAt || new Date().toISOString());
      }
    } catch {
      // Non-fatal fallback
    }
  }, []);

  useEffect(() => {
    if (TOOLKIT_MODULES.has(moduleId)) {
      void fetchKevSnapshotForWatchlist();
    }
  }, [moduleId, fetchKevSnapshotForWatchlist]);

  // =========================================================================
  // 1. URL INSPECTOR STATE
  // =========================================================================
  const [urlInput, setUrlInput] = useState<string>(
    'http://admin@login-verify-portal.example.com.bd:8080/auth/update.exe?token=secret999&redirect=https://example.org'
  );
  const [urlExternalConsent, setUrlExternalConsent] = useState<boolean>(false);
  const [urlReport, setUrlReport] = useState<SafeUrlInspectionReport | null>(
    null
  );
  const [copiedTextMessage, setCopiedTextMessage] = useState<string | null>(
    null
  );

  const configuredFeedIndicators = useMemo(() => {
    const list: {
      sourceName: string;
      indicatorId: string;
      defangedOrRawValue: string;
      categoryOrThreat: string;
      lastUpdatedAt: string;
      verificationStatus: string;
    }[] = [];

    for (const r of approvedScamReports) {
      list.push({
        sourceName: 'Verified Community Scam Reports (Cloud Firestore)',
        indicatorId: r.reportId,
        defangedOrRawValue: r.defangedIndicator,
        categoryOrThreat: r.category,
        lastUpdatedAt: r.updatedAt,
        verificationStatus: r.moderationStatus,
      });
    }
    for (const ind of threatIndicators) {
      list.push({
        sourceName: ind.source || 'Authorized Firestore Threat Feed',
        indicatorId: ind.indicatorId,
        defangedOrRawValue: ind.defangedValue,
        categoryOrThreat: ind.malwareFamily,
        lastUpdatedAt: ind.updatedAt,
        verificationStatus: 'verified',
      });
    }
    return list;
  }, [approvedScamReports, threatIndicators]);

  const handleRunUrlInspection = useCallback(
    (e?: React.FormEvent) => {
      if (e) e.preventDefault();
      const result = inspectUrlSafely(urlInput, {
        configuredIndicators: configuredFeedIndicators,
        externalConsentGranted: urlExternalConsent,
        intelligenceLastUpdatedAt:
          kevLastUpdated || new Date().toISOString(),
      });
      setUrlReport(result);
    },
    [urlInput, configuredFeedIndicators, urlExternalConsent, kevLastUpdated]
  );

  useEffect(() => {
    if (!urlReport) {
      handleRunUrlInspection();
    }
  }, [urlReport, handleRunUrlInspection]);

  // =========================================================================
  // 2. HASH TOOL STATE (WEB CRYPTO SHA-256 + ZERO UPLOAD)
  // =========================================================================
  const [hashInput, setHashInput] = useState<string>(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  const [textToHashInput, setTextToHashInput] = useState<string>('');
  const [localFileMeta, setLocalFileMeta] = useState<{
    name: string;
    sizeBytes: number;
    computedSha256: string;
    computedAt: string;
  } | null>(null);
  const [isComputingFileHash, setIsComputingFileHash] =
    useState<boolean>(false);
  const [hashLookupConsent, setHashLookupConsent] = useState<boolean>(true);
  const [isLookingUpHash, setIsLookingUpHash] = useState<boolean>(false);
  const [hashLookupResult, setHashLookupResult] = useState<{
    queriedHash: string;
    verdict: 'KNOWN_THREAT_INDICATOR' | 'KNOWN_PUBLIC_REFERENCE' | 'UNKNOWN';
    localMatchesCount: number;
    circlFound: boolean;
    circlFileName?: string;
    circlFileSize?: string;
    sourceName: string;
    sourceUrl: string;
    checkedAt: string;
    message: string;
  } | null>(null);

  const hashFormatValidation = useMemo(
    () => validateCryptographicHashFormat(hashInput),
    [hashInput]
  );

  const handleLocalFileSelect = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsComputingFileHash(true);
    try {
      const arrayBuffer = await file.arrayBuffer();
      const sha256Hex = await computeSha256HexFromBytes(arrayBuffer);
      setLocalFileMeta({
        name: file.name,
        sizeBytes: file.size,
        computedSha256: sha256Hex,
        computedAt: new Date().toISOString(),
      });
      setHashInput(sha256Hex);
    } catch {
      // Handle read error
    } finally {
      setIsComputingFileHash(false);
    }
  };

  const handleComputeTextSha256 = async () => {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(textToHashInput);
    const sha256Hex = await computeSha256HexFromBytes(bytes);
    setHashInput(sha256Hex);
    setLocalFileMeta({
      name: `Text Buffer (${bytes.byteLength} bytes)`,
      sizeBytes: bytes.byteLength,
      computedSha256: sha256Hex,
      computedAt: new Date().toISOString(),
    });
  };

  const handleRunHashReputationLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!hashFormatValidation.isValid) return;

    const targetHash = hashFormatValidation.normalizedHash;
    setIsLookingUpHash(true);

    // 1. Check local authorized Firestore threat indicators
    const localHits = threatIndicators.filter(
      (ind) => ind.defangedValue.trim().toLowerCase() === targetHash
    );

    if (!hashLookupConsent || hashFormatValidation.algorithm !== 'SHA-256') {
      setHashLookupResult({
        queriedHash: targetHash,
        verdict: localHits.length > 0 ? 'KNOWN_THREAT_INDICATOR' : 'UNKNOWN',
        localMatchesCount: localHits.length,
        circlFound: false,
        sourceName:
          'KIRON PROHORI Verified Threat Indicators (Local Firestore Catalog Only)',
        sourceUrl: 'https://hashlookup.circl.lu/',
        checkedAt: new Date().toISOString(),
        message:
          localHits.length > 0
            ? `Matched ${localHits.length} authorized threat indicator(s) in local database.`
            : 'VERDICT: UNKNOWN (NOT SAFE). No match in local threat indicators. External public CIRCL lookup was skipped.',
      });
      setIsLookingUpHash(false);
      return;
    }

    // 2. Authorized public CIRCL Hashlookup query (hash digest only, never uploading files!)
    try {
      const res = await fetch(
        `/api/intelligence/sha256/lookup?sha256=${encodeURIComponent(targetHash)}`
      );
      const data = await res.json();
      const circlFound = Boolean(res.ok && data.ok && data.foundInCircl);

      setHashLookupResult({
        queriedHash: targetHash,
        verdict:
          localHits.length > 0
            ? 'KNOWN_THREAT_INDICATOR'
            : circlFound
            ? 'KNOWN_PUBLIC_REFERENCE'
            : 'UNKNOWN',
        localMatchesCount: localHits.length,
        circlFound,
        circlFileName: data.metadata?.fileName,
        circlFileSize: data.metadata?.fileSize,
        sourceName:
          data.sourceName ||
          'CIRCL Public Hashlookup Service (hashlookup.circl.lu) + Firestore Feed',
        sourceUrl:
          data.sourceUrl ||
          `https://hashlookup.circl.lu/lookup/sha256/${targetHash}`,
        checkedAt: data.retrievedAt || new Date().toISOString(),
        message:
          localHits.length > 0
            ? `ALERT: Matched ${localHits.length} authorized malware indicator(s) in Firestore.`
            : circlFound
            ? `Found in CIRCL Public Hashlookup reference database (${data.metadata?.fileName || 'Known Reference Digest'}).`
            : 'VERDICT: UNKNOWN (NOT GUARANTEED SAFE). Digest was not found in local threat indicators or CIRCL Hashlookup. No file was uploaded.',
      });
    } catch {
      setHashLookupResult({
        queriedHash: targetHash,
        verdict: localHits.length > 0 ? 'KNOWN_THREAT_INDICATOR' : 'UNKNOWN',
        localMatchesCount: localHits.length,
        circlFound: false,
        sourceName: 'Local Firestore Threat Indicators',
        sourceUrl: 'https://hashlookup.circl.lu/',
        checkedAt: new Date().toISOString(),
        message:
          'VERDICT: UNKNOWN. Evaluated against local threat indicators only.',
      });
    } finally {
      setIsLookingUpHash(false);
    }
  };

  // =========================================================================
  // 3. SECURITY CHECKLIST STATE (6 MANDATORY TRACKS)
  // =========================================================================
  const [completedChecklistIds, setCompletedChecklistIds] = useState<string[]>(
    () => {
      try {
        const raw = localStorage.getItem(CHECKLIST_STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) return parsed.filter((x) => typeof x === 'string');
        }
      } catch {
        // Ignore storage error
      }
      return ['acct_recovery_audit', 'pm_unique_passwords', 'mfa_totp_or_passkey'];
    }
  );
  const [selectedTrackFilter, setSelectedTrackFilter] = useState<
    'ALL' | SecurityChecklistTrackId
  >('ALL');
  const [checklistPriorityFilter, setChecklistPriorityFilter] = useState<
    'ALL' | 'ESSENTIAL' | 'RECOMMENDED'
  >('ALL');

  const toggleChecklistItem = (itemId: string) => {
    setCompletedChecklistIds((prev) => {
      const exists = prev.includes(itemId);
      const next = exists ? prev.filter((id) => id !== itemId) : [...prev, itemId];
      try {
        localStorage.setItem(CHECKLIST_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore storage error
      }
      return next;
    });
  };

  const checklistProgress = useMemo(
    () => calculateChecklistProgress(completedChecklistIds),
    [completedChecklistIds]
  );

  // =========================================================================
  // 4. WATCHLIST & PERSONALIZED DASHBOARD STATE
  // =========================================================================
  const [wlItemType, setWlItemType] =
    useState<'cve_id' | 'vendor_keyword' | 'product_cpe' | 'domain_pattern'>(
      'cve_id'
    );
  const [wlTargetValue, setWlTargetValue] = useState<string>('');
  const [wlNotes, setWlNotes] = useState<string>('');
  const [wlSeverityFilter, setWlSeverityFilter] = useState<
    'ALL' | 'MEDIUM_PLUS' | 'HIGH_PLUS' | 'CRITICAL_ONLY'
  >('ALL');

  const personalizedDashboard = useMemo(
    () =>
      buildPersonalizedWatchlistDashboard(watchlists, liveKevRecords, cves),
    [watchlists, liveKevRecords, cves]
  );

  const handleAddWatchlistSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!wlTargetValue.trim()) return;
    await addWatchlistItem(
      wlItemType,
      wlTargetValue.trim(),
      wlNotes.trim(),
      wlSeverityFilter
    );
    setWlTargetValue('');
    setWlNotes('');
  };

  const handleGenerateWatchlistNotification = async () => {
    if (personalizedDashboard.matches.length === 0) {
      await createInAppNotification(
        'Watchlist Status Check Completed',
        `Evaluated ${personalizedDashboard.totalWatchlistItems} saved watchlist item(s) against ${liveKevRecords.length} CISA KEV entries and ${cves.length} Firestore CVE records. 0 active matches found.`,
        'watchlist_match'
      );
      return;
    }
    const topMatch = personalizedDashboard.matches[0];
    await createInAppNotification(
      `Watchlist Alert: ${personalizedDashboard.totalCatalogMatches} Catalog Match(es) (${topMatch.matchedCveId})`,
      `Your followed ${topMatch.itemType} "${topMatch.targetValue}" matched ${topMatch.matchedCveId} (${topMatch.matchedVendor} ${topMatch.matchedProduct}). Action: ${topMatch.requiredAction}`,
      'watchlist_match'
    );
  };

  // =========================================================================
  // 5. IN-APP NOTIFICATIONS STATE
  // =========================================================================
  const [notifCategoryFilter, setNotifCategoryFilter] = useState<
    'ALL' | 'watchlist_match' | 'moderation_update' | 'security_notice' | 'system'
  >('ALL');
  const [notifReadFilter, setNotifReadFilter] = useState<
    'ALL' | 'UNREAD' | 'READ'
  >('ALL');
  const [notifSearchQuery, setNotifSearchQuery] = useState<string>('');

  const filteredNotifications = useMemo(
    () =>
      filterNotifications(notifications, {
        categoryFilter: notifCategoryFilter,
        readStatusFilter: notifReadFilter,
        searchQuery: notifSearchQuery,
      }),
    [notifications, notifCategoryFilter, notifReadFilter, notifSearchQuery]
  );

  const unreadNotificationsCount = useMemo(
    () => notifications.filter((n) => !n.isRead).length,
    [notifications]
  );

  // =========================================================================
  // 6. REPORT CENTER STATE (CSV & PDF 1.4 DOWNLOAD)
  // =========================================================================
  const [reportScope, setReportScope] = useState<
    'watchlist_and_checklist' | 'cisa_kev_top' | 'checklist_only' | 'verified_scams'
  >('watchlist_and_checklist');
  const [reportTitleInput, setReportTitleInput] = useState<string>(
    'KIRON PROHORI — Defensive Security & Threat Intelligence Report'
  );
  const [lastGeneratedReportMeta, setLastGeneratedReportMeta] = useState<{
    format: 'CSV' | 'PDF';
    fileName: string;
    rowCount: number;
    generatedAt: string;
  } | null>(null);

  const currentReportPayload: DefensiveReportPayload = useMemo(() => {
    const nowIso = new Date().toISOString();
    const preparedBy = userProfile?.displayName || 'Independent Analyst';
    const organization = userProfile?.organization || 'Independent Defender';
    const rows: DefensiveReportPayload['rows'] = [];

    if (
      reportScope === 'watchlist_and_checklist' ||
      reportScope === 'checklist_only'
    ) {
      for (const track of SECURITY_CHECKLIST_TRACKS) {
        for (const item of track.items) {
          const isDone = completedChecklistIds.includes(item.id);
          rows.push({
            recordId: item.id.toUpperCase(),
            category: track.titleEn,
            subject: item.titleEn,
            statusOrSeverity: isDone
              ? `COMPLETED (${item.priority})`
              : `PENDING (${item.priority})`,
            requiredActionOrNote: item.verificationAction,
            sourceAttribution: 'KIRON PROHORI 6-Track Defensive Checklist',
            referenceDate: nowIso.slice(0, 10),
          });
        }
      }
    }

    if (reportScope === 'watchlist_and_checklist') {
      for (const m of personalizedDashboard.matches) {
        rows.push({
          recordId: m.matchedCveId,
          category: `Watchlist Match (${m.targetValue})`,
          subject: `${m.matchedVendor} ${m.matchedProduct} — ${m.titleOrVulnerabilityName}`,
          statusOrSeverity: m.severity,
          requiredActionOrNote: m.requiredAction,
          sourceAttribution: m.sourceAttribution,
          referenceDate: m.dueDate,
        });
      }
    }

    if (reportScope === 'cisa_kev_top') {
      for (const kev of liveKevRecords.slice(0, 20)) {
        rows.push({
          recordId: kev.cveId,
          category: 'CISA KEV Catalog',
          subject: `${kev.vendorProject} ${kev.product} — ${kev.vulnerabilityName}`,
          statusOrSeverity: `Ransomware Use: ${kev.knownRansomwareCampaignUse} (Unknown != No)`,
          requiredActionOrNote: kev.requiredAction,
          sourceAttribution:
            'CISA Known Exploited Vulnerabilities Public JSON Feed',
          referenceDate: kev.dateAdded,
        });
      }
    }

    if (reportScope === 'verified_scams') {
      for (const scam of approvedScamReports) {
        rows.push({
          recordId: scam.reportId,
          category: `Scam / Phishing (${scam.category})`,
          subject: `${scam.title} (${scam.defangedIndicator})`,
          statusOrSeverity: 'MODERATOR APPROVED',
          requiredActionOrNote: scam.description,
          sourceAttribution:
            'KIRON PROHORI Moderated Community Scam Reports (Firestore)',
          referenceDate: scam.createdAt.slice(0, 10),
        });
      }
    }

    return {
      reportTitle:
        reportTitleInput.trim() ||
        'KIRON PROHORI Defensive Threat Intelligence Report',
      generatedAtIso: nowIso,
      preparedBy,
      organization,
      sourceReferences: [
        'CISA Known Exploited Vulnerabilities (KEV) Public JSON Catalog (cisa.gov)',
        'NIST National Vulnerability Database (NVD) API 2.0 (nvd.nist.gov)',
        'CIRCL Public Hashlookup Service (hashlookup.circl.lu)',
        'KIRON PROHORI 6-Track Security Hardening Checklist & Firestore Watchlist',
      ],
      disclaimer: MANDATORY_REPORT_DISCLAIMER,
      checklistSummary: {
        completedItems: checklistProgress.completedItems,
        totalItems: checklistProgress.totalItems,
        completionPercentage: checklistProgress.completionPercentage,
      },
      rows,
    };
  }, [
    reportScope,
    reportTitleInput,
    userProfile,
    completedChecklistIds,
    personalizedDashboard.matches,
    liveKevRecords,
    approvedScamReports,
    checklistProgress,
  ]);

  const handleDownloadCsvReport = () => {
    const csvContent = generateReportCsv(currentReportPayload);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const fileName = `kiron-prohori-report-${new Date().toISOString().slice(0, 10)}.csv`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', fileName);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setLastGeneratedReportMeta({
      format: 'CSV',
      fileName,
      rowCount: currentReportPayload.rows.length,
      generatedAt: currentReportPayload.generatedAtIso,
    });
  };

  const handleDownloadPdfReport = () => {
    const pdfContent = generateValidPdfDocument(currentReportPayload);
    const blob = new Blob([pdfContent], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const fileName = `kiron-prohori-report-${new Date().toISOString().slice(0, 10)}.pdf`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', fileName);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setLastGeneratedReportMeta({
      format: 'PDF',
      fileName,
      rowCount: currentReportPayload.rows.length,
      generatedAt: currentReportPayload.generatedAtIso,
    });
  };

  // =========================================================================
  // 7. USER PROFILE, THEME, LANGUAGE & AUTOMATED TEST SUITE STATE
  // =========================================================================
  const [profileDisplayName, setProfileDisplayName] = useState<string>(
    userProfile?.displayName || 'Defender Analyst'
  );
  const [profileOrg, setProfileOrg] = useState<string>(
    userProfile?.organization || 'Independent Security Team'
  );
  const [profileLang, setProfileLang] = useState<'en' | 'bn'>(language);
  const [toolkitTests, setToolkitTests] = useState<ToolkitTestResult[]>([]);
  const [isRunningToolkitTests, setIsRunningToolkitTests] =
    useState<boolean>(false);

  useEffect(() => {
    if (userProfile) {
      setProfileDisplayName(userProfile.displayName);
      setProfileOrg(userProfile.organization);
      setProfileLang(userProfile.preferredLanguage);
    }
  }, [userProfile]);

  const handleProfileSave = async (e: React.FormEvent) => {
    e.preventDefault();
    await updateUserProfile(profileDisplayName, profileOrg, profileLang);
    setLanguage(profileLang);
  };

  const handleExecuteToolkitTests = async () => {
    setIsRunningToolkitTests(true);
    try {
      const res = await runSecurityToolkitTests();
      setToolkitTests(res);
    } finally {
      setIsRunningToolkitTests(false);
    }
  };

  if (!TOOLKIT_MODULES.has(moduleId)) {
    return null;
  }

  const copyToClipboard = (text: string, label: string) => {
    void navigator.clipboard?.writeText(text);
    setCopiedTextMessage(`Copied ${label} safely to clipboard.`);
    setTimeout(() => setCopiedTextMessage(null), 2500);
  };

  return (
    <section
      aria-label="Phase 4 Security Toolkit and Personal Features Workspace"
      className="space-y-6 rounded-xl border border-blue-500/30 bg-[#0A1020] p-5 shadow-lg"
    >
      {/* Top Workspace Header & Navigation Tabs */}
      <div className="flex flex-col gap-4 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-blue-300">
              <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
              PHASE 4 · SECURITY TOOLKIT & PERSONAL FEATURES
            </span>
            <span className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
              $0 BUDGET · ZERO FILE UPLOAD · NO PAID EMAIL/SMS
            </span>
          </div>
          <h2 className="text-base font-bold tracking-tight text-slate-100">
            {isBn
              ? 'প্রতিরক্ষামূলক সিকিউরিটি টুলকিট, ওয়াচলিস্ট, নোটিফিকেশন এবং রিপোর্ট সেন্টার'
              : 'Defensive Security Toolkit, Personal Watchlist, In-App Alerts & Report Generator'}
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleExecuteToolkitTests}
            disabled={isRunningToolkitTests}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20 disabled:opacity-50"
          >
            <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
            <span>
              {isRunningToolkitTests
                ? 'Running Phase 4 Tests...'
                : 'Run Phase 4 Automated Tests (6/6)'}
            </span>
          </button>
        </div>
      </div>

      {/* Live Clipboard Toast Announcement */}
      {copiedTextMessage && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-lg border border-emerald-500/40 bg-emerald-950/50 px-3.5 py-2 text-xs text-emerald-200"
        >
          {copiedTextMessage}
        </div>
      )}

      {/* Automated Test Suite Results Drawer */}
      {toolkitTests.length > 0 && (
        <div
          role="region"
          aria-label="Phase 4 Automated Test Verification Results"
          className="rounded-lg border border-emerald-500/30 bg-[#080D1A] p-4 space-y-3"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-300">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              <span>
                Phase 4 Automated Verification Suite:{' '}
                {toolkitTests.filter((t) => t.passed).length} /{' '}
                {toolkitTests.length} Passed
              </span>
            </div>
            <button
              type="button"
              onClick={() => setToolkitTests([])}
              className="text-xs text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
            {toolkitTests.map((tr) => (
              <div
                key={tr.id}
                className="rounded-md border border-[#1E2D4A] bg-[#0E1628] p-2.5 text-xs"
              >
                <div className="flex items-center justify-between gap-2 font-semibold text-slate-100">
                  <span>{tr.module}</span>
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                      tr.passed
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'bg-rose-500/20 text-rose-300'
                    }`}
                  >
                    {tr.passed ? 'PASS' : 'FAIL'}
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-300">{tr.testName}</p>
                <p className="mt-1 font-mono text-[10px] text-emerald-300/90">
                  {tr.details}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 7-Module Switcher Bar */}
      <nav
        aria-label="Security Toolkit Modules"
        className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-1.5"
      >
        {[
          {
            id: 'url' as const,
            route: 'url-inspector' as RouteId,
            label: isBn ? '১. URL ইন্সপেক্টর' : '1. URL Inspector',
            icon: Link2,
          },
          {
            id: 'hash' as const,
            route: 'hash-lookup' as RouteId,
            label: isBn ? '২. SHA-256 হ্যাশ টুল' : '2. Hash Tool (WebCrypto)',
            icon: FileDigit,
          },
          {
            id: 'checklist' as const,
            route: 'security-checklist' as RouteId,
            label: isBn
              ? `৩. নিরাপত্তা চেকলিস্ট (${checklistProgress.completionPercentage}%)`
              : `3. Security Checklist (${checklistProgress.completionPercentage}%)`,
            icon: ClipboardCheck,
          },
          {
            id: 'watchlist' as const,
            route: 'my-watchlist' as RouteId,
            label: isBn
              ? `৪. ওয়াচলিস্ট ও ড্যাশবোর্ড (${watchlists.length})`
              : `4. Watchlist & Dashboard (${watchlists.length})`,
            icon: BookmarkCheck,
          },
          {
            id: 'notifications' as const,
            route: 'notifications' as RouteId,
            label: isBn
              ? `৫. ইন-অ্যাপ নোটিফিকেশন (${unreadNotificationsCount})`
              : `5. Notifications (${unreadNotificationsCount} Unread)`,
            icon: Bell,
          },
          {
            id: 'reports' as const,
            route: 'report-center' as RouteId,
            label: isBn ? '৬. রিপোর্ট সেন্টার (CSV/PDF)' : '6. Report Center (CSV/PDF)',
            icon: FileText,
          },
          {
            id: 'preferences' as const,
            route: 'settings' as RouteId,
            label: isBn ? '৭. প্রোফাইল ও থিম সেটিংস' : '7. Profile, Theme & UX',
            icon: Settings,
          },
        ].map((tab) => {
          const IconComp = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setActiveTab(tab.id);
                if (moduleId !== tab.route && moduleId !== 'dashboard') {
                  setActiveRoute(tab.route);
                }
              }}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-2 text-xs font-medium transition-colors ${
                active
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-300 hover:bg-[#141F38] hover:text-white'
              }`}
            >
              <IconComp className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* =====================================================================
          TAB 1: URL INSPECTOR
      ===================================================================== */}
      {activeTab === 'url' && (
        <div className="space-y-5">
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3.5 text-xs text-amber-200">
            <div className="flex items-start gap-2.5">
              <AlertTriangle
                className="mt-0.5 h-4 w-4 shrink-0 text-amber-400"
                aria-hidden="true"
              />
              <div className="space-y-1">
                <span className="font-semibold">
                  ZERO-EXECUTION & PRIVACY BOUNDARY:
                </span>{' '}
                KIRON PROHORI never visits, fetches, or renders submitted URLs.
                Private URLs are decomposed 100% in local browser memory and are
                never sent to external services without your explicit consent.{' '}
                <strong className="underline">
                  No match means UNKNOWN — never SAFE.
                </strong>
              </div>
            </div>
          </div>

          <form
            onSubmit={handleRunUrlInspection}
            aria-label="Suspicious URL Inspection Form"
            className="space-y-3 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4"
          >
            <div>
              <label
                htmlFor="phase4-url-inspector-input"
                className="block text-xs font-semibold text-slate-200"
              >
                {isBn
                  ? 'পরীক্ষার জন্য সন্দেহজনক URL বা ডোমেইন লিখুন (স্বয়ংক্রিয়ভাবে ডিফ্যাং করা হবে)'
                  : 'Enter Suspicious URL or Domain to Inspect Safely (Defanged or Raw)'}
              </label>
              <div className="mt-1.5 flex flex-col gap-2 sm:flex-row">
                <input
                  id="phase4-url-inspector-input"
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example-login-verify.com/path?token=..."
                  aria-describedby="url-inspector-privacy-note"
                  className="flex-1 rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3.5 py-2 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
                />
                <button
                  type="submit"
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-blue-500 shrink-0"
                >
                  <Search className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{isBn ? 'নিরাপদে বিশ্লেষণ করুন' : 'Inspect URL Safely'}</span>
                </button>
              </div>
            </div>

            <div className="flex flex-col gap-2 pt-1 sm:flex-row sm:items-center sm:justify-between">
              <label
                htmlFor="url-external-consent-checkbox"
                className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer"
              >
                <input
                  id="url-external-consent-checkbox"
                  type="checkbox"
                  checked={urlExternalConsent}
                  onChange={(e) => setUrlExternalConsent(e.target.checked)}
                  className="h-4 w-4 rounded border-[#1E2D4A] bg-[#080D1A] text-blue-600 focus:ring-blue-500"
                />
                <span>
                  Explicit Consent: Allow checking normalized domain against
                  optional external public feeds (Unchecked = 100% local check)
                </span>
              </label>

              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    setUrlInput(
                      'http://admin@xn--pple-43d.login-verify.example.com.bd:8080/drop.exe?otp=1234'
                    );
                  }}
                  className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-1 font-mono text-[11px] text-slate-300 hover:border-blue-500/40"
                >
                  Load Punycode/@ Sample
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setUrlInput('javascript:alert(document.cookie)');
                  }}
                  className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-1 font-mono text-[11px] text-slate-300 hover:border-rose-500/40"
                >
                  Load Malformed Scheme Sample
                </button>
              </div>
            </div>
          </form>

          {urlReport && (
            <div className="space-y-4">
              {/* Verdict Banner */}
              <div
                role="status"
                aria-live="polite"
                className={`rounded-lg border p-4 ${
                  urlReport.verdict === 'KNOWN_THREAT_MATCH'
                    ? 'border-rose-500/50 bg-rose-950/30 text-rose-100'
                    : urlReport.verdict === 'MALFORMED'
                    ? 'border-amber-500/50 bg-amber-950/30 text-amber-100'
                    : 'border-blue-500/40 bg-[#0E1628] text-slate-100'
                }`}
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold">
                    {urlReport.verdict === 'KNOWN_THREAT_MATCH' ? (
                      <XCircle
                        className="h-4 w-4 text-rose-400 shrink-0"
                        aria-hidden="true"
                      />
                    ) : (
                      <ShieldAlert
                        className="h-4 w-4 text-amber-400 shrink-0"
                        aria-hidden="true"
                      />
                    )}
                    <span>VERDICT: {urlReport.verdictBadgeLabel}</span>
                  </div>
                  <span className="font-mono text-[11px] text-slate-300">
                    {urlReport.networkActionTaken}
                  </span>
                </div>
                <p className="mt-2 text-xs leading-relaxed">
                  {urlReport.verdictExplanation}
                </p>
                {urlReport.malformedReason && (
                  <p className="mt-1 font-mono text-xs text-amber-300">
                    Malformed Diagnostic: {urlReport.malformedReason}
                  </p>
                )}
              </div>

              {/* Domain Normalization & Lexical Decomposition Grid */}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Domain Normalization & Defanged Output
                    </h3>
                    <button
                      type="button"
                      onClick={() =>
                        copyToClipboard(urlReport.defangedUrl, 'Defanged URL')
                      }
                      className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-1 text-[11px] text-slate-300 hover:text-white"
                    >
                      <Copy className="h-3 w-3" aria-hidden="true" />
                      <span>Copy Defanged</span>
                    </button>
                  </div>

                  <dl className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-2">
                    <div className="sm:col-span-2 rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5">
                      <dt className="text-[11px] text-slate-400">
                        Defanged Safe URL (Query Values Redacted)
                      </dt>
                      <dd className="mt-0.5 break-all font-mono text-xs text-blue-300">
                        {urlReport.defangedUrl}
                      </dd>
                    </div>
                    <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5">
                      <dt className="text-[11px] text-slate-400">
                        Normalized Hostname
                      </dt>
                      <dd className="mt-0.5 font-mono text-xs text-slate-100">
                        {urlReport.normalizedDomain}
                      </dd>
                    </div>
                    <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5">
                      <dt className="text-[11px] text-slate-400">
                        Registrable Domain (eTLD+1)
                      </dt>
                      <dd className="mt-0.5 font-mono text-xs text-emerald-300">
                        {urlReport.registrableDomain}
                      </dd>
                    </div>
                    <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5">
                      <dt className="text-[11px] text-slate-400">
                        Scheme / Port / Path
                      </dt>
                      <dd className="mt-0.5 font-mono text-xs text-slate-200">
                        {urlReport.scheme} · Port: {urlReport.port} ·{' '}
                        {urlReport.path}
                      </dd>
                    </div>
                    <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5">
                      <dt className="text-[11px] text-slate-400">
                        Query Parameter Keys ({urlReport.queryParameterNames.length})
                      </dt>
                      <dd className="mt-0.5 font-mono text-xs text-slate-200">
                        {urlReport.queryParameterNames.length > 0
                          ? urlReport.queryParameterNames.join(', ')
                          : 'None'}
                      </dd>
                    </div>
                  </dl>
                </div>

                {/* Structural Warnings & Source / Last Updated / Limitations */}
                <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Structural Heuristics, Source Attribution & Limitations
                  </h3>

                  {urlReport.structuralWarnings.length > 0 ? (
                    <ul className="space-y-1.5 text-xs text-amber-300">
                      {urlReport.structuralWarnings.map((w, idx) => (
                        <li
                          key={idx}
                          className="flex items-start gap-2 rounded border border-amber-500/30 bg-amber-950/20 p-2"
                        >
                          <AlertTriangle
                            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400"
                            aria-hidden="true"
                          />
                          <span>{w}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5 text-xs text-slate-300">
                      No lexical obfuscation flags triggered. Remember: clean
                      syntax does NOT mean a domain is safe.
                    </p>
                  )}

                  <div className="space-y-1.5 rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-[11px] text-slate-300">
                    <div>
                      <span className="font-semibold text-slate-200">
                        Intelligence Source:
                      </span>{' '}
                      {urlReport.intelligenceSourceAttribution}
                    </div>
                    <div>
                      <span className="font-semibold text-slate-200">
                        Last Updated:
                      </span>{' '}
                      <span className="font-mono">
                        {urlReport.intelligenceLastUpdatedAt}
                      </span>
                    </div>
                    <div className="text-amber-300/90">
                      {urlReport.limitationsNotice}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          TAB 2: HASH TOOL (BROWSER WEB CRYPTO SHA-256)
      ===================================================================== */}
      {activeTab === 'hash' && (
        <div className="space-y-5">
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3.5 text-xs text-emerald-200">
            <div className="flex items-start gap-2.5">
              <Lock
                className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400"
                aria-hidden="true"
              />
              <div>
                <span className="font-semibold">
                  ZERO FILE UPLOAD GUARANTEE (W3C WEB CRYPTO API):
                </span>{' '}
                Files selected below are hashed 100% inside your browser using{' '}
                <code className="font-mono">
                  window.crypto.subtle.digest(&apos;SHA-256&apos;)
                </code>
                . No file bytes or malware samples ever leave your device.
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Local File WebCrypto SHA-256 Calculator */}
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                A. Calculate Local File or Text SHA-256 (Browser Web Crypto)
              </h3>

              <div>
                <label
                  htmlFor="webcrypto-file-input"
                  className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-[#1E2D4A] bg-[#080D1A] p-4 text-center transition-colors hover:border-blue-500/50"
                >
                  <Upload
                    className="h-5 w-5 text-blue-400"
                    aria-hidden="true"
                  />
                  <span className="mt-1.5 text-xs font-medium text-slate-200">
                    {isComputingFileHash
                      ? 'Computing SHA-256 in Browser Memory...'
                      : 'Select Any Local File to Compute SHA-256 Locally (0 Bytes Uploaded)'}
                  </span>
                  <span className="mt-0.5 font-mono text-[11px] text-slate-400">
                    Uses window.crypto.subtle.digest(&apos;SHA-256&apos;, arrayBuffer)
                  </span>
                  <input
                    id="webcrypto-file-input"
                    type="file"
                    onChange={handleLocalFileSelect}
                    className="sr-only"
                  />
                </label>
              </div>

              <div className="space-y-1.5">
                <label
                  htmlFor="webcrypto-text-buffer"
                  className="block text-xs font-medium text-slate-300"
                >
                  Or Compute SHA-256 from Text String:
                </label>
                <div className="flex gap-2">
                  <input
                    id="webcrypto-text-buffer"
                    type="text"
                    value={textToHashInput}
                    onChange={(e) => setTextToHashInput(e.target.value)}
                    placeholder="Enter text string to hash via WebCrypto..."
                    className="flex-1 rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={handleComputeTextSha256}
                    className="rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/20"
                  >
                    Compute SHA-256
                  </button>
                </div>
              </div>

              {localFileMeta && (
                <div className="rounded border border-emerald-500/30 bg-[#080D1A] p-3 text-xs space-y-1">
                  <div className="flex items-center justify-between text-emerald-300 font-semibold">
                    <span>Local WebCrypto Digest Computed</span>
                    <span className="font-mono text-[11px]">
                      {localFileMeta.sizeBytes.toLocaleString()} bytes
                    </span>
                  </div>
                  <div className="text-slate-300">
                    Source: <span className="font-mono">{localFileMeta.name}</span>
                  </div>
                  <div className="break-all font-mono text-[11px] text-blue-300">
                    SHA-256: {localFileMeta.computedSha256}
                  </div>
                </div>
              )}
            </div>

            {/* Hash Format Validator & Authorized Public Reputation Lookup */}
            <form
              onSubmit={handleRunHashReputationLookup}
              aria-label="Hash Format Validation and Reputation Lookup Form"
              className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3"
            >
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                B. Validate Hash Format & Authorized Public Reputation Lookup
              </h3>

              <div>
                <label
                  htmlFor="hash-validator-input"
                  className="block text-xs font-medium text-slate-300"
                >
                  Hexadecimal Hash Digest (SHA-256 / SHA-1 / MD5):
                </label>
                <div className="mt-1 flex gap-2">
                  <input
                    id="hash-validator-input"
                    type="text"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    placeholder="64-character SHA-256 hexadecimal string..."
                    className="flex-1 rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={!hashFormatValidation.isValid || isLookingUpHash}
                    className="rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
                  >
                    {isLookingUpHash ? 'Checking...' : 'Lookup Hash'}
                  </button>
                </div>
              </div>

              {/* Format Validation Indicator */}
              <div
                className={`rounded border p-2.5 text-xs ${
                  hashFormatValidation.isValid
                    ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-200'
                    : 'border-amber-500/30 bg-amber-950/20 text-amber-200'
                }`}
              >
                <div className="font-mono font-semibold">
                  Format: {hashFormatValidation.algorithm} (
                  {hashFormatValidation.bitLength} bits)
                </div>
                <p className="mt-0.5 text-[11px]">
                  {hashFormatValidation.validationMessage}
                </p>
              </div>

              <label
                htmlFor="hash-public-lookup-consent"
                className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer"
              >
                <input
                  id="hash-public-lookup-consent"
                  type="checkbox"
                  checked={hashLookupConsent}
                  onChange={(e) => setHashLookupConsent(e.target.checked)}
                  className="h-4 w-4 rounded border-[#1E2D4A] bg-[#080D1A] text-blue-600"
                />
                <span>
                  Query authorized public CIRCL Hashlookup service (sends only
                  the 64-char SHA-256 string, never the file)
                </span>
              </label>

              {hashLookupResult && (
                <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs space-y-1.5">
                  <div className="flex items-center justify-between font-mono font-bold">
                    <span
                      className={
                        hashLookupResult.verdict === 'KNOWN_THREAT_INDICATOR'
                          ? 'text-rose-400'
                          : hashLookupResult.verdict ===
                            'KNOWN_PUBLIC_REFERENCE'
                          ? 'text-emerald-400'
                          : 'text-amber-300'
                      }
                    >
                      VERDICT: {hashLookupResult.verdict}
                    </span>
                    <span className="text-[10px] text-slate-400">
                      {hashLookupResult.checkedAt}
                    </span>
                  </div>
                  <p className="text-slate-200">{hashLookupResult.message}</p>
                  {hashLookupResult.circlFileName && (
                    <div className="font-mono text-[11px] text-slate-300">
                      CIRCL Known File: {hashLookupResult.circlFileName} (
                      {hashLookupResult.circlFileSize || 'N/A'} bytes)
                    </div>
                  )}
                  <div className="flex items-center justify-between pt-1 text-[11px] text-slate-400">
                    <span>Source: {hashLookupResult.sourceName}</span>
                    <a
                      href={hashLookupResult.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-blue-400 hover:underline"
                    >
                      <span>Official Reference</span>
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                  </div>
                </div>
              )}
            </form>
          </div>
        </div>
      )}

      {/* =====================================================================
          TAB 3: SECURITY CHECKLIST (6 MANDATORY DEFENSIVE TRACKS)
      ===================================================================== */}
      {activeTab === 'checklist' && (
        <div className="space-y-5">
          {/* Overall Progress Header */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  {isBn
                    ? '৬-ট্র্যাক প্রতিরক্ষামূলক নিরাপত্তা চেকলিস্ট অগ্রগতি'
                    : '6-Track Defensive Security Hardening Progress'}
                </h3>
                <p className="text-xs text-slate-400">
                  Persisted locally in your browser. Export your current posture
                  anytime in the Report Center (CSV / PDF).
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm font-bold text-emerald-400">
                  {checklistProgress.completedItems} /{' '}
                  {checklistProgress.totalItems} Verified (
                  {checklistProgress.completionPercentage}%)
                </span>
                <button
                  type="button"
                  onClick={() => setActiveTab('reports')}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-500"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Export Checklist Report</span>
                </button>
              </div>
            </div>

            <div className="h-2.5 w-full overflow-hidden rounded-full bg-[#080D1A]">
              <div
                className="h-full bg-emerald-500 transition-all duration-300"
                style={{ width: `${checklistProgress.completionPercentage}%` }}
              />
            </div>

            {/* Track Filter Pills */}
            <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => setSelectedTrackFilter('ALL')}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium ${
                    selectedTrackFilter === 'ALL'
                      ? 'bg-blue-600 text-white'
                      : 'border border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:text-white'
                  }`}
                >
                  All 6 Tracks ({checklistProgress.totalItems})
                </button>
                {SECURITY_CHECKLIST_TRACKS.map((track) => {
                  const stat = checklistProgress.byTrack[track.trackId];
                  return (
                    <button
                      key={track.trackId}
                      type="button"
                      onClick={() => setSelectedTrackFilter(track.trackId)}
                      className={`rounded-md px-2.5 py-1 text-xs font-medium ${
                        selectedTrackFilter === track.trackId
                          ? 'bg-blue-600 text-white'
                          : 'border border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:text-white'
                      }`}
                    >
                      {isBn ? track.titleBn : track.titleEn} ({stat.completed}/
                      {stat.total})
                    </button>
                  );
                })}
              </div>

              <select
                aria-label="Filter checklist items by priority"
                value={checklistPriorityFilter}
                onChange={(e) =>
                  setChecklistPriorityFilter(
                    e.target.value as 'ALL' | 'ESSENTIAL' | 'RECOMMENDED'
                  )
                }
                className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-xs text-slate-200"
              >
                <option value="ALL">All Priorities</option>
                <option value="ESSENTIAL">Essential Controls Only</option>
                <option value="RECOMMENDED">Recommended Controls Only</option>
              </select>
            </div>
          </div>

          {/* 6 Checklist Tracks Grid */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {SECURITY_CHECKLIST_TRACKS.filter(
              (tr) =>
                selectedTrackFilter === 'ALL' ||
                tr.trackId === selectedTrackFilter
            ).map((track) => {
              const stat = checklistProgress.byTrack[track.trackId];
              const visibleItems = track.items.filter(
                (i) =>
                  checklistPriorityFilter === 'ALL' ||
                  i.priority === checklistPriorityFilter
              );

              return (
                <div
                  key={track.trackId}
                  className="flex flex-col justify-between rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3"
                >
                  <div className="space-y-2">
                    <div className="flex items-start justify-between gap-2 border-b border-[#1E2D4A] pb-2.5">
                      <div>
                        <h4 className="text-sm font-bold text-slate-100">
                          {isBn ? track.titleBn : track.titleEn}
                        </h4>
                        <p className="text-[11px] text-slate-400">
                          Audience: {isBn ? track.audienceBn : track.audienceEn}
                        </p>
                      </div>
                      <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-xs text-emerald-300 shrink-0">
                        {stat.completed}/{stat.total} ({stat.percentage}%)
                      </span>
                    </div>

                    <p className="text-xs text-slate-300">
                      {isBn ? track.summaryBn : track.summaryEn}
                    </p>

                    <div className="space-y-2 pt-1">
                      {visibleItems.map((item) => {
                        const checked = completedChecklistIds.includes(item.id);
                        return (
                          <label
                            key={item.id}
                            htmlFor={`chk-${item.id}`}
                            className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ${
                              checked
                                ? 'border-emerald-500/40 bg-emerald-950/20'
                                : 'border-[#1E2D4A] bg-[#080D1A] hover:border-blue-500/40'
                            }`}
                          >
                            <input
                              id={`chk-${item.id}`}
                              type="checkbox"
                              checked={checked}
                              onChange={() => toggleChecklistItem(item.id)}
                              className="mt-0.5 h-4 w-4 rounded border-[#1E2D4A] bg-[#080D1A] text-emerald-500 focus:ring-emerald-500"
                            />
                            <div className="space-y-1 text-xs">
                              <div className="flex flex-wrap items-center gap-2 font-semibold text-slate-100">
                                <span>
                                  {isBn ? item.titleBn : item.titleEn}
                                </span>
                                <span
                                  className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                                    item.priority === 'ESSENTIAL'
                                      ? 'bg-amber-500/20 text-amber-300'
                                      : 'bg-blue-500/20 text-blue-300'
                                  }`}
                                >
                                  {item.priority}
                                </span>
                              </div>
                              <p className="text-slate-300 leading-relaxed">
                                {isBn ? item.guidanceBn : item.guidanceEn}
                              </p>
                              <div className="font-mono text-[10px] text-slate-400">
                                Verification: {item.verificationAction}
                              </div>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* =====================================================================
          TAB 4: WATCHLIST & PERSONALIZED DASHBOARD
      ===================================================================== */}
      {activeTab === 'watchlist' && (
        <div className="space-y-5">
          {/* Personalized Watchlist KPI Summary Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3">
              <div className="text-[11px] text-slate-400">Saved Watchlist</div>
              <div className="mt-1 font-mono text-lg font-bold text-slate-100">
                {personalizedDashboard.totalWatchlistItems}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3">
              <div className="text-[11px] text-slate-400">Saved CVEs</div>
              <div className="mt-1 font-mono text-lg font-bold text-blue-300">
                {personalizedDashboard.savedCvesCount}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3">
              <div className="text-[11px] text-slate-400">Followed Vendors</div>
              <div className="mt-1 font-mono text-lg font-bold text-emerald-300">
                {personalizedDashboard.followedVendorsCount}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3">
              <div className="text-[11px] text-slate-400">Followed Products</div>
              <div className="mt-1 font-mono text-lg font-bold text-purple-300">
                {personalizedDashboard.followedProductsCount}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3">
              <div className="text-[11px] text-slate-400">Catalog Matches</div>
              <div className="mt-1 font-mono text-lg font-bold text-amber-300">
                {personalizedDashboard.totalCatalogMatches}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3">
              <div className="text-[11px] text-slate-400">Active KEV Hits</div>
              <div className="mt-1 font-mono text-lg font-bold text-rose-400">
                {personalizedDashboard.activeKevMatchesCount}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {/* Add Watchlist Item Form */}
            <form
              onSubmit={handleAddWatchlistSubmit}
              aria-label="Save CVE or Follow Vendor and Product Watchlist Form"
              className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3"
            >
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                Save CVE or Follow Vendor / Product
              </h3>

              <div>
                <label
                  htmlFor="wl-item-type"
                  className="block text-xs font-medium text-slate-300"
                >
                  Watchlist Target Type
                </label>
                <select
                  id="wl-item-type"
                  value={wlItemType}
                  onChange={(e) =>
                    setWlItemType(
                      e.target.value as
                        | 'cve_id'
                        | 'vendor_keyword'
                        | 'product_cpe'
                        | 'domain_pattern'
                    )
                  }
                  className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
                >
                  <option value="cve_id">Save Specific CVE ID (e.g., CVE-2024-3400)</option>
                  <option value="vendor_keyword">Follow Vendor (e.g., Microsoft, Apache, Cisco)</option>
                  <option value="product_cpe">Follow Product (e.g., PAN-OS, Log4j, Chrome)</option>
                  <option value="domain_pattern">Monitor Domain Pattern</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="wl-target-value"
                  className="block text-xs font-medium text-slate-300"
                >
                  Target CVE ID, Vendor, or Product Name
                </label>
                <input
                  id="wl-target-value"
                  type="text"
                  required
                  value={wlTargetValue}
                  onChange={(e) => setWlTargetValue(e.target.value)}
                  placeholder={
                    wlItemType === 'cve_id'
                      ? 'CVE-2024-3400'
                      : wlItemType === 'vendor_keyword'
                      ? 'Apache'
                      : 'PAN-OS'
                  }
                  className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label
                  htmlFor="wl-severity-threshold"
                  className="block text-xs font-medium text-slate-300"
                >
                  Minimum Alert Severity Filter
                </label>
                <select
                  id="wl-severity-threshold"
                  value={wlSeverityFilter}
                  onChange={(e) =>
                    setWlSeverityFilter(
                      e.target.value as
                        | 'ALL'
                        | 'MEDIUM_PLUS'
                        | 'HIGH_PLUS'
                        | 'CRITICAL_ONLY'
                    )
                  }
                  className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
                >
                  <option value="ALL">All Severities</option>
                  <option value="MEDIUM_PLUS">Medium & Above</option>
                  <option value="HIGH_PLUS">High & Critical Only</option>
                  <option value="CRITICAL_ONLY">Critical / KEV Only</option>
                </select>
              </div>

              <div>
                <label
                  htmlFor="wl-analyst-notes"
                  className="block text-xs font-medium text-slate-300"
                >
                  Defensive Asset / Context Note (Optional)
                </label>
                <input
                  id="wl-analyst-notes"
                  type="text"
                  value={wlNotes}
                  onChange={(e) => setWlNotes(e.target.value)}
                  placeholder="e.g., Branch office firewall appliance"
                  className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
                />
              </div>

              <button
                type="submit"
                className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-500"
              >
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                <span>Save to My Watchlist</span>
              </button>

              {/* Quick Follow Presets */}
              <div className="pt-1">
                <div className="text-[11px] text-slate-400">
                  Quick Follow Real KEV Vendors/Products:
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {[
                    { type: 'vendor_keyword' as const, val: 'Microsoft' },
                    { type: 'vendor_keyword' as const, val: 'Apache' },
                    { type: 'product_cpe' as const, val: 'PAN-OS' },
                    { type: 'cve_id' as const, val: 'CVE-2021-44228' },
                  ].map((p) => (
                    <button
                      key={p.val}
                      type="button"
                      onClick={() =>
                        void addWatchlistItem(
                          p.type,
                          p.val,
                          'Quick Watchlist Follow',
                          'ALL'
                        )
                      }
                      className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-1 font-mono text-[11px] text-slate-300 hover:border-blue-500/40 hover:text-white"
                    >
                      + {p.val}
                    </button>
                  ))}
                </div>
              </div>
            </form>

            {/* Saved Watchlist Items & Personalized Vulnerability Feed */}
            <div className="lg:col-span-2 space-y-4">
              <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                    Saved Watchlist Targets ({watchlists.length})
                  </h3>
                  <button
                    type="button"
                    onClick={() => void handleGenerateWatchlistNotification()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/20"
                  >
                    <Bell className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Log Watchlist Alert to In-App Notifications</span>
                  </button>
                </div>

                {watchlists.length === 0 ? (
                  <p className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs text-slate-400">
                    No saved CVEs, vendors, or products yet. Add an item on the
                    left or click a Quick Follow preset to populate your
                    personalized threat dashboard.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {watchlists.map((item) => (
                      <div
                        key={item.watchlistId}
                        className="flex items-center justify-between gap-3 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-2.5 text-xs"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="rounded bg-blue-500/20 px-1.5 py-0.5 font-mono text-[10px] text-blue-300">
                              {item.itemType}
                            </span>
                            <span className="font-mono font-bold text-slate-100">
                              {item.targetValue}
                            </span>
                            <span className="font-mono text-[10px] text-slate-400">
                              Filter: {item.severityFilter}
                            </span>
                          </div>
                          {item.notes && (
                            <p className="mt-0.5 truncate text-[11px] text-slate-400">
                              {item.notes}
                            </p>
                          )}
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            void deleteWatchlistItem(item.watchlistId)
                          }
                          aria-label={`Remove ${item.targetValue} from watchlist`}
                          className="inline-flex items-center gap-1 rounded border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-[11px] text-rose-300 hover:bg-rose-500/20 shrink-0"
                        >
                          <Trash2 className="h-3 w-3" aria-hidden="true" />
                          <span>Remove</span>
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Personalized Dashboard Matches Table */}
              <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                    Personalized Intelligence Feed Matches (
                    {personalizedDashboard.matches.length})
                  </h3>
                  <span className="font-mono text-[11px] text-slate-400">
                    Correlated against {liveKevRecords.length} live KEV entries &{' '}
                    {cves.length} Firestore CVEs
                  </span>
                </div>

                {personalizedDashboard.matches.length === 0 ? (
                  <p className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs text-slate-400">
                    0 catalog vulnerabilities currently match your saved
                    watchlist targets. Follow &quot;Microsoft&quot;,
                    &quot;Apache&quot;, or &quot;PAN-OS&quot; to see live CISA
                    KEV matches immediately.
                  </p>
                ) : (
                  <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                    {personalizedDashboard.matches.map((m, idx) => (
                      <div
                        key={`${m.watchlistId}-${m.matchedCveId}-${idx}`}
                        className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs space-y-1"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-blue-300">
                              {m.matchedCveId}
                            </span>
                            <span className="text-slate-200 font-semibold">
                              {m.matchedVendor} · {m.matchedProduct}
                            </span>
                          </div>
                          <span
                            className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                              m.inKev
                                ? 'bg-rose-500/20 text-rose-300'
                                : 'bg-amber-500/20 text-amber-300'
                            }`}
                          >
                            {m.severity}
                          </span>
                        </div>
                        <p className="text-slate-300">
                          {m.titleOrVulnerabilityName}
                        </p>
                        <div className="flex flex-wrap items-center justify-between gap-2 pt-1 font-mono text-[11px] text-slate-400">
                          <span>Matched Rule: &quot;{m.targetValue}&quot;</span>
                          <span>Due: {m.dueDate}</span>
                          <span>Source: {m.sourceAttribution}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          TAB 5: IN-APP NOTIFICATIONS ($0 IN-APP ONLY)
      ===================================================================== */}
      {activeTab === 'notifications' && (
        <div className="space-y-4">
          <div className="flex flex-col gap-3 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                In-App Notification Center ({unreadNotificationsCount} Unread /{' '}
                {notifications.length} Total)
              </h3>
              <p className="text-xs text-slate-400">
                Strict $0 Budget: Uses 100% in-app Cloud Firestore notifications.
                Zero paid email (SendGrid/SES) or SMS (Twilio) gateways.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => void handleGenerateWatchlistNotification()}
                className="rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/20"
              >
                + Generate Watchlist Alert
              </button>
              <button
                type="button"
                onClick={() => void markAllNotificationsRead()}
                disabled={unreadNotificationsCount === 0}
                className="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-40"
              >
                Mark All as Read ({unreadNotificationsCount})
              </button>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-col gap-3 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-3.5 sm:flex-row sm:items-center">
            <div className="flex-1">
              <label htmlFor="notif-search" className="sr-only">
                Search notifications
              </label>
              <input
                id="notif-search"
                type="text"
                value={notifSearchQuery}
                onChange={(e) => setNotifSearchQuery(e.target.value)}
                placeholder="Filter notifications by title or keyword..."
                className="w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs text-slate-100"
              />
            </div>

            <select
              aria-label="Filter notifications by category"
              value={notifCategoryFilter}
              onChange={(e) =>
                setNotifCategoryFilter(
                  e.target.value as
                    | 'ALL'
                    | 'watchlist_match'
                    | 'moderation_update'
                    | 'security_notice'
                    | 'system'
                )
              }
              className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Categories</option>
              <option value="watchlist_match">Watchlist Matches</option>
              <option value="moderation_update">Moderation Updates</option>
              <option value="security_notice">Security Notices</option>
              <option value="system">System Events</option>
            </select>

            <select
              aria-label="Filter notifications by read status"
              value={notifReadFilter}
              onChange={(e) =>
                setNotifReadFilter(e.target.value as 'ALL' | 'UNREAD' | 'READ')
              }
              className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Read States</option>
              <option value="UNREAD">Unread Only</option>
              <option value="READ">Read Only</option>
            </select>
          </div>

          {/* Notifications List */}
          {filteredNotifications.length === 0 ? (
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 text-center text-xs text-slate-400">
              No in-app notifications match the selected category/read filters.
              Click &quot;+ Generate Watchlist Alert&quot; above to create an
              in-app alert from your current watchlist state.
            </div>
          ) : (
            <div className="space-y-2.5">
              {filteredNotifications.map((n) => (
                <div
                  key={n.notificationId}
                  className={`flex flex-col gap-3 rounded-lg border p-3.5 sm:flex-row sm:items-center sm:justify-between ${
                    n.isRead
                      ? 'border-[#1E2D4A] bg-[#080D1A] text-slate-300'
                      : 'border-blue-500/40 bg-[#0E1628] text-slate-100'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {!n.isRead && (
                        <span className="inline-block h-2 w-2 rounded-full bg-blue-400" />
                      )}
                      <span className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-0.5 font-mono text-[10px] text-blue-300">
                        {n.category}
                      </span>
                      <span className="text-xs font-bold">{n.title}</span>
                      <span className="font-mono text-[10px] text-slate-400">
                        {n.createdAt}
                      </span>
                    </div>
                    <p className="text-xs leading-relaxed text-slate-300">
                      {n.message}
                    </p>
                  </div>

                  <div className="shrink-0">
                    {n.isRead ? (
                      <span className="font-mono text-[11px] text-emerald-400">
                        READ
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() =>
                          void markNotificationRead(n.notificationId)
                        }
                        className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/20"
                      >
                        <Eye className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Mark as Read</span>
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          TAB 6: REPORT CENTER (DOWNLOADABLE CSV & PDF 1.4)
      ===================================================================== */}
      {activeTab === 'reports' && (
        <div className="space-y-5">
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Defensive Report Center — Downloadable CSV & PDF Reports
                </h3>
                <p className="text-xs text-slate-400">
                  Every generated report includes the UTC Report Date, Official
                  Source References, and Mandatory Non-Affiliation Disclaimer.
                  Zero security findings are fabricated.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleDownloadCsvReport}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/20"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Download CSV (.csv)</span>
                </button>
                <button
                  type="button"
                  onClick={handleDownloadPdfReport}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-blue-500"
                >
                  <FileText className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Download PDF Report (.pdf)</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label
                  htmlFor="report-title-input"
                  className="block text-xs font-medium text-slate-300"
                >
                  Report Title
                </label>
                <input
                  id="report-title-input"
                  type="text"
                  value={reportTitleInput}
                  onChange={(e) => setReportTitleInput(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
                />
              </div>

              <div>
                <label
                  htmlFor="report-scope-select"
                  className="block text-xs font-medium text-slate-300"
                >
                  Verified Data Scope (Never Fabricated)
                </label>
                <select
                  id="report-scope-select"
                  value={reportScope}
                  onChange={(e) =>
                    setReportScope(
                      e.target.value as
                        | 'watchlist_and_checklist'
                        | 'cisa_kev_top'
                        | 'checklist_only'
                        | 'verified_scams'
                    )
                  }
                  className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
                >
                  <option value="watchlist_and_checklist">
                    My Watchlist Matches + 6-Track Security Checklist Posture
                  </option>
                  <option value="cisa_kev_top">
                    Live CISA KEV Active Exploitation Snapshot (Top 20 Records)
                  </option>
                  <option value="checklist_only">
                    6-Track Defensive Security Checklist Audit Only (18 Controls)
                  </option>
                  <option value="verified_scams">
                    Moderated & Approved Community Scam/Phishing Reports
                  </option>
                </select>
              </div>
            </div>

            {lastGeneratedReportMeta && (
              <div
                role="status"
                aria-live="polite"
                className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 p-3 text-xs text-emerald-200"
              >
                Generated & downloaded{' '}
                <strong className="font-mono">
                  {lastGeneratedReportMeta.fileName}
                </strong>{' '}
                ({lastGeneratedReportMeta.format}) containing{' '}
                {lastGeneratedReportMeta.rowCount} verified records at{' '}
                <span className="font-mono">
                  {lastGeneratedReportMeta.generatedAt}
                </span>
                .
              </div>
            )}

            {/* Live Report Preview Card */}
            <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#1E2D4A] pb-2.5">
                <div>
                  <div className="font-bold text-slate-100">
                    {currentReportPayload.reportTitle}
                  </div>
                  <div className="font-mono text-[11px] text-slate-400">
                    Report Date (UTC): {currentReportPayload.generatedAtIso} ·
                    Prepared By: {currentReportPayload.preparedBy} (
                    {currentReportPayload.organization})
                  </div>
                </div>
                <span className="rounded bg-blue-500/20 px-2 py-0.5 font-mono text-[11px] text-blue-300">
                  {currentReportPayload.rows.length} Verified Row(s)
                </span>
              </div>

              <div>
                <div className="font-semibold text-slate-300">
                  Official Source References Included:
                </div>
                <ul className="mt-1 list-disc pl-5 text-[11px] text-slate-400 space-y-0.5">
                  {currentReportPayload.sourceReferences.map((src, i) => (
                    <li key={i}>{src}</li>
                  ))}
                </ul>
              </div>

              <div className="rounded border border-amber-500/30 bg-amber-950/20 p-2.5 text-[11px] text-amber-200">
                {currentReportPayload.disclaimer}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          TAB 7: USER EXPERIENCE (PROFILE, THEME PREFERENCE, LANGUAGE, ACCESSIBILITY)
      ===================================================================== */}
      {activeTab === 'preferences' && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Accessible User Profile Form */}
          <form
            onSubmit={handleProfileSave}
            aria-label="User Security Profile Form"
            className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-3"
          >
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-2.5">
              <div className="flex items-center gap-2">
                <UserCheck
                  className="h-4 w-4 text-blue-400"
                  aria-hidden="true"
                />
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200">
                  Private User Profile (/users/&#123;uid&#125;)
                </h3>
              </div>
              <span className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2 py-0.5 font-mono text-[10px] text-emerald-300">
                Role: {authoritativeRole.toUpperCase()} · Mode: {persistenceMode}
              </span>
            </div>

            {!isSignedIn && (
              <div className="rounded border border-blue-500/30 bg-blue-950/20 p-3 text-xs text-blue-200 flex items-center justify-between">
                <span>
                  Sign in with Google to persist your profile in Cloud Firestore.
                </span>
                <button
                  type="button"
                  onClick={() => void signInWithGoogle()}
                  className="rounded bg-blue-600 px-3 py-1 font-semibold text-white hover:bg-blue-500"
                >
                  Google Sign-In
                </button>
              </div>
            )}

            <div>
              <label
                htmlFor="profile-display-name"
                className="block text-xs font-medium text-slate-300"
              >
                Display Name (1–100 chars)
              </label>
              <input
                id="profile-display-name"
                type="text"
                required
                maxLength={100}
                value={profileDisplayName}
                onChange={(e) => setProfileDisplayName(e.target.value)}
                className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="profile-organization"
                className="block text-xs font-medium text-slate-300"
              >
                Organization / Team (0–120 chars)
              </label>
              <input
                id="profile-organization"
                type="text"
                maxLength={120}
                value={profileOrg}
                onChange={(e) => setProfileOrg(e.target.value)}
                className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
              />
            </div>

            <div>
              <label
                htmlFor="profile-preferred-language"
                className="block text-xs font-medium text-slate-300"
              >
                Preferred Interface Language
              </label>
              <select
                id="profile-preferred-language"
                value={profileLang}
                onChange={(e) => setProfileLang(e.target.value as 'en' | 'bn')}
                className="mt-1 w-full rounded-lg border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
              >
                <option value="en">English (EN)</option>
                <option value="bn">বাংলা (Bengali - BN)</option>
              </select>
            </div>

            <button
              type="submit"
              className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500"
            >
              <span>Save Profile & Sync Preferences</span>
            </button>
          </form>

          {/* Theme Preference, Language Preference & Accessibility Controls */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 border-b border-[#1E2D4A] pb-2.5">
              Theme Preference, Language & Accessibility
            </h3>

            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-300">
                Visual Theme Preference
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => setThemePreference('dark')}
                  aria-pressed={themePreference === 'dark'}
                  className={`flex items-center justify-center gap-2 rounded-lg border p-3 text-xs font-semibold transition-colors ${
                    themePreference === 'dark'
                      ? 'border-blue-500 bg-blue-600/20 text-white'
                      : 'border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:text-white'
                  }`}
                >
                  <Moon className="h-4 w-4 text-blue-400" aria-hidden="true" />
                  <span>Tactical Dark (#080D1A)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setThemePreference('high_contrast')}
                  aria-pressed={themePreference === 'high_contrast'}
                  className={`flex items-center justify-center gap-2 rounded-lg border p-3 text-xs font-semibold transition-colors ${
                    themePreference === 'high_contrast'
                      ? 'border-emerald-400 bg-emerald-500/20 text-white'
                      : 'border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:text-white'
                  }`}
                >
                  <Sun
                    className="h-4 w-4 text-amber-300"
                    aria-hidden="true"
                  />
                  <span>High-Contrast Mode</span>
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <div className="text-xs font-medium text-slate-300">
                Bilingual Interface Toggle
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => {
                    setLanguage('en');
                    setProfileLang('en');
                  }}
                  aria-pressed={language === 'en'}
                  className={`flex items-center justify-center gap-2 rounded-lg border p-3 text-xs font-semibold ${
                    language === 'en'
                      ? 'border-blue-500 bg-blue-600/20 text-white'
                      : 'border-[#1E2D4A] bg-[#080D1A] text-slate-300'
                  }`}
                >
                  <Globe className="h-4 w-4 text-blue-400" aria-hidden="true" />
                  <span>English (EN)</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setLanguage('bn');
                    setProfileLang('bn');
                  }}
                  aria-pressed={language === 'bn'}
                  className={`flex items-center justify-center gap-2 rounded-lg border p-3 text-xs font-semibold ${
                    language === 'bn'
                      ? 'border-blue-500 bg-blue-600/20 text-white'
                      : 'border-[#1E2D4A] bg-[#080D1A] text-slate-300'
                  }`}
                >
                  <Globe
                    className="h-4 w-4 text-emerald-400"
                    aria-hidden="true"
                  />
                  <span>বাংলা (Bengali)</span>
                </button>
              </div>
            </div>

            <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-[11px] text-slate-300 space-y-1">
              <div className="font-semibold text-slate-200">
                Accessibility & Responsive Mobile Navigation Status:
              </div>
              <p>
                • All form inputs are bound to explicit{' '}
                <code className="font-mono">&lt;label htmlFor&gt;</code>{' '}
                attributes and live status regions (
                <code className="font-mono">aria-live=&quot;polite&quot;</code>
                ).
              </p>
              <p>
                • Responsive mobile drawer and bottom quick-navigation bar are
                active on mobile &amp; tablet viewports.
              </p>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
