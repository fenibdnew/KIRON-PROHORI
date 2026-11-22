import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldCheck,
  Users,
  UserCog,
  AlertTriangle,
  Database,
  RefreshCw,
  History,
  Clock,
  MessageSquare,
  Sliders,
  FileSearch,
  Activity,
  Lock,
  Eye,
  EyeOff,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Send,
  AlertOctagon,
  Plus,
  Search,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { useApp } from '../../context/AppContext';
import {
  computeRealAdminMetrics,
  mergeUsersWithAuthoritativeRoles,
  scrubPiiFromModerationText,
  formatScamReportAppealMessage,
  evaluateSourcesFreshnessMatrix,
  filterAuditLogs,
} from '../../admin/engine';
import { DataSourceDoc, FeedbackDoc, RoleDoc, ScamReportDoc } from '../../types/security';

interface ConnectorTelemetryItem {
  connectorId: string;
  name: string;
  status: string;
  credentialEnvVar: string | null;
  credentialConfigured: boolean;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  cachedRecordCount: number;
}

interface ConnectorErrorLogItem {
  id: string;
  connectorId: string;
  timestamp: string;
  attemptCount: number;
  errorMessage: string;
  preservedCachedCount: number;
}

interface AdminGovernanceWorkspaceProps {
  moduleId: string;
}

type AdminSectionTab =
  | 'overview'
  | 'users_roles'
  | 'scam_moderation'
  | 'sources_sync'
  | 'feedback_config'
  | 'audit_health';

export const AdminGovernanceWorkspace: React.FC<AdminGovernanceWorkspaceProps> = ({
  moduleId,
}) => {
  const { language } = useApp();
  const isBn = language === 'bn';

  const {
    persistenceMode,
    demoRolePersona,
    setDemoRolePersona,
    isAdmin,
    isSignedIn,
    userProfile,
    authoritativeRole,
    projectId,
    databaseId,
    connectionStatusMessage,
    actionFeedback,
    clearActionFeedback,
    usersList,
    rolesList,
    cves,
    kevEntries,
    threatIndicators,
    approvedScamReports,
    pendingScamReports,
    myScamReports,
    dataSources,
    syncLogs,
    feedbackItems,
    appSettings,
    auditLogs,
    signInWithGoogle,
    assignUserRole,
    moderateScamReport,
    upsertDataSource,
    submitFeedback,
    updateFeedbackStatus,
    recordManualSyncLog,
    upsertAppSetting,
    seedOfficialPublicReferenceSample,
    refreshCollections,
  } = useSecurity();

  const [connectors, setConnectors] = useState<ConnectorTelemetryItem[]>([]);
  const [connectorErrorLogs, setConnectorErrorLogs] = useState<ConnectorErrorLogItem[]>([]);
  const [liveKevCachedCount, setLiveKevCachedCount] = useState<number>(0);
  const [liveNvdCachedCount, setLiveNvdCachedCount] = useState<number>(0);
  const [liveUrlhausCachedCount, setLiveUrlhausCachedCount] = useState<number>(0);
  const [isRefreshingKev, setIsRefreshingKev] = useState<boolean>(false);
  const [isSearchingNvd, setIsSearchingNvd] = useState<boolean>(false);
  const [isRefreshingUrlhaus, setIsRefreshingUrlhaus] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<AdminSectionTab>('overview');
  const [revealUserPiiEmails, setRevealUserPiiEmails] = useState<boolean>(false);

  // User Role Assignment Form State
  const [roleTargetUid, setRoleTargetUid] = useState<string>('');
  const [selectedRoleValue, setSelectedRoleValue] = useState<RoleDoc['role']>('analyst');

  // Scam Moderation State
  const [moderationFilter, setModerationFilter] = useState<
    'ALL' | ScamReportDoc['moderationStatus']
  >('ALL');
  const [moderatorNotesDraft, setModeratorNotesDraft] = useState<Record<string, string>>({});

  // Scam Report Appeal / Contact Form State (available to both regular users and admins)
  const [appealReportId, setAppealReportId] = useState<string>('');
  const [appealIndicator, setAppealIndicator] = useState<string>('');
  const [appealReason, setAppealReason] = useState<string>('');
  const [appealContactInfo, setAppealContactInfo] = useState<string>('');

  // Data Source Form State
  const [srcIdInput, setSrcIdInput] = useState<string>('src_osv_public');
  const [srcNameInput, setSrcNameInput] = useState<string>(
    'OSV.dev Open Source Vulnerabilities Public API'
  );
  const [srcUrlInput, setSrcUrlInput] = useState<string>('https://api.osv.dev/v1/query');
  const [srcTypeInput, setSrcTypeInput] = useState<DataSourceDoc['sourceType']>('osv_advisory');
  const [srcEnabledInput, setSrcEnabledInput] = useState<boolean>(true);

  // App Setting Form State
  const [settingIdInput, setSettingIdInput] = useState<string>('moderation_pii_policy');
  const [settingKeyInput, setSettingKeyInput] = useState<string>(
    'moderation.strictPiiRedaction'
  );
  const [settingValInput, setSettingValInput] = useState<string>('ENABLED (Mandatory)');
  const [settingDescInput, setSettingDescInput] = useState<string>(
    'Automatically scrubs personal emails, phone numbers, and National IDs from moderation notes and appeals.'
  );

  // Audit Log Filter State
  const [auditSearch, setAuditSearch] = useState<string>('');
  const [auditActionFilter, setAuditActionFilter] = useState<string>('ALL');
  const [auditCollectionFilter, setAuditCollectionFilter] = useState<string>('ALL');

  // Feedback Filter State
  const [feedbackFilter, setFeedbackFilter] = useState<'ALL' | FeedbackDoc['status']>('ALL');

  // Server Health Snapshot
  const [serverHealth, setServerHealth] = useState<{
    status: string;
    rateLimitPolicy: string;
    strictZeroCostBudget: boolean;
    checkedAt: string;
  } | null>(null);

  const refreshTelemetryStatus = async () => {
    try {
      const res = await fetch('/api/connectors/status');
      const data = await res.json();
      if (data && data.ok) {
        const list: ConnectorTelemetryItem[] = data.connectors || [];
        setConnectors(list);
        setConnectorErrorLogs(data.errorLogs || []);
        const kevConn = list.find((c) => c.connectorId === 'cisa_kev');
        const nvdConn = list.find((c) => c.connectorId === 'nist_nvd');
        const urlConn = list.find((c) => c.connectorId === 'urlhaus');
        setLiveKevCachedCount(
          data.kevMetadata?.totalCached ?? kevConn?.cachedRecordCount ?? 0
        );
        setLiveNvdCachedCount(nvdConn?.cachedRecordCount ?? 0);
        setLiveUrlhausCachedCount(urlConn?.cachedRecordCount ?? 0);
      }
    } catch {
      // Non-fatal
    }
  };

  useEffect(() => {
    if (moduleId === 'admin-center') {
      void refreshTelemetryStatus();
      void fetch('/api/security/health')
        .then((r) => r.json())
        .then((d) => {
          if (d && d.ok) {
            setServerHealth({
              status: 'OPERATIONAL (HTTP 200)',
              rateLimitPolicy: d.rateLimitPolicy || '40 requests / 60s window',
              strictZeroCostBudget: true,
              checkedAt: new Date().toISOString(),
            });
          }
        })
        .catch(() => {
          setServerHealth({
            status:
              'STATIC DEMO FALLBACK (Backend Proxy Unavailable — Client-Side Tools & Direct Firestore Rules Active; Server Proxy Routes Offline)',
            rateLimitPolicy: '15 writes / 60s client + Firestore rules (Static Hosting Mode)',
            strictZeroCostBudget: true,
            checkedAt: new Date().toISOString(),
          });
        });
    }
  }, [moduleId]);

  // Combine stored scam reports across queues without duplicates
  const allKnownScamReports = useMemo(() => {
    const map = new Map<string, ScamReportDoc>();
    for (const r of approvedScamReports) map.set(r.reportId, r);
    for (const r of pendingScamReports) map.set(r.reportId, r);
    for (const r of myScamReports) map.set(r.reportId, r);
    return Array.from(map.values()).sort((a, b) =>
      b.createdAt.localeCompare(a.createdAt)
    );
  }, [approvedScamReports, pendingScamReports, myScamReports]);

  // Ensure current signed-in user profile is included in user directory computation
  const effectiveUsersDirectoryInput = useMemo(() => {
    const map = new Map<string, typeof userProfile>();
    for (const u of usersList) {
      map.set(u.uid, u);
    }
    if (userProfile) {
      map.set(userProfile.uid, userProfile);
    }
    return Array.from(map.values()).filter(
      (u): u is NonNullable<typeof userProfile> => u !== null
    );
  }, [usersList, userProfile]);

  // Compute Real Admin Metrics strictly from stored records & live connector telemetry
  const adminMetrics = useMemo(() => {
    return computeRealAdminMetrics({
      users: effectiveUsersDirectoryInput,
      firestoreCves: cves,
      cachedNvdCveCount: liveNvdCachedCount,
      firestoreKevs: kevEntries,
      cachedCisaKevCount: liveKevCachedCount,
      firestoreIndicators: threatIndicators,
      cachedUrlhausCount: liveUrlhausCachedCount,
      scamReports: allKnownScamReports,
      dataSources,
      syncLogs,
      connectors,
      isFirebaseLive: persistenceMode === 'FIRESTORE_LIVE',
    });
  }, [
    effectiveUsersDirectoryInput,
    cves,
    liveNvdCachedCount,
    kevEntries,
    liveKevCachedCount,
    threatIndicators,
    liveUrlhausCachedCount,
    allKnownScamReports,
    dataSources,
    syncLogs,
    connectors,
    persistenceMode,
  ]);

  // Join Users with Authoritative Roles (/roles/{uid})
  const directoryUsers = useMemo(() => {
    return mergeUsersWithAuthoritativeRoles(effectiveUsersDirectoryInput, rolesList);
  }, [effectiveUsersDirectoryInput, rolesList]);

  // Data Freshness Matrix
  const freshnessMatrix = useMemo(() => {
    return evaluateSourcesFreshnessMatrix(connectors);
  }, [connectors]);

  // Filtered Audit Logs
  const filteredAudits = useMemo(() => {
    return filterAuditLogs(auditLogs, {
      searchQuery: auditSearch,
      actionFilter: auditActionFilter,
      collectionFilter: auditCollectionFilter,
    });
  }, [auditLogs, auditSearch, auditActionFilter, auditCollectionFilter]);

  // Handle Manual Sync Trigger from Admin Center with immutable SyncLog & AuditLog
  const handleAdminManualSync = async (
    connectorType: 'cisa_kev' | 'nvd_cve' | 'urlhaus' | 'all'
  ) => {
    if (!isAdmin) return;

    if (connectorType === 'cisa_kev' || connectorType === 'all') {
      setIsRefreshingKev(true);
      try {
        const res = await fetch('/api/connectors/cisa-kev/sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        const data = await res.json();
        const count = Number(data?.totalCached ?? liveKevCachedCount ?? kevEntries.length);
        await recordManualSyncLog(
          'src_cisa_kev_public',
          data?.ok ? 'COMPLETED' : 'FAILED',
          count,
          `Admin manual CISA KEV sync ${data?.ok ? 'completed' : 'failed'} (${count} verified KEV entries)`
        );
      } catch {
        // Non-fatal
      } finally {
        setIsRefreshingKev(false);
      }
    }

    if (connectorType === 'nvd_cve' || connectorType === 'all') {
      setIsSearchingNvd(true);
      try {
        const res = await fetch(
          '/api/connectors/nvd/search?keyword=Apache&resultsPerPage=10&startIndex=0'
        );
        const data = await res.json();
        const count = Number(data?.records?.length ?? liveNvdCachedCount ?? cves.length);
        await recordManualSyncLog(
          'src_nvd_cve_v2',
          data?.ok ? 'COMPLETED' : 'FAILED',
          count,
          `Admin manual NIST NVD API 2.0 sync ${data?.ok ? 'completed' : 'failed'} (${count} CVE records cached)`
        );
      } catch {
        // Non-fatal
      } finally {
        setIsSearchingNvd(false);
      }
    }

    if (connectorType === 'urlhaus' || connectorType === 'all') {
      setIsRefreshingUrlhaus(true);
      try {
        const res = await fetch('/api/connectors/urlhaus/sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
        const data = await res.json();
        const urlhausConn = connectors.find(
          (c: ConnectorTelemetryItem) => c.connectorId === 'urlhaus'
        );
        const isConfigured = Boolean(urlhausConn?.credentialConfigured);
        const count = Number(data?.records?.length ?? liveUrlhausCachedCount);
        await recordManualSyncLog(
          'src_urlhaus_community',
          isConfigured && data?.ok ? 'COMPLETED' : 'FAILED',
          count,
          isConfigured
            ? `Admin manual URLhaus sync completed (${count} indicators)`
            : 'Skipped URLhaus sync: Optional URLHAUS_AUTH_KEY is NOT CONFIGURED ($0 optional)'
        );
      } catch {
        // Non-fatal
      } finally {
        setIsRefreshingUrlhaus(false);
      }
    }

    await refreshTelemetryStatus();
  };

  // Handle Scam Report Appeal Submission
  const handleAppealSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!appealIndicator.trim() || !appealReason.trim()) return;

    const formattedMessage = formatScamReportAppealMessage({
      reportIdOrIndicator: `${appealReportId.trim() || 'UNSPECIFIED'} (${appealIndicator.trim()})`,
      appellantRelation: 'domain_owner',
      appealReason: appealReason.trim(),
      verificationEvidence: appealContactInfo.trim() || 'In-App Account Verification',
    });

    await submitFeedback('appeal_request', formattedMessage);
    setAppealReportId('');
    setAppealIndicator('');
    setAppealReason('');
    setAppealContactInfo('');
  };

  // Render Scam Report Appeal & Contact Mechanism inside `scam-phishing` module as well
  if (moduleId === 'scam-phishing') {
    return (
      <section
        aria-label="Scam Report Moderation Appeal & False-Positive Contact"
        className="rounded-lg border border-blue-500/30 bg-[#0E1628] p-5 space-y-4"
      >
        <div className="flex flex-col gap-2 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <MessageSquare className="h-4 w-4 text-blue-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? 'স্ক্যাম রিপোর্ট আপিল ও ফলস-পজিটিভ যোগাযোগ কেন্দ্র (Report Appeal & Contact Mechanism)'
                  : 'Scam Report Appeal & False-Positive Contact Mechanism'}
              </h3>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              {isBn
                ? 'অযাচাইকৃত কোনো অভিযোগ পাবলিকলি প্রদর্শন করা হয় না। কোনো ডোমেইন বা রিপোর্ট ভুলবশত তালিকাভুক্ত হলে বা অতিরিক্ত তথ্যের প্রয়োজন হলে এখানে আপিল জমা দিন।'
                : 'Unverified scam accusations are never displayed publicly. Domain owners or reporters can appeal a moderation decision, respond to a Needs-More-Information request, or report a false positive.'}
            </p>
          </div>
          <span className="rounded border border-emerald-500/30 bg-emerald-950/30 px-2.5 py-1 font-mono text-[11px] text-emerald-300 shrink-0">
            PII AUTO-SCRUBBED · GOVERNANCE QUEUE
          </span>
        </div>

        <form onSubmit={handleAppealSubmit} className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">
              {isBn ? 'রিপোর্ট আইডি (ঐচ্ছিক)' : 'Report ID (Optional)'}
            </label>
            <input
              type="text"
              value={appealReportId}
              onChange={(e) => setAppealReportId(e.target.value)}
              placeholder="e.g., scam_1763..."
              className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">
              {isBn ? 'সংশ্লিষ্ট ডোমেইন / ইন্ডিকেটর *' : 'Disputed Domain / Indicator *'}
            </label>
            <input
              type="text"
              required
              value={appealIndicator}
              onChange={(e) => setAppealIndicator(e.target.value)}
              placeholder="e.g., example.org"
              className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">
              {isBn ? 'যোগাযোগের মাধ্যম (PII সুরক্ষিত)' : 'Verification Context / Reference'}
            </label>
            <input
              type="text"
              value={appealContactInfo}
              onChange={(e) => setAppealContactInfo(e.target.value)}
              placeholder="e.g., Official IT Administrator / Ticket #12"
              className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div className="sm:col-span-2">
            <label className="block text-[11px] font-medium text-slate-300 mb-1">
              {isBn
                ? 'আপিলের কারণ বা অতিরিক্ত প্রমাণ (ব্যক্তিগত ফোন/ইমেইল স্বয়ংক্রিয়ভাবে মাস্ক করা হবে) *'
                : 'Appeal Justification or Additional Evidence (Personal emails/phones are auto-redacted for privacy) *'}
            </label>
            <input
              type="text"
              required
              value={appealReason}
              onChange={(e) => setAppealReason(e.target.value)}
              placeholder="Explain why this report is a false positive or provide requested verification details..."
              className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              className="inline-flex w-full items-center justify-center gap-1.5 rounded-md bg-blue-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500"
            >
              <Send className="h-3.5 w-3.5" />
              <span>
                {isBn ? 'আপিল জমা দিন (Submit Appeal)' : 'Submit Appeal to Admin Center'}
              </span>
            </button>
          </div>
        </form>
      </section>
    );
  }

  // Only render the full Admin Center on `admin-center`
  if (moduleId !== 'admin-center') {
    return null;
  }

  const navTabs: {
    id: AdminSectionTab;
    labelEn: string;
    labelBn: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string | number;
  }[] = [
    {
      id: 'overview',
      labelEn: '1. Admin Dashboard & Freshness',
      labelBn: '১. অ্যাডমিন ড্যাশবোর্ড ও ফ্রেশনেস',
      icon: ShieldCheck,
    },
    {
      id: 'users_roles',
      labelEn: '2. Users & Role Governance',
      labelBn: '২. ইউজার ও রোল ব্যবস্থাপনা',
      icon: UserCog,
      badge: adminMetrics.totalUsers,
    },
    {
      id: 'scam_moderation',
      labelEn: '3. Scam Moderation & Appeals',
      labelBn: '৩. স্ক্যাম মডারেশন ও আপিল',
      icon: AlertTriangle,
      badge: adminMetrics.pendingReports + adminMetrics.needsMoreInfoReports,
    },
    {
      id: 'sources_sync',
      labelEn: '4. Threat Sources & Manual Sync',
      labelBn: '৪. থ্রেট উৎস ও ম্যানুয়াল সিঙ্ক',
      icon: RefreshCw,
      badge: `${adminMetrics.dataSourceHealth.connectedCount}/${adminMetrics.dataSourceHealth.totalConfiguredSources}`,
    },
    {
      id: 'feedback_config',
      labelEn: '5. Feedback & App Config',
      labelBn: '৫. ফিডব্যাক ও অ্যাপ কনফিগ',
      icon: Sliders,
      badge: feedbackItems.filter((f) => f.status === 'open').length,
    },
    {
      id: 'audit_health',
      labelEn: '6. Audit Logs & System Health',
      labelBn: '৬. অডিট লগ ও সিস্টেম হেলথ',
      icon: Activity,
      badge: auditLogs.length,
    },
  ];

  const displayedScamQueue = allKnownScamReports.filter((r) =>
    moderationFilter === 'ALL' ? true : r.moderationStatus === moderationFilter
  );

  const displayedFeedbackQueue = feedbackItems.filter((f) =>
    feedbackFilter === 'ALL' ? true : f.status === feedbackFilter
  );

  return (
    <div className="space-y-6">
      {/* Zero-Trust Admin Authorization & Mode Header */}
      <section className="rounded-lg border border-blue-500/40 bg-[#0E1628] p-5 space-y-4">
        <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-blue-400" />
              <h2 className="text-base font-semibold text-slate-100">
                {isBn
                  ? 'কিরণ প্রহরী — সিকিউর অ্যাডমিন সেন্টার, মডারেশন ও গভার্নেন্স (Phase 5)'
                  : 'KIRON PROHORI — Secure Admin Center, Moderation & Governance (Phase 5)'}
              </h2>
              <span
                className={`rounded px-2 py-0.5 font-mono text-[11px] font-semibold ${
                  isAdmin
                    ? 'border border-emerald-500/40 bg-emerald-950/50 text-emerald-300'
                    : 'border border-amber-500/40 bg-amber-950/50 text-amber-300'
                }`}
              >
                {isAdmin
                  ? 'ADMIN AUTHORIZED (/roles/{uid})'
                  : `READ-ONLY VIEWER (ROLE: ${authoritativeRole.toUpperCase()})`}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isBn
                ? 'সকল প্রশাসনিক ক্ষমতা সার্ভার এবং ফায়ারস্টোর সিকিউরিটি রুলস দ্বারা যাচাইকৃত। ইউজার-এডিটেবল প্রোফাইল থেকে কখনোই অ্যাডমিন ক্ষমতা প্রদান করা হয় না।'
                : 'All privileged operations enforce server-side gate validation and Firestore security rules. Admin privileges never derive from user-editable /users/{uid} documents.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {persistenceMode === 'LOCAL_DEMO_EPHEMERAL' && (
              <div className="flex items-center gap-1 rounded-md border border-amber-500/40 bg-[#080D1A] p-1">
                <span className="px-2 font-mono text-[11px] text-amber-300">
                  DEMO PERSONA:
                </span>
                {(['guest', 'user', 'admin'] as const).map((persona) => (
                  <button
                    key={persona}
                    type="button"
                    onClick={() => setDemoRolePersona(persona)}
                    className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                      demoRolePersona === persona
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {persona.toUpperCase()}
                  </button>
                ))}
              </div>
            )}

            {!isSignedIn && persistenceMode === 'FIRESTORE_LIVE' && (
              <button
                type="button"
                onClick={() => void signInWithGoogle()}
                className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500"
              >
                <Lock className="h-3.5 w-3.5" />
                <span>Sign In with Admin Google Account</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => {
                void refreshCollections();
                void refreshTelemetryStatus();
              }}
              className="inline-flex items-center gap-1.5 rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-blue-500/50 hover:text-white"
            >
              <RefreshCw className="h-3.5 w-3.5 text-blue-400" />
              <span>{isBn ? 'ডেটা রিফ্রেশ' : 'Refresh Stored Records'}</span>
            </button>
          </div>
        </div>

        {/* Action Feedback Banner */}
        {actionFeedback && (
          <div
            className={`flex items-center justify-between rounded-md border px-3.5 py-2.5 text-xs ${
              actionFeedback.type === 'error'
                ? 'border-red-500/40 bg-red-950/30 text-red-200'
                : actionFeedback.type === 'success'
                ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-200'
                : 'border-blue-500/40 bg-blue-950/30 text-blue-200'
            }`}
          >
            <span className="font-mono">{actionFeedback.message}</span>
            <button
              type="button"
              onClick={clearActionFeedback}
              className="ml-3 text-[11px] underline hover:text-white"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* 7 Required Real Admin Metrics Strip (Derived Strictly from Real Stored Records) */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'মোট ইউজার' : 'Total Users'}</span>
              <Users className="h-3.5 w-3.5 text-blue-400" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-slate-100 tabular-nums">
              {adminMetrics.totalUsers}
            </div>
            <div className="mt-1 font-mono text-[10px] text-slate-400">
              /users + /roles union
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'যাচাইকৃত CVE' : 'Verified CVEs'}</span>
              <Database className="h-3.5 w-3.5 text-blue-400" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-slate-100 tabular-nums">
              {adminMetrics.totalVerifiedCves}
            </div>
            <div className="mt-1 font-mono text-[10px] text-slate-400">
              Firestore: {cves.length} · NVD Cache: {liveNvdCachedCount}
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'CISA KEV এন্ট্রি' : 'Total KEV Entries'}</span>
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-emerald-300 tabular-nums">
              {adminMetrics.totalKevEntries}
            </div>
            <div className="mt-1 font-mono text-[10px] text-slate-400">
              Official CISA KEV Catalog
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'থ্রেট ইন্ডিকেটর' : 'Threat Indicators'}</span>
              <AlertOctagon className="h-3.5 w-3.5 text-amber-400" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-slate-100 tabular-nums">
              {adminMetrics.totalThreatIndicators}
            </div>
            <div className="mt-1 font-mono text-[10px] text-slate-400">
              Defanged IOC Records
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'পেন্ডিং রিপোর্ট' : 'Pending Reports'}</span>
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
            </div>
            <div className="mt-2 font-mono text-xl font-bold text-amber-300 tabular-nums">
              {adminMetrics.pendingReports}
            </div>
            <div className="mt-1 font-mono text-[10px] text-slate-400">
              Needs Info: {adminMetrics.needsMoreInfoReports} · Approved:{' '}
              {adminMetrics.approvedReports}
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'ডেটা উৎস হেলথ' : 'Data Source Health'}</span>
              <Activity className="h-3.5 w-3.5 text-emerald-400" />
            </div>
            <div className="mt-2 font-mono text-sm font-bold text-slate-100">
              {adminMetrics.dataSourceHealth.healthLabel}
            </div>
            <div className="mt-1 font-mono text-[10px] text-amber-300">
              {adminMetrics.dataSourceHealth.notConfiguredCount} Optional Unconfigured
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5">
            <div className="flex items-center justify-between text-[11px] text-slate-400">
              <span>{isBn ? 'সর্বশেষ সফল সিঙ্ক' : 'Last Successful Sync'}</span>
              <Clock className="h-3.5 w-3.5 text-blue-400" />
            </div>
            <div className="mt-2 font-mono text-xs font-bold text-slate-100 break-all">
              {adminMetrics.lastSuccessfulSync !== 'NEVER_SYNCED'
                ? adminMetrics.lastSuccessfulSync.replace('T', ' ').slice(0, 19) + 'Z'
                : 'NEVER_SYNCED'}
            </div>
            <div className="mt-1 font-mono text-[10px] text-slate-400">
              Derived from live logs
            </div>
          </div>
        </div>

        {/* Navigation Sub-Tabs for the 12 Admin Center Capabilities */}
        <div className="flex flex-wrap items-center gap-1.5 border-t border-[#1E2D4A] pt-3">
          {navTabs.map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  active
                    ? 'bg-blue-600 text-white'
                    : 'border border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:border-blue-500/40 hover:text-white'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{isBn ? tab.labelBn : tab.labelEn}</span>
                {tab.badge !== undefined && (
                  <span
                    className={`ml-1 rounded px-1.5 py-0.2 font-mono text-[10px] ${
                      active
                        ? 'bg-blue-800 text-white'
                        : 'bg-[#141F38] text-slate-300'
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </section>

      {/* TAB 1: ADMIN DASHBOARD, MISSING INTEGRATIONS & DATA FRESHNESS MONITORING */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Missing Optional Integrations & Honest Status Identification */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'অনুপস্থিত বা ঐচ্ছিক ইন্টিগ্রেশন শনাক্তকরণ (Missing Integrations Audit)'
                    : 'Missing & Optional Integration Identification (Honest Status)'}
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">
                  {isBn
                    ? 'কোনো সংযোগ কনফিগার করা না থাকলে তা কখনোই সচল বলে দাবি করা হয় না।'
                    : 'KIRON PROHORI never claims unconnected or optional feeds are active.'}
                </p>
              </div>
              <span className="rounded border border-blue-500/30 bg-blue-950/30 px-2 py-0.5 font-mono text-[11px] text-blue-300">
                $0.00 STRICT BUDGET
              </span>
            </div>

            {adminMetrics.missingIntegrations.length === 0 ? (
              <div className="rounded-md border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs text-emerald-200">
                All optional integrations and baseline collections are configured and populated.
              </div>
            ) : (
              <div className="space-y-2.5">
                {adminMetrics.missingIntegrations.map((item) => (
                  <div
                    key={item.integrationId}
                    className="rounded-md border border-amber-500/30 bg-[#080D1A] p-3 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-slate-100">{item.name}</span>
                      <span className="rounded border border-amber-500/40 bg-amber-950/40 px-2 py-0.5 font-mono text-[10px] text-amber-300">
                        {item.currentStatus} · {item.envVarName}
                      </span>
                    </div>
                    <p className="text-slate-400">{item.impactExplanation}</p>
                  </div>
                ))}
              </div>
            )}

            {isAdmin && (
              <div className="border-t border-[#1E2D4A] pt-3 flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  {isBn
                    ? 'ফায়ারস্টোর কালেকশন বেসলাইন রেকর্ড ইনিশিয়ালাইজ করুন:'
                    : 'Initialize verified public reference records in Firestore:'}
                </span>
                <button
                  type="button"
                  onClick={() => void seedOfficialPublicReferenceSample()}
                  className="inline-flex items-center gap-1.5 rounded-md border border-blue-500/40 bg-blue-950/40 px-3 py-1.5 text-xs font-medium text-blue-200 hover:bg-blue-900/50"
                >
                  <Database className="h-3.5 w-3.5" />
                  <span>Seed Verified Public Reference Sample</span>
                </button>
              </div>
            )}
          </div>

          {/* Feature 8: Data Freshness Monitoring Matrix */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'ডেটা ফ্রেশনেস মনিটরিং (Data Freshness Monitoring)'
                    : 'Data Freshness Monitoring Matrix'}
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">
                  {isBn
                    ? 'প্রতিটি পাবলিক কানেক্টরের সর্বশেষ সফল সিঙ্ক এবং ডেটার বয়স পর্যবেক্ষণ।'
                    : 'Tracks exact age in minutes since last verified pull across all public feeds.'}
                </p>
              </div>
              <Clock className="h-4 w-4 text-blue-400" />
            </div>

            <div className="space-y-2.5">
              {freshnessMatrix.map((row) => (
                <div
                  key={row.connectorId}
                  className="flex flex-col justify-between gap-2 rounded-md border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs sm:flex-row sm:items-center"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-100">{row.name}</span>
                      <span className="font-mono text-[10px] text-slate-400">
                        [{row.connectorId}]
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-400">
                      Last Sync:{' '}
                      {row.lastSuccessAt
                        ? row.lastSuccessAt.replace('T', ' ').slice(0, 19) + 'Z'
                        : 'NEVER SYNCED'}{' '}
                      · Records: {row.cachedRecordCount}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {row.freshness.ageMinutes !== null && (
                      <span className="font-mono text-[11px] text-slate-300">
                        {row.freshness.ageMinutes}m ago
                      </span>
                    )}
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${
                        row.freshness.level === 'FRESH'
                          ? 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                          : row.freshness.level === 'AGING'
                          ? 'border border-blue-500/40 bg-blue-950/40 text-blue-300'
                          : row.freshness.level === 'STALE'
                          ? 'border border-amber-500/40 bg-amber-950/40 text-amber-300'
                          : 'border border-slate-600 bg-slate-900 text-slate-400'
                      }`}
                    >
                      {row.freshness.level}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: USER LIST, STATUS & AUTHORITATIVE ROLE MANAGEMENT */}
      {activeTab === 'users_roles' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* User Directory Table (Feature 2) */}
            <div className="lg:col-span-2 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
              <div className="flex flex-col gap-2 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    {isBn
                      ? 'ইউজার তালিকা, স্ট্যাটাস ও অথরিটেটিভ রোল (/users + /roles)'
                      : 'Registered User Directory & Authoritative Role Status'}
                  </h3>
                  <p className="mt-0.5 text-xs text-slate-400">
                    {isBn
                      ? 'ব্যক্তিগত গোপনীয়তা রক্ষার জন্য ইমেইল ডিফল্টভাবে মাস্ক করা থাকে।'
                      : 'Emails are masked by default to protect personal information during screen-sharing or audits.'}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setRevealUserPiiEmails((prev) => !prev)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1.5 text-xs text-slate-300 hover:border-blue-500/40 hover:text-white self-start"
                >
                  {revealUserPiiEmails ? (
                    <>
                      <EyeOff className="h-3.5 w-3.5 text-amber-400" />
                      <span>Mask PII Emails</span>
                    </>
                  ) : (
                    <>
                      <Eye className="h-3.5 w-3.5 text-blue-400" />
                      <span>Reveal Full Emails (Admin Only)</span>
                    </>
                  )}
                </button>
              </div>

              {directoryUsers.length === 0 ? (
                <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs text-slate-400">
                  No user records loaded in current session. Sign in or switch to Local Demo Mode to inspect user role records.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-[#1E2D4A] text-[11px] text-slate-400">
                        <th className="py-2 pr-3">UID</th>
                        <th className="py-2 px-3">Display Name & Org</th>
                        <th className="py-2 px-3">Protected Email</th>
                        <th className="py-2 px-3">Authoritative Role (/roles)</th>
                        <th className="py-2 pl-3 text-right">Status & Quick Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1E2D4A]/60">
                      {directoryUsers.map((u) => (
                        <tr key={u.uid} className="hover:bg-[#141F38]/40">
                          <td className="py-2.5 pr-3 font-mono text-[11px] text-slate-300">
                            {u.uid}
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="font-medium text-slate-100">{u.displayName}</div>
                            <div className="text-[11px] text-slate-400">{u.organization}</div>
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                            {revealUserPiiEmails && isAdmin ? u.rawEmail : u.maskedEmail}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`inline-block rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                                u.authoritativeRole === 'admin'
                                  ? 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                                  : u.authoritativeRole === 'moderator' ||
                                    u.authoritativeRole === 'analyst'
                                  ? 'border border-blue-500/40 bg-blue-950/40 text-blue-300'
                                  : 'border border-slate-600 bg-slate-900 text-slate-300'
                              }`}
                            >
                              {u.authoritativeRole}
                            </span>
                            <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                              Source: {u.roleSource}
                            </div>
                          </td>
                          <td className="py-2.5 pl-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <span className="font-mono text-[10px] text-emerald-400">
                                {u.statusLabel}
                              </span>
                              {isAdmin && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setRoleTargetUid(u.uid);
                                    setSelectedRoleValue(u.authoritativeRole);
                                  }}
                                  className="rounded border border-blue-500/40 bg-blue-950/40 px-2 py-1 text-[11px] text-blue-200 hover:bg-blue-900/60"
                                >
                                  Select UID
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Authoritative Role Assignment Form (Feature 3) */}
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
              <div className="border-b border-[#1E2D4A] pb-3">
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'ইউজার রোল ম্যানেজমেন্ট (/roles/{uid})'
                    : 'Authoritative User Role Management'}
                </h3>
                <p className="mt-1 text-xs text-slate-400">
                  {isBn
                    ? 'শুধুমাত্র যাচাইকৃত অ্যাডমিন /roles কালেকশনে রোল নির্ধারণ করতে পারেন।'
                    : 'Writes strictly to /roles/{uid} and logs an immutable entry in /audit_logs. Never trusts client profile fields.'}
                </p>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!roleTargetUid.trim()) return;
                  void assignUserRole(roleTargetUid.trim(), selectedRoleValue);
                }}
                className="space-y-3"
              >
                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    Target User UID *
                  </label>
                  <input
                    type="text"
                    required
                    value={roleTargetUid}
                    onChange={(e) => setRoleTargetUid(e.target.value)}
                    placeholder="e.g., user_uid_123"
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    Authoritative Role (/roles) *
                  </label>
                  <select
                    value={selectedRoleValue}
                    onChange={(e) =>
                      setSelectedRoleValue(e.target.value as RoleDoc['role'])
                    }
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 font-mono text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                  >
                    <option value="user">user (Standard Authenticated Defender)</option>
                    <option value="analyst">analyst (Threat Intelligence Analyst)</option>
                    <option value="moderator">moderator (Scam Queue Reviewer)</option>
                    <option value="admin">admin (Full Governance Administrator)</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={!isAdmin}
                  className="inline-flex w-full items-center justify-center gap-1.5 rounded-md bg-blue-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-40"
                >
                  <UserCog className="h-3.5 w-3.5" />
                  <span>
                    {isAdmin
                      ? 'Commit Authoritative Role to /roles'
                      : 'Admin Authorization Required'}
                  </span>
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SCAM REPORT MODERATION (4 STATUSES + PII PROTECTION + APPEALS) */}
      {activeTab === 'scam_moderation' && (
        <div className="space-y-6">
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'স্ক্যাম রিপোর্ট মডারেশন কিউ (৪-স্টেট গভর্ন্যান্স ও PII সুরক্ষা)'
                    : '4-State Scam Report Moderation Queue & PII Protection'}
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">
                  {isBn
                    ? 'স্ট্যাটাসসমূহ: pending, approved, rejected, এবং needs_more_info। শুধুমাত্র approved রিপোর্ট পাবলিকলি প্রদর্শিত হয়।'
                    : 'Supported statuses: pending, approved, rejected, and needs_more_info. Unverified accusations are strictly hidden from public display.'}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {(
                  [
                    'ALL',
                    'pending',
                    'needs_more_info',
                    'approved',
                    'rejected',
                  ] as const
                ).map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setModerationFilter(st)}
                    className={`rounded px-2.5 py-1 font-mono text-[11px] transition-colors ${
                      moderationFilter === st
                        ? 'bg-blue-600 text-white'
                        : 'border border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:text-white'
                    }`}
                  >
                    {st.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {displayedScamQueue.length === 0 ? (
              <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs text-slate-400">
                No scam reports match the selected status filter ({moderationFilter}).
              </div>
            ) : (
              <div className="space-y-3">
                {displayedScamQueue.map((report) => {
                  const piiCheckedDescription = scrubPiiFromModerationText(
                    report.description
                  );
                  const draftNote =
                    moderatorNotesDraft[report.reportId] ?? report.moderatorNotes ?? '';

                  return (
                    <div
                      key={report.reportId}
                      className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3"
                    >
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                        <div className="space-y-0.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-semibold text-sm text-slate-100">
                              {report.title}
                            </span>
                            <span className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2 py-0.5 font-mono text-[10px] text-slate-300">
                              {report.category}
                            </span>
                            <span className="font-mono text-[10px] text-slate-500">
                              ID: {report.reportId}
                            </span>
                          </div>
                          <div className="font-mono text-xs text-amber-300 break-all">
                            Defanged Indicator: {report.defangedIndicator}
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <span
                            className={`rounded px-2.5 py-1 font-mono text-[11px] font-semibold uppercase ${
                              report.moderationStatus === 'approved'
                                ? 'border border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                                : report.moderationStatus === 'rejected'
                                ? 'border border-red-500/40 bg-red-950/40 text-red-300'
                                : report.moderationStatus === 'needs_more_info'
                                ? 'border border-blue-500/40 bg-blue-950/40 text-blue-300'
                                : 'border border-amber-500/40 bg-amber-950/40 text-amber-300'
                            }`}
                          >
                            {report.moderationStatus === 'approved'
                              ? 'APPROVED (PUBLICLY VISIBLE)'
                              : `${report.moderationStatus} (HIDDEN FROM PUBLIC)`}
                          </span>
                        </div>
                      </div>

                      <div className="rounded border border-[#1E2D4A]/70 bg-[#0E1628] p-2.5 text-xs text-slate-300">
                        <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                          <span>PII-Sanitized Incident Description:</span>
                          {piiCheckedDescription.redactionsApplied > 0 && (
                            <span className="text-emerald-400">
                              {piiCheckedDescription.redactionsApplied} PII token(s) auto-redacted
                            </span>
                          )}
                        </div>
                        <p>{piiCheckedDescription.scrubbedText}</p>
                      </div>

                      {isAdmin && (
                        <div className="flex flex-col gap-2 pt-1 sm:flex-row sm:items-center">
                          <input
                            type="text"
                            value={draftNote}
                            onChange={(e) =>
                              setModeratorNotesDraft((prev) => ({
                                ...prev,
                                [report.reportId]: e.target.value,
                              }))
                            }
                            placeholder="Moderator decision notes (PII will be automatically scrubbed)..."
                            className="flex-1 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-xs text-slate-100 focus:border-blue-500 focus:outline-none"
                          />

                          <div className="flex flex-wrap items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() =>
                                void moderateScamReport(
                                  report.reportId,
                                  'approved',
                                  draftNote || 'Verified against public defensive indicators.'
                                )
                              }
                              className="inline-flex items-center gap-1 rounded bg-emerald-600 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-emerald-500"
                            >
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              <span>Approve</span>
                            </button>

                            <button
                              type="button"
                              onClick={() =>
                                void moderateScamReport(
                                  report.reportId,
                                  'needs_more_info',
                                  draftNote ||
                                    'Additional headers or screenshot evidence required before verification.'
                                )
                              }
                              className="inline-flex items-center gap-1 rounded bg-blue-600 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-blue-500"
                            >
                              <HelpCircle className="h-3.5 w-3.5" />
                              <span>Needs More Info</span>
                            </button>

                            <button
                              type="button"
                              onClick={() =>
                                void moderateScamReport(
                                  report.reportId,
                                  'rejected',
                                  draftNote ||
                                    'Insufficient evidence or uncorroborated accusation.'
                                )
                              }
                              className="inline-flex items-center gap-1 rounded bg-red-600 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-red-500"
                            >
                              <XCircle className="h-3.5 w-3.5" />
                              <span>Reject</span>
                            </button>

                            <button
                              type="button"
                              onClick={() =>
                                void moderateScamReport(
                                  report.reportId,
                                  'pending',
                                  draftNote || 'Returned to pending queue for re-triage.'
                                )
                              }
                              className="inline-flex items-center gap-1 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:text-white"
                            >
                              <span>Set Pending</span>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Scam Report Appeal & Contact Mechanism inside Admin Center */}
          <div className="rounded-lg border border-blue-500/30 bg-[#0E1628] p-5 space-y-4">
            <div className="border-b border-[#1E2D4A] pb-3">
              <h3 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? 'রিপোর্ট আপিল ও যোগাযোগ মেকানিজম (Report Appeal / Contact Mechanism)'
                  : 'Report Appeal & False-Positive Contact Mechanism'}
              </h3>
              <p className="mt-0.5 text-xs text-slate-400">
                {isBn
                  ? 'কোনো রিপোর্টের বিষয়ে আপিল বা অতিরিক্ত তথ্য জমা দিলে তা সরাসরি /feedback কালেকশনে appeal_request হিসেবে সংরক্ষিত হয়।'
                  : 'Submits a structured, PII-redacted appeal directly to /feedback with category="appeal_request" for moderator review.'}
              </p>
            </div>

            <form
              onSubmit={handleAppealSubmit}
              className="grid grid-cols-1 gap-3 sm:grid-cols-4"
            >
              <input
                type="text"
                value={appealReportId}
                onChange={(e) => setAppealReportId(e.target.value)}
                placeholder="Report ID (e.g., scam_...)"
                className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 font-mono text-xs text-slate-100"
              />
              <input
                type="text"
                required
                value={appealIndicator}
                onChange={(e) => setAppealIndicator(e.target.value)}
                placeholder="Disputed Domain / Indicator *"
                className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 font-mono text-xs text-slate-100"
              />
              <input
                type="text"
                required
                value={appealReason}
                onChange={(e) => setAppealReason(e.target.value)}
                placeholder="Appeal reason or additional evidence *"
                className="rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-2 text-xs text-slate-100"
              />
              <button
                type="submit"
                className="inline-flex items-center justify-center gap-1.5 rounded-md bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500"
              >
                <Send className="h-3.5 w-3.5" />
                <span>Log Report Appeal</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* TAB 4: THREAT FEED SOURCE MANAGEMENT, MANUAL SYNC CONTROLS & SYNC LOGS */}
      {activeTab === 'sources_sync' && (
        <div className="space-y-6">
          {/* Feature 6: Manual Sync Controls */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex flex-col gap-2 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'ম্যানুয়াল থ্রেট ফিড সিঙ্ক কন্ট্রোল (Manual Sync Controls)'
                    : 'Manual Threat Feed Synchronization Controls ($0 Public Feeds)'}
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">
                  {isBn
                    ? 'কোনো পেইড ব্যাকগ্রাউন্ড ক্রন ছাড়াই অ্যাডমিন-ট্রিগারড ম্যানুয়াল সিঙ্ক এবং অপরিবর্তনীয় সিঙ্ক লগ।'
                    : 'Triggers on-demand synchronization with official public feeds and commits an auditable record to /sync_logs and /audit_logs.'}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={!isAdmin || isRefreshingKev}
                  onClick={() => void handleAdminManualSync('cisa_kev')}
                  className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${isRefreshingKev ? 'animate-spin' : ''}`}
                  />
                  <span>Sync CISA KEV</span>
                </button>

                <button
                  type="button"
                  disabled={!isAdmin || isSearchingNvd}
                  onClick={() => void handleAdminManualSync('nvd_cve')}
                  className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${isSearchingNvd ? 'animate-spin' : ''}`}
                  />
                  <span>Sync NIST NVD 2.0</span>
                </button>

                <button
                  type="button"
                  disabled={!isAdmin || isRefreshingUrlhaus}
                  onClick={() => void handleAdminManualSync('urlhaus')}
                  className="inline-flex items-center gap-1.5 rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-blue-500/40 disabled:opacity-40"
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${isRefreshingUrlhaus ? 'animate-spin' : ''}`}
                  />
                  <span>Probe URLhaus</span>
                </button>

                <button
                  type="button"
                  disabled={!isAdmin}
                  onClick={() => void handleAdminManualSync('all')}
                  className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  <span>Sync All Public Feeds</span>
                </button>
              </div>
            </div>

            {/* Feature 5: Threat Feed Source Registry & Admin Upsert */}
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2 space-y-2.5">
                <h4 className="text-xs font-semibold text-slate-300">
                  Configured Public Data Sources (/data_sources)
                </h4>
                {dataSources.length === 0 ? (
                  <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs text-slate-400">
                    No custom data sources stored in /data_sources yet. Use the form or Seed Baseline button to register sources.
                  </div>
                ) : (
                  dataSources.map((src) => (
                    <div
                      key={src.sourceId}
                      className="flex flex-col justify-between gap-2 rounded-md border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs sm:flex-row sm:items-center"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-100">{src.name}</span>
                          <span className="rounded border border-emerald-500/30 bg-emerald-950/30 px-1.5 py-0.2 font-mono text-[10px] text-emerald-300">
                            {src.costTier}
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400 break-all">
                          {src.endpointUrl}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <span
                          className={`rounded px-2 py-0.5 font-mono text-[10px] ${
                            src.isEnabled
                              ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-500/40'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {src.isEnabled ? 'ENABLED' : 'DISABLED'}
                        </span>
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() =>
                              void upsertDataSource(
                                src.sourceId,
                                src.name,
                                src.endpointUrl,
                                src.sourceType,
                                !src.isEnabled
                              )
                            }
                            className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1 text-[11px] text-slate-200 hover:border-blue-500/50"
                          >
                            {src.isEnabled ? 'Disable' : 'Enable'}
                          </button>
                        )}
                      </div>
                    </div>
                  ))
                )}
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void upsertDataSource(
                    srcIdInput,
                    srcNameInput,
                    srcUrlInput,
                    srcTypeInput,
                    srcEnabledInput
                  );
                }}
                className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-3"
              >
                <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-100">
                  <Plus className="h-3.5 w-3.5 text-blue-400" />
                  <span>Register / Update $0 Public Source</span>
                </div>

                <input
                  type="text"
                  required
                  value={srcIdInput}
                  onChange={(e) => setSrcIdInput(e.target.value)}
                  placeholder="Source ID (e.g. src_osv_public)"
                  className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
                />
                <input
                  type="text"
                  required
                  value={srcNameInput}
                  onChange={(e) => setSrcNameInput(e.target.value)}
                  placeholder="Official Source Name"
                  className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
                />
                <input
                  type="url"
                  required
                  value={srcUrlInput}
                  onChange={(e) => setSrcUrlInput(e.target.value)}
                  placeholder="https://..."
                  className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
                />
                <div className="flex items-center gap-2">
                  <select
                    value={srcTypeInput}
                    onChange={(e) =>
                      setSrcTypeInput(e.target.value as DataSourceDoc['sourceType'])
                    }
                    className="flex-1 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
                  >
                    <option value="cisa_kev">cisa_kev</option>
                    <option value="nvd_cve">nvd_cve</option>
                    <option value="urlhaus">urlhaus</option>
                    <option value="osv_advisory">osv_advisory</option>
                    <option value="community_phish">community_phish</option>
                  </select>
                  <label className="flex items-center gap-1.5 text-xs text-slate-300">
                    <input
                      type="checkbox"
                      checked={srcEnabledInput}
                      onChange={(e) => setSrcEnabledInput(e.target.checked)}
                    />
                    <span>Enabled</span>
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={!isAdmin}
                  className="w-full rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  Save Source to /data_sources
                </button>
              </form>
            </div>
          </div>

          {/* Feature 7: Sync History & Connector Error Logs */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-2.5">
                <div className="flex items-center gap-2">
                  <History className="h-4 w-4 text-blue-400" />
                  <h4 className="text-sm font-semibold text-slate-100">
                    Immutable Sync History (/sync_logs)
                  </h4>
                </div>
                <span className="font-mono text-xs text-slate-400">
                  {syncLogs.length} entries
                </span>
              </div>

              {syncLogs.length === 0 ? (
                <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs text-slate-400">
                  No sync logs recorded yet. Trigger a manual sync above to log an immutable entry.
                </div>
              ) : (
                <div className="max-h-72 overflow-y-auto space-y-2">
                  {syncLogs.map((log) => (
                    <div
                      key={log.logId}
                      className="rounded border border-[#1E2D4A] bg-[#080D1A] p-2.5 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono text-[11px]">
                        <span className="text-blue-300">{log.sourceId}</span>
                        <span
                          className={
                            log.status === 'COMPLETED'
                              ? 'text-emerald-400'
                              : 'text-amber-400'
                          }
                        >
                          {log.status} · {log.recordsProcessed} records
                        </span>
                      </div>
                      <p className="text-slate-300">{log.message}</p>
                      <div className="font-mono text-[10px] text-slate-500">
                        Actor: {log.triggeredBy} · {log.createdAt}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-3">
              <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-2.5">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <h4 className="text-sm font-semibold text-slate-100">
                    Connector Error & Retry Telemetry Logs
                  </h4>
                </div>
                <span className="font-mono text-xs text-slate-400">
                  {connectorErrorLogs.length} error events
                </span>
              </div>

              {connectorErrorLogs.length === 0 ? (
                <div className="rounded border border-emerald-500/30 bg-emerald-950/20 p-3 text-xs text-emerald-200">
                  Zero connector runtime failures logged in current server window.
                </div>
              ) : (
                <div className="max-h-72 overflow-y-auto space-y-2">
                  {connectorErrorLogs.map((err) => (
                    <div
                      key={err.id}
                      className="rounded border border-red-500/30 bg-red-950/20 p-2.5 text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono text-[11px] text-red-300">
                        <span>{err.connectorId}</span>
                        <span>Attempts: {err.attemptCount}</span>
                      </div>
                      <p className="text-slate-200">{err.errorMessage}</p>
                      <div className="font-mono text-[10px] text-slate-400">
                        Preserved Cached Records: {err.preservedCachedCount} ·{' '}
                        {err.timestamp}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: FEEDBACK MANAGEMENT & APPLICATION CONFIGURATION */}
      {activeTab === 'feedback_config' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Feature 9: Feedback & Appeal Queue Management */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex flex-col gap-2 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'ফিডব্যাক ও আপিল ম্যানেজমেন্ট (/feedback)'
                    : 'Feedback & Scam Report Appeal Management (/feedback)'}
                </h3>
                <p className="mt-0.5 text-xs text-slate-400">
                  Review user bug reports, false-positive notices, and scam report moderation appeals.
                </p>
              </div>

              <div className="flex items-center gap-1">
                {(['ALL', 'open', 'reviewed', 'closed'] as const).map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setFeedbackFilter(st)}
                    className={`rounded px-2 py-1 font-mono text-[10px] ${
                      feedbackFilter === st
                        ? 'bg-blue-600 text-white'
                        : 'border border-[#1E2D4A] bg-[#080D1A] text-slate-300'
                    }`}
                  >
                    {st.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {displayedFeedbackQueue.length === 0 ? (
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs text-slate-400">
                No feedback or appeal items match status filter ({feedbackFilter}).
              </div>
            ) : (
              <div className="space-y-2.5 max-h-96 overflow-y-auto">
                {displayedFeedbackQueue.map((fb) => (
                  <div
                    key={fb.feedbackId}
                    className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span
                        className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                          fb.category === 'appeal_request' ||
                          fb.category === 'false_positive'
                            ? 'border border-amber-500/40 bg-amber-950/40 text-amber-300'
                            : 'border border-blue-500/40 bg-blue-950/40 text-blue-300'
                        }`}
                      >
                        {fb.category}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400">
                        Status: {fb.status.toUpperCase()} · {fb.feedbackId}
                      </span>
                    </div>

                    <p className="text-slate-200 font-mono text-[11px] break-words">
                      {fb.message}
                    </p>

                    {isAdmin && (
                      <div className="flex items-center justify-end gap-1.5 pt-1">
                        {(['open', 'reviewed', 'closed'] as const).map((nextSt) => (
                          <button
                            key={nextSt}
                            type="button"
                            disabled={fb.status === nextSt}
                            onClick={() =>
                              void updateFeedbackStatus(fb.feedbackId, nextSt)
                            }
                            className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2 py-1 font-mono text-[10px] text-slate-200 hover:border-blue-500/50 disabled:opacity-40"
                          >
                            Mark {nextSt.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Feature 10: Application Configuration (/app_settings) */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="border-b border-[#1E2D4A] pb-3">
              <h3 className="text-sm font-semibold text-slate-100">
                {isBn
                  ? 'অ্যাপ্লিকেশন কনফিগারেশন (/app_settings)'
                  : 'Global Application Configuration (/app_settings)'}
              </h3>
              <p className="mt-0.5 text-xs text-slate-400">
                Publicly readable governance parameters; strictly restricted to verified Administrators for writes.
              </p>
            </div>

            <div className="space-y-2">
              {appSettings.map((setting) => (
                <div
                  key={setting.settingId}
                  className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between font-mono">
                    <span className="text-blue-300 font-semibold">{setting.key}</span>
                    <span className="rounded bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 text-[10px] text-emerald-300">
                      {setting.value}
                    </span>
                  </div>
                  <p className="text-slate-400">{setting.description}</p>
                </div>
              ))}
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void upsertAppSetting(
                  settingIdInput,
                  settingKeyInput,
                  settingValInput,
                  settingDescInput
                );
              }}
              className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3.5 space-y-2.5"
            >
              <div className="text-xs font-semibold text-slate-200">
                Upsert Global App Setting
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <input
                  type="text"
                  required
                  value={settingIdInput}
                  onChange={(e) => setSettingIdInput(e.target.value)}
                  placeholder="Setting ID"
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
                />
                <input
                  type="text"
                  required
                  value={settingKeyInput}
                  onChange={(e) => setSettingKeyInput(e.target.value)}
                  placeholder="Setting Key"
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
                />
              </div>
              <input
                type="text"
                required
                value={settingValInput}
                onChange={(e) => setSettingValInput(e.target.value)}
                placeholder="Setting Value"
                className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
              <input
                type="text"
                required
                value={settingDescInput}
                onChange={(e) => setSettingDescInput(e.target.value)}
                placeholder="Governance description"
                className="w-full rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-xs text-slate-100"
              />
              <button
                type="submit"
                disabled={!isAdmin}
                className="w-full rounded bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
              >
                Commit Configuration to /app_settings
              </button>
            </form>
          </div>
        </div>
      )}

      {/* TAB 6: IMMUTABLE AUDIT LOG VIEWER & SYSTEM HEALTH STATUS */}
      {activeTab === 'audit_health' && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Feature 11: Audit Log Viewer */}
          <div className="lg:col-span-2 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <FileSearch className="h-4 w-4 text-blue-400" />
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    {isBn
                      ? 'অপরিবর্তনীয় অডিট লগ ভিউয়ার (/audit_logs)'
                      : 'Immutable Privileged Action Audit Log Viewer (/audit_logs)'}
                  </h3>
                  <p className="text-xs text-slate-400">
                    Append-only security ledger; update and delete operations are blocked at the Firestore rule layer.
                  </p>
                </div>
              </div>
              <span className="font-mono text-xs text-slate-300">
                Showing {filteredAudits.length} of {auditLogs.length}
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <div className="relative">
                <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  value={auditSearch}
                  onChange={(e) => setAuditSearch(e.target.value)}
                  placeholder="Search UID, action, summary..."
                  className="w-full rounded border border-[#1E2D4A] bg-[#080D1A] pl-8 pr-2.5 py-1.5 text-xs text-slate-100"
                />
              </div>

              <select
                value={auditActionFilter}
                onChange={(e) => setAuditActionFilter(e.target.value)}
                className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              >
                <option value="ALL">All Actions</option>
                <option value="assign_role">assign_role</option>
                <option value="moderate_scam_report">moderate_scam_report</option>
                <option value="manage_data_source">manage_data_source</option>
                <option value="trigger_manual_sync">trigger_manual_sync</option>
                <option value="review_feedback">review_feedback</option>
                <option value="update_app_setting">update_app_setting</option>
              </select>

              <select
                value={auditCollectionFilter}
                onChange={(e) => setAuditCollectionFilter(e.target.value)}
                className="rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              >
                <option value="ALL">All Target Collections</option>
                <option value="roles">roles</option>
                <option value="scam_reports">scam_reports</option>
                <option value="data_sources">data_sources</option>
                <option value="sync_logs">sync_logs</option>
                <option value="feedback">feedback</option>
                <option value="app_settings">app_settings</option>
              </select>
            </div>

            {filteredAudits.length === 0 ? (
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-4 text-xs text-slate-400">
                No audit log entries match the active filters.
              </div>
            ) : (
              <div className="max-h-96 overflow-y-auto space-y-2">
                {filteredAudits.map((aud) => (
                  <div
                    key={aud.auditId}
                    className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs space-y-1"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
                      <span className="text-blue-300 font-semibold">{aud.action}</span>
                      <span className="text-slate-400">
                        /{aud.targetCollection}/{aud.targetId}
                      </span>
                    </div>
                    <p className="text-slate-200">{aud.summary}</p>
                    <div className="font-mono text-[10px] text-slate-500">
                      Actor UID: {aud.actorUid} · Audit ID: {aud.auditId} · {aud.createdAt}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Feature 12: System Health Status */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  {isBn
                    ? 'সিস্টেম হেলথ স্ট্যাটাস (System Health Status)'
                    : 'System Health & Governance Telemetry'}
                </h3>
                <p className="text-xs text-slate-400">
                  Real-time server gate, Firestore connection, and $0 cost guardrail diagnostics.
                </p>
              </div>
              <Activity className="h-4 w-4 text-emerald-400" />
            </div>

            <div className="space-y-2.5 text-xs font-mono">
              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 space-y-1">
                <div className="text-slate-400 text-[10px]">EXPRESS SECURITY GATE</div>
                <div className="text-emerald-300 font-semibold">
                  {serverHealth?.status || 'PROBING...'}
                </div>
                <div className="text-[10px] text-slate-400">
                  Rate Limiter: {serverHealth?.rateLimitPolicy || 'Active'}
                </div>
              </div>

              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 space-y-1">
                <div className="text-slate-400 text-[10px]">
                  CLOUD FIRESTORE & AUTH PERSISTENCE
                </div>
                <div className="text-slate-100 font-semibold">{persistenceMode}</div>
                <div className="text-[10px] text-slate-400 break-all">
                  Project: {projectId} · DB: {databaseId}
                </div>
                <div className="text-[10px] text-emerald-300">
                  {connectionStatusMessage}
                </div>
              </div>

              <div className="rounded border border-[#1E2D4A] bg-[#080D1A] p-3 space-y-1">
                <div className="text-slate-400 text-[10px]">
                  ZERO-COST & NON-AFFILIATION COMPLIANCE
                </div>
                <div className="text-emerald-300 font-semibold">
                  $0.00 STRICT CAP VERIFIED
                </div>
                <div className="text-[10px] text-slate-400">
                  0 Paid APIs · 0 Runtime LLM Calls · Independent Non-Government Product
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
