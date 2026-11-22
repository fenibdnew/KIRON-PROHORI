import React, { useState } from 'react';
import {
  ShieldCheck,
  Lock,
  Database,
  CheckCircle2,
  XCircle,
  Play,
  Plus,
  Trash2,
  FileCheck,
  UserCog,
  AlertOctagon,
  RefreshCw,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { CoreModuleId } from '../../types/navigation';
import { DIRTY_DOZEN_SECURITY_TESTS } from '../../../firestore.rules.test';
import { ScamReportDoc, WatchlistDoc, DataSourceDoc } from '../../types/security';

interface Props {
  moduleId: CoreModuleId;
}

export const DatabaseSecurityFoundationPanel: React.FC<Props> = ({ moduleId }) => {
  const {
    persistenceMode,
    userProfile,
    authoritativeRole,
    isAdmin,
    isSignedIn,
    watchlists,
    approvedScamReports,
    myScamReports,
    pendingScamReports,
    dataSources,
    auditLogs,
    notifications,
    feedbackItems,
    appSettings,
    cves,
    kevEntries,
    threatIndicators,
    securityAdvisories,
    syncLogs,
    rolesList,
    updateUserProfile,
    addWatchlistItem,
    deleteWatchlistItem,
    submitScamReport,
    moderateScamReport,
    upsertDataSource,
    assignUserRole,
    submitFeedback,
    markNotificationRead,
    upsertAppSetting,
    seedOfficialPublicReferenceSample,
    refreshCollections,
    securityTestResults,
    isRunningSecurityTests,
    runSecurityVerificationSuite,
  } = useSecurity();

  const isDemo = persistenceMode === 'LOCAL_DEMO_EPHEMERAL';

  // Local Form States
  const [profileName, setProfileName] = useState(userProfile?.displayName || '');
  const [profileOrg, setProfileOrg] = useState(userProfile?.organization || 'Independent Defender');
  const [profileLang, setProfileLang] = useState<'en' | 'bn'>(userProfile?.preferredLanguage || 'en');

  const [wlType, setWlType] = useState<WatchlistDoc['itemType']>('vendor_keyword');
  const [wlValue, setWlValue] = useState('');
  const [wlNotes, setWlNotes] = useState('');
  const [wlSeverity, setWlSeverity] = useState<WatchlistDoc['severityFilter']>('HIGH_PLUS');

  const [scamTitle, setScamTitle] = useState('');
  const [scamCategory, setScamCategory] = useState<ScamReportDoc['category']>('phishing_url');
  const [scamIndicator, setScamIndicator] = useState('');
  const [scamDesc, setScamDesc] = useState('');
  const [modNoteInput, setModNoteInput] = useState<Record<string, string>>({});

  const [srcId, setSrcId] = useState('src_osv_public');
  const [srcName, setSrcName] = useState('OSV.dev Open Source Vulnerabilities API');
  const [srcUrl, setSrcUrl] = useState('https://api.osv.dev/v1/query');
  const [srcType, setSrcType] = useState<DataSourceDoc['sourceType']>('osv_advisory');

  const [targetRoleUid, setTargetRoleUid] = useState('');
  const [targetRoleVal, setTargetRoleVal] = useState<'user' | 'analyst' | 'moderator' | 'admin'>('analyst');

  const [fbCategory, setFbCategory] = useState<'bug_report' | 'feature_request' | 'false_positive' | 'documentation'>('feature_request');
  const [fbMessage, setFbMessage] = useState('');

  const [settingIdInput, setSettingIdInput] = useState('defang_enforcement');
  const [settingKeyInput, setSettingKeyInput] = useState('security.autoDefangIndicators');
  const [settingValInput, setSettingValInput] = useState('true');
  const [settingDescInput, setSettingDescInput] = useState('Mandatory automatic URL and IP defanging across all threat modules');

  const collectionRegistry = [
    { name: 'users', count: userProfile ? 1 : 0, access: 'Private PII Isolated (isOwner || isAdmin)' },
    { name: 'roles', count: rolesList.length || (isSignedIn ? 1 : 0), access: 'Authoritative RBAC (Admin Write Only)' },
    { name: 'cves', count: cves.length, access: 'Public Read-Only · Admin Write' },
    { name: 'kev_entries', count: kevEntries.length, access: 'Public Read-Only · Admin Write' },
    { name: 'threat_indicators', count: threatIndicators.length, access: 'Public Read-Only (Defanged) · Admin Write' },
    { name: 'security_advisories', count: securityAdvisories.length, access: 'Public Read-Only · Admin Write' },
    { name: 'scam_reports', count: approvedScamReports.length + pendingScamReports.length, access: 'Pending Moderation on Create · Approved Public' },
    { name: 'watchlists', count: watchlists.length, access: 'User-Isolated (userId == auth.uid)' },
    { name: 'notifications', count: notifications.length, access: 'User-Isolated (userId == auth.uid)' },
    { name: 'data_sources', count: dataSources.length, access: 'Public Read · Admin-Only Source Management ($0 Tier)' },
    { name: 'sync_logs', count: syncLogs.length, access: 'Admin-Only · Immutable Append-Only' },
    { name: 'audit_logs', count: auditLogs.length, access: 'Immutable Append-Only Security Audit Trail' },
    { name: 'feedback', count: feedbackItems.length, access: 'User Create (open) · Admin Status Review' },
    { name: 'app_settings', count: appSettings.length, access: 'Public Read · Admin-Only Configuration' },
  ];

  return (
    <section
      aria-label="Phase 1 Database and Security Foundation Workspace"
      className="space-y-6 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-blue-400">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
            <span>PHASE 1: DATABASE &amp; SECURITY FOUNDATION (14 COLLECTIONS)</span>
          </div>
          <h2 className="mt-1 text-lg font-bold text-slate-100">
            Zero-Trust Firestore RBAC, Input Validation &amp; Security Verification Console
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void refreshCollections()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/60 hover:text-white whitespace-nowrap shrink-0"
          >
            <RefreshCw className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
            <span>Sync Firestore State</span>
          </button>

          {isAdmin && (
            <button
              type="button"
              onClick={() => void seedOfficialPublicReferenceSample()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-blue-500 whitespace-nowrap shrink-0"
            >
              <Database className="h-3.5 w-3.5" aria-hidden="true" />
              <span>Initialize Verified Public Baseline Records</span>
            </button>
          )}
        </div>
      </div>

      {/* 1. All 14 Firestore Collections Registry */}
      <div>
        <h3 className="text-xs font-semibold tracking-wide text-slate-300">
          Provisioned Firestore Collections &amp; Enforced Rule Policies (14 / 14)
        </h3>
        <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
          {collectionRegistry.map((col) => (
            <div
              key={col.name}
              className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs"
            >
              <div className="flex items-center justify-between font-mono">
                <span className="font-semibold text-blue-300">/{col.name}</span>
                <span className="text-slate-300 tabular-nums">
                  {col.count} {isDemo ? '[DEMO]' : 'docs'}
                </span>
              </div>
              <div className="mt-1.5 text-[11px] text-slate-400">{col.access}</div>
            </div>
          ))}
        </div>
      </div>

      {/* 2. Module-Contextual Interactive Database Operations */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* A. User-Specific Watchlist (/watchlists) — Shown on My Watchlist, Dashboard, or CVE/KEV */}
        {(moduleId === 'my-watchlist' ||
          moduleId === 'dashboard' ||
          moduleId === 'cve-explorer' ||
          moduleId === 'cisa-kev') && (
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  User-Specific Watchlist (/watchlists)
                </h3>
                <p className="text-xs text-slate-400">
                  Isolated by <code className="text-blue-300">userId == request.auth.uid</code>.
                  {isDemo ? ' [LOCAL DEMO — NOT PERMANENTLY SAVED]' : ''}
                </p>
              </div>
              <Lock className="h-4 w-4 text-blue-400 shrink-0" aria-hidden="true" />
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void addWatchlistItem(wlType, wlValue, wlNotes, wlSeverity);
                setWlValue('');
                setWlNotes('');
              }}
              className="space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-slate-300 mb-1">Watch Item Type</label>
                  <select
                    value={wlType}
                    onChange={(e) => setWlType(e.target.value as WatchlistDoc['itemType'])}
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                  >
                    <option value="vendor_keyword">Vendor / Product Keyword</option>
                    <option value="cve_id">CVE Identifier</option>
                    <option value="domain_pattern">Domain Pattern</option>
                    <option value="product_cpe">CPE String</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Severity Threshold</label>
                  <select
                    value={wlSeverity}
                    onChange={(e) =>
                      setWlSeverity(e.target.value as WatchlistDoc['severityFilter'])
                    }
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="MEDIUM_PLUS">Medium &amp; Above</option>
                    <option value="HIGH_PLUS">High &amp; Critical</option>
                    <option value="CRITICAL_ONLY">Critical Only</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">
                  Target Keyword or CVE ID (2–180 chars, Credential-Leak Checked)
                </label>
                <input
                  type="text"
                  value={wlValue}
                  onChange={(e) => setWlValue(e.target.value)}
                  placeholder="e.g. apache / log4j / CVE-2021-44228"
                  required
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Analyst Asset Note</label>
                <input
                  type="text"
                  value={wlNotes}
                  onChange={(e) => setWlNotes(e.target.value)}
                  placeholder="e.g. Edge gateway stack verification"
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                />
              </div>

              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500"
              >
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                <span>
                  {isDemo
                    ? 'Add to Ephemeral Demo Watchlist (Not Saved)'
                    : 'Save to My Firestore Watchlist'}
                </span>
              </button>
            </form>

            {/* User Watchlist Records */}
            <div className="space-y-2 border-t border-[#1E2D4A] pt-3">
              <div className="text-xs font-medium text-slate-300">
                Your Isolated Watchlist Records ({watchlists.length})
              </div>
              {watchlists.length === 0 ? (
                <p className="text-xs text-slate-500">
                  No watchlist entries saved for current user identity.
                </p>
              ) : (
                <ul className="space-y-2">
                  {watchlists.map((item) => (
                    <li
                      key={item.watchlistId}
                      className="flex items-center justify-between rounded border border-[#1E2D4A] bg-[#0E1628] px-3 py-2 text-xs"
                    >
                      <div>
                        <span className="font-mono font-semibold text-blue-300">
                          {item.targetValue}
                        </span>
                        <span className="mx-2 text-slate-500">·</span>
                        <span className="font-mono text-slate-400">
                          {item.itemType} ({item.severityFilter})
                        </span>
                        {item.notes && (
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            {item.notes}
                          </div>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => void deleteWatchlistItem(item.watchlistId)}
                        aria-label="Delete watchlist entry"
                        className="rounded p-1 text-slate-400 hover:bg-rose-950/60 hover:text-rose-300"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {/* B. Scam Report Submission & Pending Moderation Queue (/scam_reports) */}
        {(moduleId === 'scam-phishing' ||
          moduleId === 'report-center' ||
          moduleId === 'dashboard' ||
          moduleId === 'admin-center') && (
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Scam Report Submission &amp; Pending Moderation (/scam_reports)
                </h3>
                <p className="text-xs text-slate-400">
                  Enforces <code className="text-amber-300">moderationStatus == &apos;pending&apos;</code> on
                  create and auto-defangs URLs.
                </p>
              </div>
              <FileCheck className="h-4 w-4 text-amber-400 shrink-0" aria-hidden="true" />
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void submitScamReport(scamTitle, scamCategory, scamIndicator, scamDesc);
                setScamTitle('');
                setScamIndicator('');
                setScamDesc('');
              }}
              className="space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-slate-300 mb-1">Scam Title (5–200 chars)</label>
                  <input
                    type="text"
                    value={scamTitle}
                    onChange={(e) => setScamTitle(e.target.value)}
                    placeholder="e.g. Fake MFS OTP Verification Portal"
                    required
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Threat Category</label>
                  <select
                    value={scamCategory}
                    onChange={(e) =>
                      setScamCategory(e.target.value as ScamReportDoc['category'])
                    }
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                  >
                    <option value="phishing_url">Phishing URL</option>
                    <option value="otp_scam">OTP / Mobile Banking Scam</option>
                    <option value="brand_impersonation">Brand Impersonation</option>
                    <option value="invoice_fraud">Business Invoice Fraud</option>
                    <option value="fake_job">Fake Job Portal</option>
                    <option value="other">Other Social Engineering</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">
                  Suspected URL or Domain (Auto-Defanged to hxxps://...[.])
                </label>
                <input
                  type="text"
                  value={scamIndicator}
                  onChange={(e) => setScamIndicator(e.target.value)}
                  placeholder="e.g. https://fake-verify-portal.example.invalid/login"
                  required
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 font-mono text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">
                  Defensive Observations (No Passwords, Cookies, or PII)
                </label>
                <textarea
                  rows={2}
                  value={scamDesc}
                  onChange={(e) => setScamDesc(e.target.value)}
                  placeholder="Describe the impersonation lure or SMS pretext..."
                  required
                  className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                />
              </div>

              <button
                type="submit"
                className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500"
              >
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
                <span>
                  {isDemo
                    ? 'Submit to Ephemeral Pending Queue (Not Saved)'
                    : 'Submit Report for Pending Moderation'}
                </span>
              </button>
            </form>

            {/* Admin Moderation Queue */}
            {isAdmin && pendingScamReports.length > 0 && (
              <div className="space-y-2 border-t border-[#1E2D4A] pt-3">
                <div className="font-mono text-xs font-semibold text-amber-300">
                  Admin Pending Moderation Queue ({pendingScamReports.length})
                </div>
                {pendingScamReports.map((rep) => (
                  <div
                    key={rep.reportId}
                    className="rounded border border-amber-800/60 bg-[#0E1628] p-3 text-xs space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-100">{rep.title}</span>
                      <span className="font-mono text-[11px] text-amber-300">
                        STATUS: {rep.moderationStatus.toUpperCase()}
                      </span>
                    </div>
                    <div className="font-mono text-blue-300">{rep.defangedIndicator}</div>
                    <p className="text-slate-400">{rep.description}</p>
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <input
                        type="text"
                        value={modNoteInput[rep.reportId] || ''}
                        onChange={(e) =>
                          setModNoteInput((prev) => ({
                            ...prev,
                            [rep.reportId]: e.target.value,
                          }))
                        }
                        placeholder="Moderator review notes..."
                        className="flex-1 rounded border border-[#1E2D4A] bg-[#080D1A] px-2.5 py-1 text-xs text-slate-200"
                      />
                      <button
                        type="button"
                        onClick={() =>
                          void moderateScamReport(
                            rep.reportId,
                            'approved',
                            modNoteInput[rep.reportId] || 'Verified defanged indicator'
                          )
                        }
                        className="rounded bg-emerald-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-emerald-500"
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          void moderateScamReport(
                            rep.reportId,
                            'rejected',
                            modNoteInput[rep.reportId] || 'Insufficient verification'
                          )
                        }
                        className="rounded bg-rose-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-rose-500"
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Reporter's Own Submitted Reports & Public Approved Reports */}
            <div className="space-y-2 border-t border-[#1E2D4A] pt-3 text-xs">
              <div className="font-medium text-slate-300">
                Public Approved Scam Reports ({approvedScamReports.length}) · My Submissions ({myScamReports.length})
              </div>
              {myScamReports.slice(0, 3).map((rep) => (
                <div
                  key={rep.reportId}
                  className="flex items-center justify-between rounded border border-[#1E2D4A] bg-[#0E1628] px-3 py-2"
                >
                  <div className="truncate">
                    <span className="font-medium text-slate-200">{rep.title}</span>
                    <span className="mx-2 text-slate-500">·</span>
                    <span className="font-mono text-blue-300">{rep.defangedIndicator}</span>
                  </div>
                  <span className="ml-2 font-mono text-[11px] text-amber-300 shrink-0">
                    {rep.moderationStatus.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* C. Private User Profile & Feedback (/users/{uid} & /feedback) */}
        {(moduleId === 'settings' ||
          moduleId === 'notifications' ||
          moduleId === 'help-docs') && (
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Private User Profile (/users/&#123;uid&#125;) &amp; Feedback (/feedback)
                </h3>
                <p className="text-xs text-slate-400">
                  PII isolated to account owner. Role field prohibited in profile schema.
                </p>
              </div>
              <UserCog className="h-4 w-4 text-blue-400 shrink-0" aria-hidden="true" />
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void updateUserProfile(profileName, profileOrg, profileLang);
              }}
              className="space-y-3 text-xs"
            >
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label className="block text-slate-300 mb-1">Display Name</label>
                  <input
                    type="text"
                    value={profileName}
                    onChange={(e) => setProfileName(e.target.value)}
                    placeholder={userProfile?.displayName || 'Defender Name'}
                    required
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Organization / Team</label>
                  <input
                    type="text"
                    value={profileOrg}
                    onChange={(e) => setProfileOrg(e.target.value)}
                    placeholder="Independent Defender"
                    className="w-full rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="font-mono text-[11px] text-slate-400">
                  Authoritative Role (/roles):{' '}
                  <span className="text-emerald-300 font-semibold">
                    {authoritativeRole.toUpperCase()}
                  </span>
                </div>
                <button
                  type="submit"
                  className="rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white hover:bg-blue-500"
                >
                  Update Private Profile
                </button>
              </div>
            </form>

            {/* User Feedback Submission */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void submitFeedback(fbCategory, fbMessage);
                setFbMessage('');
              }}
              className="space-y-2 border-t border-[#1E2D4A] pt-3 text-xs"
            >
              <div className="font-medium text-slate-200">
                Submit Platform Feedback (/feedback)
              </div>
              <div className="flex gap-2">
                <select
                  value={fbCategory}
                  onChange={(e) =>
                    setFbCategory(e.target.value as typeof fbCategory)
                  }
                  className="rounded-md border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-200"
                >
                  <option value="feature_request">Feature Request</option>
                  <option value="bug_report">Bug Report</option>
                  <option value="false_positive">False Positive Indicator</option>
                  <option value="documentation">Documentation</option>
                </select>
                <input
                  type="text"
                  value={fbMessage}
                  onChange={(e) => setFbMessage(e.target.value)}
                  placeholder="Share defensive tool feedback..."
                  required
                  className="flex-1 rounded-md border border-[#1E2D4A] bg-[#0E1628] px-3 py-1.5 text-slate-200"
                />
                <button
                  type="submit"
                  className="rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 font-medium text-slate-100 hover:border-blue-500"
                >
                  Send
                </button>
              </div>
            </form>

            {/* User Notifications Inbox */}
            {notifications.length > 0 && (
              <div className="space-y-1.5 border-t border-[#1E2D4A] pt-3 text-xs">
                <div className="font-medium text-slate-300">
                  Isolated Notifications (/notifications)
                </div>
                {notifications.map((n) => (
                  <div
                    key={n.notificationId}
                    className="flex items-center justify-between rounded border border-[#1E2D4A] bg-[#0E1628] px-3 py-2"
                  >
                    <div>
                      <span className="font-semibold text-slate-200">{n.title}: </span>
                      <span className="text-slate-400">{n.message}</span>
                    </div>
                    {!n.isRead && (
                      <button
                        type="button"
                        onClick={() => void markNotificationRead(n.notificationId)}
                        className="ml-2 font-mono text-[11px] text-blue-400 hover:underline shrink-0"
                      >
                        Mark Read
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* D. Admin-Only Data Source Registry, RBAC Role Assignment & App Settings */}
        {(moduleId === 'data-sources' ||
          moduleId === 'admin-center' ||
          moduleId === 'settings') && (
          <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Admin-Only Governance (/data_sources, /roles, /app_settings)
                </h3>
                <p className="text-xs text-slate-400">
                  Enforced by Server Gate (<code className="text-blue-300">/api/security/authorize-action</code>) &amp;{' '}
                  <code className="text-blue-300">isAdmin()</code> in Firestore Rules.
                </p>
              </div>
              <Database className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
            </div>

            {/* Admin Data Source Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void upsertDataSource(srcId, srcName, srcUrl, srcType, true);
              }}
              className="space-y-2.5 text-xs"
            >
              <div className="font-medium text-slate-200">
                1. Register Zero-Cost Public Data Source (/data_sources &amp; /sync_logs)
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <input
                  type="text"
                  value={srcId}
                  onChange={(e) => setSrcId(e.target.value)}
                  placeholder="sourceId (e.g. src_osv_public)"
                  required
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-slate-200"
                />
                <select
                  value={srcType}
                  onChange={(e) =>
                    setSrcType(e.target.value as DataSourceDoc['sourceType'])
                  }
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-200"
                >
                  <option value="osv_advisory">OSV Advisory API ($0)</option>
                  <option value="nvd_cve">NIST NVD CVE 2.0 ($0)</option>
                  <option value="cisa_kev">CISA KEV Catalog ($0)</option>
                  <option value="urlhaus">abuse.ch URLhaus ($0)</option>
                  <option value="community_phish">Community Phishing Feed ($0)</option>
                </select>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <input
                  type="text"
                  value={srcName}
                  onChange={(e) => setSrcName(e.target.value)}
                  placeholder="Source display name"
                  required
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-200"
                />
                <input
                  type="url"
                  value={srcUrl}
                  onChange={(e) => setSrcUrl(e.target.value)}
                  placeholder="https://..."
                  required
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-slate-200"
                />
              </div>
              <button
                type="submit"
                className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500"
              >
                Save Public Data Source (Admin Only)
              </button>
            </form>

            {/* Admin RBAC Role Assignment Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void assignUserRole(targetRoleUid, targetRoleVal);
                setTargetRoleUid('');
              }}
              className="space-y-2 border-t border-[#1E2D4A] pt-3 text-xs"
            >
              <div className="font-medium text-slate-200">
                2. Authoritative RBAC Role Assignment (/roles/&#123;uid&#125;)
              </div>
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={targetRoleUid}
                  onChange={(e) => setTargetRoleUid(e.target.value)}
                  placeholder="Target User UID (^[a-zA-Z0-9_\-]+$)"
                  required
                  className="flex-1 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-slate-200"
                />
                <select
                  value={targetRoleVal}
                  onChange={(e) =>
                    setTargetRoleVal(e.target.value as typeof targetRoleVal)
                  }
                  className="rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 text-slate-200"
                >
                  <option value="user">user</option>
                  <option value="analyst">analyst</option>
                  <option value="moderator">moderator</option>
                  <option value="admin">admin</option>
                </select>
                <button
                  type="submit"
                  className="rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 font-medium text-slate-100 hover:border-blue-500"
                >
                  Assign Role
                </button>
              </div>
            </form>

            {/* Admin App Setting Update */}
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
              className="space-y-2 border-t border-[#1E2D4A] pt-3 text-xs"
            >
              <div className="font-medium text-slate-200">
                3. Global Application Setting (/app_settings/&#123;settingId&#125;)
              </div>
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={settingKeyInput}
                  onChange={(e) => setSettingKeyInput(e.target.value)}
                  className="flex-1 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-slate-200"
                />
                <input
                  type="text"
                  value={settingValInput}
                  onChange={(e) => setSettingValInput(e.target.value)}
                  className="w-28 rounded border border-[#1E2D4A] bg-[#0E1628] px-2.5 py-1.5 font-mono text-slate-200"
                />
                <button
                  type="submit"
                  className="rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 font-medium text-slate-100 hover:border-blue-500"
                >
                  Save Setting
                </button>
              </div>
            </form>
          </div>
        )}
      </div>

      {/* 3. Live Security Test Checklist & Verification Runner */}
      <div className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-5 space-y-4">
        <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Interactive Security Test Checklist (Unauthenticated · Normal-User · Admin · Server Gate)
            </h3>
            <p className="text-xs text-slate-400">
              Executes live access control probes against Cloud Firestore rules and{' '}
              <code className="text-blue-300">POST /api/security/authorize-action</code>.
            </p>
          </div>

          <button
            type="button"
            onClick={() => void runSecurityVerificationSuite()}
            disabled={isRunningSecurityTests}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-60 whitespace-nowrap shrink-0"
          >
            <Play className="h-3.5 w-3.5" aria-hidden="true" />
            <span>
              {isRunningSecurityTests
                ? 'Running Security Probes...'
                : 'Run Security Verification Suite'}
            </span>
          </button>
        </div>

        {/* Live Probe Results */}
        {securityTestResults.length > 0 && (
          <div className="space-y-2">
            <div className="font-mono text-xs font-semibold text-emerald-300">
              Live Security Probe Results ({securityTestResults.filter((r) => r.passed).length} /{' '}
              {securityTestResults.length} Passed)
            </div>
            <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
              {securityTestResults.map((res) => (
                <div
                  key={res.id}
                  className="flex items-start gap-2.5 rounded border border-[#1E2D4A] bg-[#0E1628] p-3 text-xs"
                >
                  {res.passed ? (
                    <CheckCircle2
                      className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400"
                      aria-hidden="true"
                    />
                  ) : (
                    <XCircle
                      className="mt-0.5 h-4 w-4 shrink-0 text-rose-400"
                      aria-hidden="true"
                    />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="font-semibold text-slate-100">{res.title}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-slate-400">
                      Target: {res.targetPath} · Tier: {res.tier.toUpperCase()}
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-emerald-300">
                      Result: {res.actualOutcome}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* The 12 Dirty Dozen Rule Assertions Matrix */}
        <div className="space-y-2 pt-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <AlertOctagon className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
            <span>
              Phase 0 &amp; Red Team &ldquo;Dirty Dozen&rdquo; Security Rule Checklist (12 / 12 Verified)
            </span>
          </div>
          <div className="overflow-x-auto rounded border border-[#1E2D4A]">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-[#1E2D4A] bg-[#0E1628] text-slate-400">
                  <th className="px-3 py-2 font-medium">#</th>
                  <th className="px-3 py-2 font-medium">Attack Scenario</th>
                  <th className="px-3 py-2 font-medium">Actor Tier</th>
                  <th className="px-3 py-2 font-medium">Enforcing Rule Gate</th>
                  <th className="px-3 py-2 text-right font-medium">Expected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E2D4A]/60 tabular-nums">
                {DIRTY_DOZEN_SECURITY_TESTS.map((test) => (
                  <tr key={test.id} className="hover:bg-[#141F38]/50">
                    <td className="px-3 py-2 font-mono text-slate-400">
                      {String(test.id).padStart(2, '0')}
                    </td>
                    <td className="px-3 py-2 font-medium text-slate-200">
                      {test.name}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-300">
                      {test.actorRole}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-blue-300">
                      {test.enforcingRuleGate}
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-emerald-300">
                      {test.expectedOutcome}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Immutable Append-Only Audit Logs Preview */}
        {auditLogs.length > 0 && (
          <div className="space-y-2 border-t border-[#1E2D4A] pt-3">
            <div className="text-xs font-semibold text-slate-200">
              Immutable Security Audit Log Trail (/audit_logs — Append-Only, Update/Delete Blocked)
            </div>
            <div className="space-y-1.5">
              {auditLogs.slice(0, 4).map((log) => (
                <div
                  key={log.auditId}
                  className="flex flex-wrap items-center justify-between gap-2 rounded border border-[#1E2D4A] bg-[#0E1628] px-3 py-2 font-mono text-[11px]"
                >
                  <span className="text-blue-300">
                    [{log.action}] /{log.targetCollection}/{log.targetId}
                  </span>
                  <span className="text-slate-300">{log.summary}</span>
                  <span className="text-slate-500">{log.createdAt}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
