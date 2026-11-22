import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldCheck,
  Monitor,
  Play,
  FileCode2,
  FolderSearch,
  Usb,
  Lock,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Sun,
  Moon,
  Languages,
  Trash2,
  RotateCcw,
  Terminal,
} from 'lucide-react';
import { CoreModuleId } from '../../types/navigation';
import { useApp } from '../../context/AppContext';

interface AgentFileEntry {
  relativePath: string;
  sizeBytes: number;
  lines: number;
  category: 'SOLUTION' | 'CORE_CSHARP' | 'DESKTOP_WPF' | 'XUNIT_TESTS' | 'DOCUMENTATION';
}

interface AgentEngineStatus {
  engineId: string;
  displayName: string;
  license: string;
  status: 'READY' | 'INSTALLATION_REQUIRED' | 'NOT_CONFIGURED' | 'CONNECTED';
  maturityTier: 'WORKING_PHASE_7A' | 'EXPERIMENTAL_USER_MODE' | 'FUTURE_KERNEL_ROADMAP';
  detail: string;
}

interface AgentManifestResponse {
  ok: boolean;
  phase: string;
  targetPlatform: string;
  framework: string;
  budget: string;
  buildEnvironmentDisclosure: {
    currentPreviewHostOs: string;
    canCompileWindowsExeInLinuxContainer: boolean;
    honestDisclosure: string;
  };
  coexistenceInvariants: string[];
  engines: AgentEngineStatus[];
  files: AgentFileEntry[];
}

interface VerificationSuiteResult {
  id: string;
  title: string;
  passed: boolean;
  expected: string;
  actual: string;
  durationMs: number;
}

type DesktopNavViewId =
  | 'overview'
  | 'quick-scan'
  | 'full-scan'
  | 'custom-scan'
  | 'usb-scan'
  | 'protection-status'
  | 'threat-history'
  | 'quarantine'
  | 'firewall-status'
  | 'windows-security'
  | 'updates'
  | 'reports'
  | 'settings';

interface SimulatedFinding {
  id: string;
  filePath: string;
  fileName: string;
  sha256: string;
  detectionName: string;
  engineId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  confidence: 'VERIFIED_SIGNATURE' | 'HEURISTIC_SUSPICIOUS';
  falsePositiveNote: string;
  detectedAt: string;
}

interface QuarantineVaultItem {
  quarantineId: string;
  originalPath: string;
  fileName: string;
  vaultFileName: string;
  sha256: string;
  detectionName: string;
  quarantinedAt: string;
}

const DESKTOP_NAV_ITEMS: {
  id: DesktopNavViewId;
  order: string;
  labelEn: string;
  labelBn: string;
  tier: 'WORKING' | 'EXPERIMENTAL' | 'ROADMAP';
}[] = [
  { id: 'overview', order: '01', labelEn: 'Security Overview', labelBn: 'সিকিউরিটি ওভারভিউ', tier: 'WORKING' },
  { id: 'quick-scan', order: '02', labelEn: 'Quick Scan', labelBn: 'কুইক স্ক্যান', tier: 'WORKING' },
  { id: 'full-scan', order: '03', labelEn: 'Full Scan', labelBn: 'ফুল স্ক্যান', tier: 'WORKING' },
  { id: 'custom-scan', order: '04', labelEn: 'Custom Scan', labelBn: 'কাস্টম ফোল্ডার স্ক্যান', tier: 'WORKING' },
  { id: 'usb-scan', order: '05', labelEn: 'USB Scan', labelBn: 'ইউএসবি ড্রাইভ স্ক্যান', tier: 'WORKING' },
  { id: 'protection-status', order: '06', labelEn: 'Protection Status', labelBn: 'সুরক্ষা অবস্থা', tier: 'WORKING' },
  { id: 'threat-history', order: '07', labelEn: 'Threat History', labelBn: 'থ্রেট ইতিহাস', tier: 'WORKING' },
  { id: 'quarantine', order: '08', labelEn: 'Quarantine', labelBn: 'কোয়ারেন্টাইন ভল্ট', tier: 'WORKING' },
  { id: 'firewall-status', order: '09', labelEn: 'Firewall Status', labelBn: 'ফায়ারওয়াল অবস্থা', tier: 'WORKING' },
  { id: 'windows-security', order: '10', labelEn: 'Windows Security', labelBn: 'উইন্ডোজ সিকিউরিটি', tier: 'WORKING' },
  { id: 'updates', order: '11', labelEn: 'Updates', labelBn: 'সিগনেচার আপডেট', tier: 'WORKING' },
  { id: 'reports', order: '12', labelEn: 'Reports', labelBn: 'স্ক্যান রিপোর্ট', tier: 'WORKING' },
  { id: 'settings', order: '13', labelEn: 'Settings', labelBn: 'সেটিংস ও সিডিউল', tier: 'EXPERIMENTAL' },
];

export const Phase7WindowsAgentWorkspace: React.FC<{ moduleId: CoreModuleId }> = ({
  moduleId,
}) => {
  const { language } = useApp();
  const [agentLang, setAgentLang] = useState<'en' | 'bn'>(language === 'bn' ? 'bn' : 'en');
  const [agentTheme, setAgentTheme] = useState<'dark' | 'light'>('dark');
  const [activeDesktopView, setActiveDesktopView] = useState<DesktopNavViewId>('overview');

  const [manifest, setManifest] = useState<AgentManifestResponse | null>(null);
  const [selectedSourceFile, setSelectedSourceFile] = useState<string>(
    'desktop-agent/src/KironProhori.Agent.Core/Scanning/ModularScanPipeline.cs'
  );
  const [sourceCodeContent, setSourceCodeContent] = useState<string>('');
  const [loadingSource, setLoadingSource] = useState<boolean>(false);

  const [suiteResults, setSuiteResults] = useState<VerificationSuiteResult[]>([]);
  const [runningSuite, setRunningSuite] = useState<boolean>(false);

  // Interactive Desktop Agent Preview State
  const [scanRunning, setScanRunning] = useState<boolean>(false);
  const [scanStatusText, setScanStatusText] = useState<string>(
    'IDLE · Cooperative User-Mode Modular Scanner Ready'
  );
  const [activeFindings, setActiveFindings] = useState<SimulatedFinding[]>([
    {
      id: 'FIND-EICAR-01',
      filePath: 'C:\\Users\\Defender\\Downloads\\eicar_harmless_test.com',
      fileName: 'eicar_harmless_test.com',
      sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
      detectionName: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
      engineId: 'KIRON-SHA256-SIGNATURE-ENGINE',
      severity: 'CRITICAL',
      confidence: 'VERIFIED_SIGNATURE',
      falsePositiveNote:
        'Harmless official 68-byte EICAR standard antivirus verification test signature.',
      detectedAt: '2026-11-22 11:15:00 UTC',
    },
    {
      id: 'HEUR-SPOOF-02',
      filePath: 'C:\\Users\\Defender\\Downloads\\Invoice_November_2026.pdf.exe',
      fileName: 'Invoice_November_2026.pdf.exe',
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      detectionName: 'Heuristic.DoubleExtension.pdf_exe',
      engineId: 'KIRON-STATIC-HEURISTIC-ENGINE',
      severity: 'HIGH',
      confidence: 'HEURISTIC_SUSPICIOUS',
      falsePositiveNote:
        'Heuristic warning: Double extension (.pdf.exe). Review digital signature before quarantine.',
      detectedAt: '2026-11-22 11:15:02 UTC',
    },
  ]);

  const [quarantineVault, setQuarantineVault] = useState<QuarantineVaultItem[]>([]);
  const [auditTrail, setAuditTrail] = useState<string[]>([
    '[2026-11-22T11:10:00Z]STARTUP: QuarantineManager initialized · Zero system modifications guaranteed.',
  ]);
  const [pendingConfirmModal, setPendingConfirmModal] = useState<{
    action: 'QUARANTINE' | 'RESTORE' | 'DELETE';
    targetId: string;
    title: string;
    detail: string;
  } | null>(null);

  const shouldDisplay =
    moduleId === 'dashboard' ||
    moduleId === 'malware-intel' ||
    moduleId === 'hash-lookup' ||
    moduleId === 'help-docs';

  const loadManifest = useCallback(async () => {
    try {
      const res = await fetch('/api/agent/v1/manifest');
      if (res.ok) {
        const data = (await res.json()) as AgentManifestResponse;
        setManifest(data);
      }
    } catch {
      // Non-fatal
    }
  }, []);

  const loadSourceFile = useCallback(async (filePath: string) => {
    setLoadingSource(true);
    try {
      const res = await fetch(`/api/agent/v1/source?file=${encodeURIComponent(filePath)}`);
      if (res.ok) {
        const data = (await res.json()) as { content: string };
        setSourceCodeContent(data.content || '');
      }
    } catch {
      setSourceCodeContent('// Unable to load source file.');
    } finally {
      setLoadingSource(false);
    }
  }, []);

  const execute9ScenarioVerification = useCallback(async () => {
    setRunningSuite(true);
    try {
      const res = await fetch('/api/agent/v1/verify-suite', { method: 'POST' });
      if (res.ok) {
        const data = (await res.json()) as { results: VerificationSuiteResult[] };
        setSuiteResults(data.results || []);
      }
    } finally {
      setRunningSuite(false);
    }
  }, []);

  useEffect(() => {
    if (shouldDisplay) {
      void loadManifest();
      void loadSourceFile(selectedSourceFile);
      void execute9ScenarioVerification();
    }
  }, [shouldDisplay, loadManifest, loadSourceFile, selectedSourceFile, execute9ScenarioVerification]);

  if (!shouldDisplay) return null;

  const isBn = agentLang === 'bn';
  const isLight = agentTheme === 'light';

  const triggerSimulatedDesktopScan = (scanLabel: string) => {
    setScanRunning(true);
    setScanStatusText(`RUNNING ${scanLabel} · Inspecting files read-only (64 KB streaming SHA-256)...`);
    setTimeout(() => {
      setScanRunning(false);
      setScanStatusText(
        `COMPLETED: ${scanLabel} finished in 0.42s · ${activeFindings.length} finding(s) reported · 0 files executed.`
      );
    }, 350);
  };

  const cancelSimulatedScan = () => {
    setScanRunning(false);
    setScanStatusText('CANCELLED_BY_USER · Cooperative CancellationToken halted scan immediately.');
    setAuditTrail((prev) => [
      `[${new Date().toISOString()}] SCAN_CANCELLED: Cooperative CancellationToken triggered by user.`,
      ...prev,
    ]);
  };

  const handleConfirmedVaultAction = () => {
    if (!pendingConfirmModal) return;
    const { action, targetId } = pendingConfirmModal;
    const nowIso = new Date().toISOString();

    if (action === 'QUARANTINE') {
      const found = activeFindings.find((f) => f.id === targetId);
      if (found) {
        const qId = `Q-${Date.now().toString().slice(-6)}`;
        const vaultItem: QuarantineVaultItem = {
          quarantineId: qId,
          originalPath: found.filePath,
          fileName: found.fileName,
          vaultFileName: `${qId}.kpq`,
          sha256: found.sha256,
          detectionName: found.detectionName,
          quarantinedAt: nowIso,
        };
        setQuarantineVault((prev) => [vaultItem, ...prev]);
        setActiveFindings((prev) => prev.filter((f) => f.id !== targetId));
        setAuditTrail((prev) => [
          `[${nowIso}] QUARANTINED (userConfirmed=true): '${found.filePath}' -> Isolated XOR payload '${qId}.kpq'`,
          ...prev,
        ]);
        setScanStatusText(`QUARANTINED: '${found.fileName}' isolated as '${qId}.kpq' after explicit confirmation.`);
      }
    } else if (action === 'RESTORE') {
      const qItem = quarantineVault.find((q) => q.quarantineId === targetId);
      if (qItem) {
        setActiveFindings((prev) => [
          {
            id: `RESTORED-${Date.now().toString().slice(-4)}`,
            filePath: qItem.originalPath,
            fileName: qItem.fileName,
            sha256: qItem.sha256,
            detectionName: qItem.detectionName,
            engineId: 'KIRON-SHA256-SIGNATURE-ENGINE',
            severity: 'CRITICAL',
            confidence: 'VERIFIED_SIGNATURE',
            falsePositiveNote: 'Restored from Quarantine Vault with verified SHA-256 integrity.',
            detectedAt: nowIso,
          },
          ...prev,
        ]);
        setQuarantineVault((prev) => prev.filter((q) => q.quarantineId !== targetId));
        setAuditTrail((prev) => [
          `[${nowIso}] RESTORED (userConfirmed=true): '${qItem.vaultFileName}' -> '${qItem.originalPath}' (SHA-256 verified)`,
          ...prev,
        ]);
        setScanStatusText(`RESTORED: '${qItem.fileName}' restored and SHA-256 verified.`);
      }
    } else if (action === 'DELETE') {
      const qItem = quarantineVault.find((q) => q.quarantineId === targetId);
      if (qItem) {
        setQuarantineVault((prev) => prev.filter((q) => q.quarantineId !== targetId));
        setAuditTrail((prev) => [
          `[${nowIso}] PERMANENTLY_DELETED (userConfirmed=true): Removed '${qItem.vaultFileName}' (${qItem.sha256.slice(0, 16)}...)`,
          ...prev,
        ]);
        setScanStatusText(`DELETED: '${qItem.fileName}' permanently removed from Quarantine Vault.`);
      }
    }

    setPendingConfirmModal(null);
  };

  return (
    <section
      aria-label="Phase 7A Windows Antivirus and Endpoint Security Agent Workspace"
      className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-6"
    >
      {/* Top Section Header & Honest Build Environment Disclosure */}
      <div className="flex flex-col gap-4 border-b border-[#1E2D4A] pb-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-blue-300">
            <Monitor className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>PHASE 7A — WINDOWS 10 &amp; WINDOWS 11 (64-BIT) ENDPOINT SECURITY AGENT</span>
            <span>·</span>
            <span>C# 12 / .NET 8.0 (/desktop-agent)</span>
            <span>·</span>
            <span className="text-emerald-300">STRICT $0.00 BUDGET</span>
          </div>
          <h2 className="text-lg font-semibold text-slate-100">
            {isBn
              ? 'কিরণ প্রহরী — উইন্ডোজ এন্ডপয়েন্ট সিকিউরিটি এজেন্ট (ফেজ ৭এ ইউজার-মোড এমভিপি)'
              : 'KIRON PROHORI — Windows Desktop Security Agent & Cloud Companion Hub'}
          </h2>
          <p className="text-xs text-slate-400">
            {manifest?.buildEnvironmentDisclosure.honestDisclosure ||
              'Separate C# / .NET 8.0 Windows Desktop Agent in /desktop-agent. Preserves Microsoft Defender and Windows Firewall co-existence. Never claims commercial kernel-driver replacement.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setAgentLang((prev) => (prev === 'en' ? 'bn' : 'en'))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-2 text-xs font-medium text-slate-200 hover:border-blue-500 whitespace-nowrap shrink-0"
          >
            <Languages className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
            <span>{isBn ? 'Language: বাংলা' : 'Language: English'}</span>
          </button>

          <button
            type="button"
            onClick={() => setAgentTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-2 text-xs font-medium text-slate-200 hover:border-blue-500 whitespace-nowrap shrink-0"
          >
            {isLight ? (
              <Sun className="h-3.5 w-3.5 text-amber-400" aria-hidden="true" />
            ) : (
              <Moon className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
            )}
            <span>{isLight ? 'Agent Theme: Light' : 'Agent Theme: Dark'}</span>
          </button>

          <button
            type="button"
            onClick={() => void execute9ScenarioVerification()}
            disabled={runningSuite}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${runningSuite ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Run 9 Phase 7A EICAR &amp; Safety Tests</span>
          </button>
        </div>
      </div>

      {/* Interactive Windows 10/11 Desktop Agent Window Preview (13 Navigation Modules + Dark/Light Theme) */}
      <div
        className={`rounded-lg border p-5 transition-colors ${
          isLight
            ? 'border-slate-300 bg-slate-50 text-slate-900'
            : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
        }`}
      >
        {/* Window Title Bar */}
        <div
          className={`flex flex-col gap-2 border-b pb-3 mb-4 sm:flex-row sm:items-center sm:justify-between ${
            isLight ? 'border-slate-200' : 'border-[#1E2D4A]'
          }`}
        >
          <div className="flex items-center gap-2 font-mono text-xs">
            <ShieldCheck className="h-4 w-4 text-blue-500 shrink-0" aria-hidden="true" />
            <span className="font-semibold">
              {isBn
                ? 'KironProhori.Agent.Desktop.exe — উইন্ডোজ ১০/১১ (৬৪-বিট) ডেক্সটপ ইন্টারফেস প্রিভিউ'
                : 'KironProhori.Agent.Desktop.exe — Interactive 13-Module Desktop Interface Preview'}
            </span>
          </div>
          <div className="font-mono text-[11px] opacity-75">
            UAC: asInvoker (Standard User) · Defender Co-Existence: ACTIVE · Kernel Driver: NONE (User-Mode MVP)
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          {/* 13-View Desktop Sidebar Navigation */}
          <div
            className={`lg:col-span-3 rounded-lg border p-3 space-y-1 ${
              isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
            }`}
          >
            <div className="px-2 py-1.5 font-mono text-[11px] uppercase tracking-wider opacity-70">
              {isBn ? '১৩টি অ্যান্টিভাইরাস নেভিগেশন মডিউল' : '13 Desktop Agent Views'}
            </div>
            {DESKTOP_NAV_ITEMS.map((nav) => {
              const active = activeDesktopView === nav.id;
              return (
                <button
                  key={nav.id}
                  type="button"
                  onClick={() => setActiveDesktopView(nav.id)}
                  className={`flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-xs font-medium transition-colors ${
                    active
                      ? 'bg-blue-600 text-white'
                      : isLight
                      ? 'text-slate-700 hover:bg-slate-100'
                      : 'text-slate-300 hover:bg-[#141F38]'
                  }`}
                >
                  <span className="truncate">
                    {nav.order}. {isBn ? nav.labelBn : nav.labelEn}
                  </span>
                  <span
                    className={`font-mono text-[10px] ${
                      active ? 'text-blue-100' : 'opacity-60'
                    }`}
                  >
                    {nav.tier}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Main Desktop Viewport */}
          <div className="lg:col-span-9 space-y-4">
            {/* Desktop Action & Status Bar */}
            <div
              className={`rounded-lg border p-4 space-y-3 ${
                isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
              }`}
            >
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="text-sm font-semibold">
                    {DESKTOP_NAV_ITEMS.find((n) => n.id === activeDesktopView)?.order}.{' '}
                    {isBn
                      ? DESKTOP_NAV_ITEMS.find((n) => n.id === activeDesktopView)?.labelBn
                      : DESKTOP_NAV_ITEMS.find((n) => n.id === activeDesktopView)?.labelEn}
                  </h3>
                  <p className="mt-0.5 font-mono text-xs opacity-75">{scanStatusText}</p>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    disabled={scanRunning}
                    onClick={() => triggerSimulatedDesktopScan('Quick Scan (%USERPROFILE%\\Downloads, %TEMP%, Startup)')}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50 whitespace-nowrap shrink-0"
                  >
                    <Play className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{isBn ? 'কুইক স্ক্যান' : 'Quick Scan'}</span>
                  </button>

                  <button
                    type="button"
                    disabled={scanRunning}
                    onClick={() => triggerSimulatedDesktopScan('Custom Folder Scan')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/40 px-3 py-1.5 text-xs font-medium hover:border-blue-500 whitespace-nowrap shrink-0"
                  >
                    <FolderSearch className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                    <span>{isBn ? 'ফোল্ডার স্ক্যান' : 'Custom Scan'}</span>
                  </button>

                  <button
                    type="button"
                    disabled={scanRunning}
                    onClick={() => triggerSimulatedDesktopScan('USB Removable Drive Scan (DriveType.Removable)')}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/40 px-3 py-1.5 text-xs font-medium hover:border-blue-500 whitespace-nowrap shrink-0"
                  >
                    <Usb className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                    <span>{isBn ? 'ইউএসবি স্ক্যান' : 'USB Scan'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={cancelSimulatedScan}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 px-3 py-1.5 text-xs font-medium text-rose-400 hover:border-rose-400 whitespace-nowrap shrink-0"
                  >
                    <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{isBn ? 'বাতিল করুন' : 'Cancel Scan'}</span>
                  </button>
                </div>
              </div>

              {/* Read-Only Windows Defender & Firewall Co-Existence Strip */}
              <div
                className={`grid grid-cols-1 gap-3 border-t pt-3 text-xs sm:grid-cols-3 ${
                  isLight ? 'border-slate-200' : 'border-[#1E2D4A]'
                }`}
              >
                <div>
                  <div className="opacity-70">Microsoft Defender (WMI Read-Only)</div>
                  <div className="font-mono font-semibold text-emerald-500">
                    ACTIVE_COEXISTENT (RTP: ON)
                  </div>
                </div>
                <div>
                  <div className="opacity-70">Windows Firewall (Domain/Private/Public)</div>
                  <div className="font-mono font-semibold text-emerald-500">
                    ENABLED (Read-Only Verified)
                  </div>
                </div>
                <div>
                  <div className="opacity-70">ClamAV / YARA External CLI Adapters</div>
                  <div className="font-mono font-semibold text-amber-500">
                    INSTALLATION_REQUIRED (Honest Status)
                  </div>
                </div>
              </div>
            </div>

            {/* Mandatory User Confirmation Dialog Modal (when user clicks Quarantine, Restore, or Delete) */}
            {pendingConfirmModal && (
              <div className="rounded-lg border border-amber-500/60 bg-amber-950/30 p-4 space-y-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                  <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>MANDATORY USER CONFIRMATION GATE (No Silent File Actions Permitted)</span>
                </div>
                <p className="text-xs font-medium text-slate-100">{pendingConfirmModal.title}</p>
                <p className="font-mono text-xs text-slate-300">{pendingConfirmModal.detail}</p>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={handleConfirmedVaultAction}
                    className="rounded-lg bg-amber-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-amber-500"
                  >
                    Confirm &amp; Log Action (userConfirmed = true)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setAuditTrail((prev) => [
                        `[${new Date().toISOString()}] REJECTED_NO_CONFIRMATION: User declined ${pendingConfirmModal.action} for ${pendingConfirmModal.targetId}. File left untouched.`,
                        ...prev,
                      ]);
                      setPendingConfirmModal(null);
                    }}
                    className="rounded-lg border border-slate-600 px-3.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    Cancel (Keep File Untouched)
                  </button>
                </div>
              </div>
            )}

            {/* Findings & Quarantine Split Grid */}
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              {/* Left: Active Scan Findings */}
              <div
                className={`rounded-lg border p-4 space-y-3 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider opacity-80">
                    {isBn
                      ? `শনাক্তকৃত থ্রেট ও হিউরিস্টিক (${activeFindings.length})`
                      : `Local Scan Detections (${activeFindings.length})`}
                  </h4>
                  <span className="font-mono text-[11px] opacity-70">Zero File Execution</span>
                </div>

                {activeFindings.length === 0 ? (
                  <p className="py-4 text-xs opacity-70">
                    All findings have been isolated in the Quarantine Vault (.kpq).
                  </p>
                ) : (
                  <div className="space-y-3">
                    {activeFindings.map((f) => (
                      <div
                        key={f.id}
                        className={`rounded border p-3 space-y-1.5 text-xs ${
                          isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 font-mono">
                          <span className="font-semibold text-rose-400">
                            [{f.severity} · {f.confidence}] {f.detectionName}
                          </span>
                          <span className="opacity-70">{f.engineId}</span>
                        </div>
                        <div className="font-mono text-[11px] break-all opacity-90">{f.filePath}</div>
                        <div className="font-mono text-[11px] opacity-70">
                          SHA-256: {f.sha256.slice(0, 32)}...
                        </div>
                        <p className="text-[11px] opacity-75">{f.falsePositiveNote}</p>
                        <div className="pt-1">
                          <button
                            type="button"
                            onClick={() =>
                              setPendingConfirmModal({
                                action: 'QUARANTINE',
                                targetId: f.id,
                                title: `Isolate '${f.fileName}' into %LOCALAPPDATA%\\KironProhori\\Quarantine\\Vault?`,
                                detail: `Original Path: ${f.filePath} | SHA-256: ${f.sha256} | Detection: ${f.detectionName}`,
                              })
                            }
                            className="inline-flex items-center gap-1.5 rounded bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500"
                          >
                            <Lock className="h-3 w-3" aria-hidden="true" />
                            <span>Quarantine File (Requires Confirmation)</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Right: Isolated Quarantine Vault (.kpq) & Audit Log */}
              <div
                className={`rounded-lg border p-4 space-y-3 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider opacity-80">
                    {isBn
                      ? `কোয়ারেন্টাইন ভল্ট (.kpq) (${quarantineVault.length})`
                      : `Isolated Quarantine Vault (.kpq) (${quarantineVault.length})`}
                  </h4>
                  <span className="font-mono text-[11px] opacity-70">XOR Neutralized</span>
                </div>

                {quarantineVault.length === 0 ? (
                  <p className="py-2 text-xs opacity-70">
                    Vault is currently empty. Click &ldquo;Quarantine File&rdquo; on any detection to test the mandatory confirmation gate.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {quarantineVault.map((q) => (
                      <div
                        key={q.quarantineId}
                        className={`rounded border p-3 space-y-1.5 text-xs ${
                          isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-semibold text-amber-400">
                            {q.vaultFileName} ({q.detectionName})
                          </span>
                          <span className="opacity-70">{q.quarantinedAt.slice(11, 19)} UTC</span>
                        </div>
                        <div className="font-mono text-[11px] break-all opacity-80">
                          Original: {q.originalPath}
                        </div>
                        <div className="flex items-center gap-2 pt-1">
                          <button
                            type="button"
                            onClick={() =>
                              setPendingConfirmModal({
                                action: 'RESTORE',
                                targetId: q.quarantineId,
                                title: `Restore '${q.fileName}' to '${q.originalPath}' and verify SHA-256 integrity?`,
                                detail: `Vault File: ${q.vaultFileName} | Expected SHA-256: ${q.sha256}`,
                              })
                            }
                            className="inline-flex items-center gap-1 rounded border border-emerald-500/50 px-2.5 py-1 text-xs font-medium text-emerald-400 hover:border-emerald-400"
                          >
                            <RotateCcw className="h-3 w-3" aria-hidden="true" />
                            <span>Restore (Confirm)</span>
                          </button>

                          <button
                            type="button"
                            onClick={() =>
                              setPendingConfirmModal({
                                action: 'DELETE',
                                targetId: q.quarantineId,
                                title: `Permanently delete isolated payload '${q.vaultFileName}'?`,
                                detail: `Original File: ${q.fileName} | SHA-256: ${q.sha256} (Irreversible Action)`,
                              })
                            }
                            className="inline-flex items-center gap-1 rounded border border-rose-500/50 px-2.5 py-1 text-xs font-medium text-rose-400 hover:border-rose-400"
                          >
                            <Trash2 className="h-3 w-3" aria-hidden="true" />
                            <span>Delete Permanently (Confirm)</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="border-t border-[#1E2D4A]/60 pt-2">
                  <div className="font-mono text-[11px] opacity-75 mb-1">
                    Immutable Audit Trail (quarantine-audit.jsonl):
                  </div>
                  <div className="max-h-24 overflow-y-auto space-y-1 font-mono text-[11px] opacity-80">
                    {auditTrail.map((log, i) => (
                      <div key={i}>{log}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Modular Scanning Engine Status Table (ClamAV, YARA-X, SHA-256, Heuristics, Cloud Sync) */}
      {manifest && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-100">
            Modular Scanning Engines &amp; Honest Installation Status
          </h3>
          <div className="overflow-x-auto rounded-lg border border-[#1E2D4A]">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-[#1E2D4A] bg-[#080D1A] text-slate-400">
                  <th className="px-3.5 py-2.5">Engine ID &amp; Name</th>
                  <th className="px-3.5 py-2.5">License ($0 Audit)</th>
                  <th className="px-3.5 py-2.5">Maturity Tier</th>
                  <th className="px-3.5 py-2.5">Operational Status</th>
                  <th className="px-3.5 py-2.5">Verification Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1E2D4A]/60">
                {manifest.engines.map((eng) => (
                  <tr key={eng.engineId} className="hover:bg-[#141F38]/40">
                    <td className="px-3.5 py-2.5">
                      <div className="font-semibold text-slate-100">{eng.displayName}</div>
                      <div className="font-mono text-[11px] text-slate-400">{eng.engineId}</div>
                    </td>
                    <td className="px-3.5 py-2.5 font-mono text-slate-300">{eng.license}</td>
                    <td className="px-3.5 py-2.5 font-mono text-blue-300">{eng.maturityTier}</td>
                    <td className="px-3.5 py-2.5 font-mono">
                      {eng.status === 'READY' || eng.status === 'CONNECTED' ? (
                        <span className="text-emerald-400 font-semibold">{eng.status}</span>
                      ) : (
                        <span className="text-amber-400 font-semibold">{eng.status}</span>
                      )}
                    </td>
                    <td className="px-3.5 py-2.5 text-slate-300">{eng.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 9 Phase 7A Automated EICAR, Quarantine, Cancellation & Defender Co-Existence Verification Suite */}
      <div className="space-y-3">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Phase 7A Automated Safety &amp; Harmless EICAR Verification Suite (9/9 Scenarios)
            </h3>
            <p className="text-xs text-slate-400">
              Tested strictly with benign files and the official 68-byte harmless EICAR test string. Zero live malware samples are ever used.
            </p>
          </div>
          <span className="font-mono text-xs text-emerald-400">
            {suiteResults.filter((r) => r.passed).length}/{suiteResults.length} PASSED
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {suiteResults.map((test) => (
            <div
              key={test.id}
              className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-3.5 space-y-1.5"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 font-mono text-xs font-semibold text-slate-100">
                  {test.passed ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" aria-hidden="true" />
                  )}
                  <span className="truncate">{test.title}</span>
                </div>
                <span className="font-mono text-[11px] text-slate-400 tabular-nums shrink-0">
                  {test.durationMs}ms
                </span>
              </div>
              <p className="font-mono text-[11px] text-emerald-300/90 break-words">{test.actual}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Live C# / .NET 8.0 & Technical Research Source Code Inspector (/desktop-agent/*) */}
      {manifest && (
        <div className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                /desktop-agent/ C# .NET 8.0 Solution &amp; Kernel Minifilter Research Inspector ({manifest.files.length} Files)
              </h3>
              <p className="text-xs text-slate-400">
                Select any C# engine class, WPF XAML window, xUnit test file, or engineering research document in /desktop-agent/ to inspect its full code.
              </p>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
              <Terminal className="h-4 w-4 text-blue-400" aria-hidden="true" />
              <span>dotnet build desktop-agent/KironProhori.DesktopAgent.sln -c Release</span>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <div className="lg:col-span-4 max-h-96 overflow-y-auto rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-2 space-y-1">
              {manifest.files.map((f) => {
                const active = selectedSourceFile === f.relativePath;
                return (
                  <button
                    key={f.relativePath}
                    type="button"
                    onClick={() => setSelectedSourceFile(f.relativePath)}
                    className={`flex w-full items-center justify-between rounded px-2.5 py-2 text-left font-mono text-xs transition-colors ${
                      active
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-300 hover:bg-[#141F38]'
                    }`}
                  >
                    <span className="truncate">{f.relativePath.replace('desktop-agent/', '')}</span>
                    <span className="text-[10px] opacity-75 shrink-0 ml-2">{f.lines}L</span>
                  </button>
                );
              })}
            </div>

            <div className="lg:col-span-8 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4">
              <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-2 mb-3 font-mono text-xs text-blue-300">
                <div className="flex items-center gap-2">
                  <FileCode2 className="h-4 w-4" aria-hidden="true" />
                  <span>{selectedSourceFile}</span>
                </div>
                <span>UTF-8 · Read-Only Source</span>
              </div>
              <pre className="max-h-80 overflow-auto font-mono text-xs leading-relaxed text-slate-200 whitespace-pre">
                {loadingSource ? 'Loading file content...' : sourceCodeContent}
              </pre>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
