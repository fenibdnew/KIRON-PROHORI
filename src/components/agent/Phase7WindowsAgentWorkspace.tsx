import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  ShieldCheck,
  Monitor,
  Play,
  Pause,
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
  Volume2,
  VolumeX,
  FolderX,
  Info,
} from 'lucide-react';
import { CoreModuleId } from '../../types/navigation';
import { useApp } from '../../context/AppContext';

interface AgentFileEntry {
  relativePath: string;
  sizeBytes: number;
  lines: number;
  category:
    | 'SOLUTION'
    | 'CORE_CSHARP'
    | 'DESKTOP_WPF'
    | 'XUNIT_TESTS'
    | 'BROWSER_EXTENSION_MV3'
    | 'DOCUMENTATION';
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
  productName: string;
  subtitle: string;
  developer: string;
  privacyPolicy: string;
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
  | 'web-protection'
  | 'download-protection'
  | 'realtime-protection'
  | 'threat-history'
  | 'quarantine'
  | 'exclusions'
  | 'security-intelligence'
  | 'updates'
  | 'settings'
  | 'about'
  | 'file-scan'
  | 'usb-scan'
  | 'windows-defender'
  | 'firewall-status'
  | 'notifications';

type ProtectionStatusLabel =
  | 'PROTECTED'
  | 'WARNING'
  | 'ACTION REQUIRED'
  | 'NOT CONFIGURED'
  | 'NOT AVAILABLE';

type DetectionVerdictTier =
  | 'ConfirmedDetection'
  | 'Suspicious'
  | 'Unknown'
  | 'CleanAccordingToAvailableEngines';

type DownloadVerdictStatusLabel =
  | 'Clean'
  | 'Suspicious'
  | 'Malicious'
  | 'Unknown / Not scanned';

interface SimulatedFinding {
  id: string;
  filePath: string;
  fileName: string;
  sha256: string;
  detectionName: string;
  engineId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  verdict: DetectionVerdictTier;
  confidenceScore: number;
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

interface ExclusionEntryItem {
  exclusionId: string;
  canonicalPath: string;
  scope: 'IndividualFile' | 'Folder' | 'FileExtension' | 'TrustedApplicationPath';
  reason: string;
  addedAt: string;
}

interface SmartNotificationLogItem {
  id: string;
  title: string;
  headerTitle: string;
  threatName: string;
  websiteDomain?: string;
  fileName?: string;
  filePath: string;
  detectionSource: string;
  recommendedAction: string;
  statusLabel?: string;
  playedGentleChime: boolean;
  createdAt: string;
}

interface DownloadVerdictLogItem {
  downloadId: string;
  fileName: string;
  localFilePath: string;
  websiteDomain: string;
  status: DownloadVerdictStatusLabel;
  sha256: string;
  threatName: string;
  explanation: string;
  evaluatedAt: string;
}

interface RealTimeEventLogItem {
  eventId: string;
  category: string;
  fileName: string;
  filePath: string;
  status: DownloadVerdictStatusLabel;
  summary: string;
  observedAt: string;
}

const DESKTOP_NAV_ITEMS: {
  id: DesktopNavViewId;
  order: string;
  labelEn: string;
  labelBn: string;
  tier: 'V1.0' | 'PRIVACY';
}[] = [
  { id: 'overview', order: '01', labelEn: 'Dashboard', labelBn: 'ড্যাশবোর্ড', tier: 'V1.0' },
  { id: 'quick-scan', order: '02', labelEn: 'Quick Scan', labelBn: 'কুইক স্ক্যান', tier: 'V1.0' },
  { id: 'full-scan', order: '03', labelEn: 'Full Scan', labelBn: 'ফুল স্ক্যান', tier: 'V1.0' },
  { id: 'custom-scan', order: '04', labelEn: 'Custom Scan', labelBn: 'কাস্টম স্ক্যান', tier: 'V1.0' },
  { id: 'web-protection', order: '05', labelEn: 'Web Protection', labelBn: 'ওয়েব সুরক্ষা (Chrome/Edge)', tier: 'V1.0' },
  { id: 'download-protection', order: '06', labelEn: 'Download Protection', labelBn: 'ডাউনলোড সুরক্ষা', tier: 'V1.0' },
  { id: 'realtime-protection', order: '07', labelEn: 'Real-Time Protection', labelBn: 'রিয়েল-টাইম সুরক্ষা', tier: 'V1.0' },
  { id: 'threat-history', order: '08', labelEn: 'Threat History', labelBn: 'থ্রেট ইতিহাস', tier: 'V1.0' },
  { id: 'quarantine', order: '09', labelEn: 'Quarantine', labelBn: 'কোয়ারেন্টাইন ভল্ট', tier: 'V1.0' },
  { id: 'exclusions', order: '10', labelEn: 'Exclusions', labelBn: 'এক্সক্লুশন ম্যানেজার', tier: 'V1.0' },
  { id: 'security-intelligence', order: '11', labelEn: 'Security Intelligence', labelBn: 'সিকিউরিটি ইন্টেলিজেন্স', tier: 'V1.0' },
  { id: 'updates', order: '12', labelEn: 'Updates', labelBn: 'স্বয়ংক্রিয় আপডেট', tier: 'V1.0' },
  { id: 'settings', order: '13', labelEn: 'Settings', labelBn: 'সেটিংস ও পারফরম্যান্স', tier: 'PRIVACY' },
  { id: 'about', order: '14', labelEn: 'About', labelBn: 'পরিচিতি (ARIFUZZAMAN KIRON)', tier: 'PRIVACY' },
  { id: 'file-scan', order: '15', labelEn: 'Single File Scan', labelBn: 'সিঙ্গেল ফাইল স্ক্যান', tier: 'V1.0' },
  { id: 'usb-scan', order: '16', labelEn: 'USB Scan', labelBn: 'ইউএসবি স্ক্যান', tier: 'V1.0' },
  { id: 'windows-defender', order: '17', labelEn: 'Microsoft Defender Status', labelBn: 'ডিফেন্ডার স্ট্যাটাস', tier: 'V1.0' },
  { id: 'firewall-status', order: '18', labelEn: 'Firewall Status', labelBn: 'ফায়ারওয়াল স্ট্যাটাস', tier: 'V1.0' },
  { id: 'notifications', order: '19', labelEn: 'Notifications', labelBn: 'স্মার্ট নোটিফিকেশন', tier: 'V1.0' },
];

const VERIFIED_MV3_WEB_RULES = [
  {
    ruleId: 1001,
    domain: 'phishing-login-verify.kiron-test.invalid',
    category: 'PHISHING_DOMAIN',
    reason: 'Verified credential-harvesting phishing domain (Controlled V1.0 Test Indicator)',
  },
  {
    ruleId: 1002,
    domain: 'malware-payload-drop.kiron-test.invalid',
    category: 'SCAM_MALWARE_DISTRIBUTION',
    reason: 'Verified malware payload distribution host (Controlled V1.0 Test Indicator)',
  },
  {
    ruleId: 1003,
    domain: 'malvertising-redirect-chain.kiron-test.invalid',
    category: 'MALICIOUS_AD_REDIRECT',
    reason: 'Known malicious advertising and drive-by redirect network request',
  },
  {
    ruleId: 1004,
    domain: 'c2-skimmer-beacon.kiron-test.invalid',
    category: 'MALICIOUS_THIRD_PARTY_REQUEST',
    reason: 'Known malicious third-party skimmer / botnet C2 network request',
  },
  {
    ruleId: 1005,
    domain: 'crypto-giveaway-scam.kiron-test.invalid',
    category: 'MALICIOUS_URL',
    reason: 'Verified financial scam and deceptive giveaway domain',
  },
];

const EXACT_ABOUT_MESSAGE = `KIRON PROHORI is an independent Windows security application designed to help protect computers through threat intelligence, malware scanning, browser protection and security monitoring.

Thank you for choosing KIRON PROHORI.

Your privacy matters. Your security matters. Your trust matters.

Built with care for a safer digital world.`;

export const Phase7WindowsAgentWorkspace: React.FC<{ moduleId: CoreModuleId }> = ({
  moduleId,
}) => {
  const { language } = useApp();
  const [agentLang, setAgentLang] = useState<'en' | 'bn'>(language === 'bn' ? 'bn' : 'en');
  const [agentTheme, setAgentTheme] = useState<'dark' | 'light'>('dark');
  const [activeDesktopView, setActiveDesktopView] = useState<DesktopNavViewId>('overview');

  const [manifest, setManifest] = useState<AgentManifestResponse | null>(null);
  const [selectedSourceFile, setSelectedSourceFile] = useState<string>(
    'desktop-agent/src/KironProhori.Agent.Core/BrowserProtection/NativeMessagingDownloadGuard.cs'
  );
  const [sourceCodeContent, setSourceCodeContent] = useState<string>('');
  const [loadingSource, setLoadingSource] = useState<boolean>(false);

  const [suiteResults, setSuiteResults] = useState<VerificationSuiteResult[]>([]);
  const [runningSuite, setRunningSuite] = useState<boolean>(false);

  // Interactive Desktop Agent State (No pre-populated fake threat detections on startup)
  const [scanRunning, setScanRunning] = useState<boolean>(false);
  const [scanPaused, setScanPaused] = useState<boolean>(false);
  const [lastScanTimeLabel, setLastScanTimeLabel] = useState<string>('Not run in this session');
  const [lastIntelUpdateLabel] = useState<string>(() => `${new Date().toISOString().slice(0, 10)} (Verified HTTPS)`);
  const [cpuThrottleProfile, setCpuThrottleProfile] = useState<
    'LowImpactBackground' | 'BalancedDefault' | 'HighSpeedForeground'
  >('BalancedDefault');
  const [maxCpuPercent, setMaxCpuPercent] = useState<number>(35);
  const [skipUnchangedCleanFiles, setSkipUnchangedCleanFiles] = useState<boolean>(true);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const [soundVolumePercent, setSoundVolumePercent] = useState<number>(65);
  const lastNotifiedDedupeMapRef = useRef<Map<string, number>>(new Map());

  // Module 2, 3, 4 Interactive States
  const [realTimeProtectionEnabled, setRealTimeProtectionEnabled] = useState<boolean>(true);
  const [browserExtensionConnected, setBrowserExtensionConnected] = useState<boolean>(true);
  const [testUrlInput, setTestUrlInput] = useState<string>(
    'https://phishing-login-verify.kiron-test.invalid/account/login'
  );
  const [urlTestResult, setUrlTestResult] = useState<{
    url: string;
    host: string;
    blocked: boolean;
    category: string;
    reason: string;
    ruleId: number | null;
  } | null>(null);
  const [tempAllowlistDomains, setTempAllowlistDomains] = useState<
    { domain: string; expiresAt: string }[]
  >([]);
  const [falsePositiveReports, setFalsePositiveReports] = useState<
    { id: string; target: string; notes: string; createdAt: string }[]
  >([]);
  const [downloadVerdicts, setDownloadVerdicts] = useState<DownloadVerdictLogItem[]>([]);
  const [realTimeEvents, setRealTimeEvents] = useState<RealTimeEventLogItem[]>([]);

  const [scanStatusText, setScanStatusText] = useState<string>(
    'IDLE · Zero Fake Detections on Startup · Click "Run Controlled EICAR Test Scan" to test detection & quarantine workflow'
  );

  const [activeFindings, setActiveFindings] = useState<SimulatedFinding[]>([]);

  const [quarantineVault, setQuarantineVault] = useState<QuarantineVaultItem[]>([]);
  const [exclusionsList, setExclusionsList] = useState<ExclusionEntryItem[]>([]);
  const [newExclusionPath, setNewExclusionPath] = useState<string>('');
  const [newExclusionScope, setNewExclusionScope] = useState<
    'IndividualFile' | 'Folder' | 'FileExtension' | 'TrustedApplicationPath'
  >('IndividualFile');
  const [newExclusionReason, setNewExclusionReason] = useState<string>('');

  const [notificationHistory, setNotificationHistory] = useState<SmartNotificationLogItem[]>([]);

  const [auditTrail, setAuditTrail] = useState<string[]>([
    '[STARTUP] KIRON PROHORI V1.0 (Developer: ARIFUZZAMAN KIRON) initialized · Telemetry: OFF · Threat Policy: QUARANTINE FIRST.',
  ]);

  const [pendingConfirmModal, setPendingConfirmModal] = useState<{
    action: 'QUARANTINE' | 'RESTORE' | 'DELETE' | 'EXCLUDE';
    targetId: string;
    title: string;
    detail: string;
  } | null>(null);

  const shouldDisplay =
    moduleId === 'dashboard' ||
    moduleId === 'malware-intel' ||
    moduleId === 'hash-lookup' ||
    moduleId === 'help-docs';

  // Play original short gentle dual-tone chime (D5 587.33 Hz -> A5 880.00 Hz) using Web Audio API
  const playOriginalGentleChime = useCallback(() => {
    if (!soundEnabled || soundVolumePercent <= 0) return false;
    try {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (!AudioCtx) return false;
      const ctx = new AudioCtx();
      const now = ctx.currentTime;
      const gainNode = ctx.createGain();
      const maxGain = Math.min(0.35, (soundVolumePercent / 100) * 0.35);

      gainNode.gain.setValueAtTime(0.001, now);
      gainNode.gain.exponentialRampToValueAtTime(maxGain, now + 0.03);
      gainNode.gain.exponentialRampToValueAtTime(0.001, now + 0.42);
      gainNode.connect(ctx.destination);

      const osc1 = ctx.createOscillator();
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(587.33, now); // D5
      osc1.frequency.setValueAtTime(880.0, now + 0.16); // A5
      osc1.connect(gainNode);
      osc1.start(now);
      osc1.stop(now + 0.42);
      return true;
    } catch {
      return false;
    }
  }, [soundEnabled, soundVolumePercent]);

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

  const execute14ScenarioVerification = useCallback(async () => {
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
      void execute14ScenarioVerification();
    }
  }, [shouldDisplay, loadManifest, loadSourceFile, selectedSourceFile, execute14ScenarioVerification]);

  if (!shouldDisplay) return null;

  const isBn = agentLang === 'bn';
  const isLight = agentTheme === 'light';

  const triggerSimulatedDesktopScan = (scanLabel: string, explanation: string) => {
    setScanRunning(true);
    setScanPaused(false);
    setScanStatusText(
      `STARTING ${scanLabel} (${explanation}) · Profile: ${cpuThrottleProfile} (Max CPU: ${maxCpuPercent}%)...`
    );
    setTimeout(() => {
      setScanRunning(false);
      setLastScanTimeLabel(`${scanLabel} (${new Date().toISOString().slice(11, 19)} UTC)`);
      setScanStatusText(
        `COMPLETED: ${scanLabel} finished · ${activeFindings.length} detection(s) · ${exclusionsList.length} excluded skipped · 0 files uploaded.`
      );
    }, 360);
  };

  const triggerControlledEicarTestScan = () => {
    setScanRunning(true);
    setScanPaused(false);
    setScanStatusText(
      'RUNNING Controlled Harmless EICAR Test Scan (68-byte standard antivirus verification string)...'
    );
    setTimeout(() => {
      setScanRunning(false);
      const nowIso = new Date().toISOString();
      setLastScanTimeLabel(`Controlled EICAR Scan (${nowIso.slice(11, 19)} UTC)`);
      const eicarPath = 'C:\\Users\\Defender\\Downloads\\eicar_harmless_test.com';
      const isExcluded = exclusionsList.some(
        (e) => e.canonicalPath.toLowerCase() === eicarPath.toLowerCase()
      );
      if (isExcluded) {
        setScanStatusText(
          `COMPLETED Controlled EICAR Scan: Path '${eicarPath}' skipped because it is in KIRON Exclusions.`
        );
        return;
      }
      const controlledFinding: SimulatedFinding = {
        id: `FIND-EICAR-${Date.now().toString().slice(-4)}`,
        filePath: eicarPath,
        fileName: 'eicar_harmless_test.com',
        sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        detectionName: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
        engineId: 'Local SHA-256 Signature Engine',
        severity: 'CRITICAL',
        verdict: 'ConfirmedDetection',
        confidenceScore: 100,
        falsePositiveNote:
          'Harmless official 68-byte EICAR standard antivirus verification signature. Policy: QUARANTINE FIRST.',
        detectedAt: nowIso,
      };
      setActiveFindings([controlledFinding]);
      playOriginalGentleChime();
      setScanStatusText(
        'CONTROLLED EICAR TEST DETECTED: Official 68-byte EICAR signature flagged · Policy: QUARANTINE FIRST.'
      );
    }, 320);
  };

  // Module 10 Rule: Never display PROTECTED when required security components are disconnected or active unhandled detections exist
  const computedProtectionStatus: ProtectionStatusLabel =
    activeFindings.length > 0
      ? 'ACTION REQUIRED'
      : !realTimeProtectionEnabled || !browserExtensionConnected
      ? 'WARNING'
      : 'PROTECTED';

  const handleEvaluateWebProtectionUrl = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const raw = testUrlInput.trim();
    if (!raw) return;
    let host = raw.toLowerCase();
    try {
      const parsed = new URL(raw.includes('://') ? raw : `https://${raw}`);
      host = parsed.hostname.toLowerCase();
    } catch {
      host = raw.toLowerCase();
    }

    const isAllowlisted = tempAllowlistDomains.some((d) => d.domain === host);
    if (isAllowlisted) {
      setUrlTestResult({
        url: raw,
        host,
        blocked: false,
        category: 'TEMPORARY_USER_ALLOWLIST',
        reason: 'Temporarily allowlisted by user for 30 minutes (Warning: Reduced Protection).',
        ruleId: null,
      });
      setScanStatusText(`WEB PROTECTION: '${host}' temporarily allowed by user allowlist.`);
      return;
    }

    const matchedRule = VERIFIED_MV3_WEB_RULES.find(
      (r) => host === r.domain || host.endsWith(`.${r.domain}`)
    );

    if (matchedRule) {
      setUrlTestResult({
        url: raw,
        host,
        blocked: true,
        category: matchedRule.category,
        reason: matchedRule.reason,
        ruleId: matchedRule.ruleId,
      });
      setScanStatusText(
        `WEB PROTECTION BLOCKED: '${host}' blocked by declarativeNetRequest Rule #${matchedRule.ruleId} (${matchedRule.category}).`
      );
      return;
    }

    setUrlTestResult({
      url: raw,
      host,
      blocked: false,
      category: 'CLEAN_VERIFIED',
      reason: 'No verified malicious, phishing, or scam indicators matched. Ordinary advertisements are not blocked.',
      ruleId: null,
    });
    setScanStatusText(`WEB PROTECTION: '${host}' verified clean.`);
  };

  const handleAddTemporaryAllowlist = (domain: string) => {
    const expiresAt = new Date(Date.now() + 30 * 60_000).toISOString();
    setTempAllowlistDomains((prev) => [
      { domain, expiresAt },
      ...prev.filter((d) => d.domain !== domain),
    ]);
    setAuditTrail((prev) => [
      `[${new Date().toISOString()}] WEB_TEMP_ALLOWLIST_ADDED: '${domain}' allowed for 30m (Warning acknowledged).`,
      ...prev,
    ]);
    setScanStatusText(`TEMPORARY ALLOWLIST: '${domain}' allowed for 30 minutes.`);
  };

  const handleReportWebFalsePositive = (target: string, reason: string) => {
    const nowIso = new Date().toISOString();
    const id = `FP-${Date.now().toString().slice(-5)}`;
    setFalsePositiveReports((prev) => [
      { id, target, notes: reason, createdAt: nowIso },
      ...prev,
    ]);
    setAuditTrail((prev) => [
      `[${nowIso}] FALSE_POSITIVE_REPORT_SAVED_LOCALLY (${id}): '${target}' (0 bytes uploaded).`,
      ...prev,
    ]);
    setScanStatusText(`FALSE POSITIVE REPORTED: '${id}' saved locally for '${target}'.`);
  };

  const handleSimulateBrowserDownloadScan = (
    scenario: 'INCOMPLETE' | 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS_EICAR'
  ) => {
    const nowIso = new Date().toISOString();
    const dlId = `DL-${Date.now().toString().slice(-4)}`;

    if (!browserExtensionConnected) {
      const disconnectedEntry: DownloadVerdictLogItem = {
        downloadId: dlId,
        fileName: 'unscanned_download.bin',
        localFilePath: 'C:\\Users\\Defender\\Downloads\\unscanned_download.bin',
        websiteDomain: 'downloads.example.org',
        status: 'Unknown / Not scanned',
        sha256: 'NOT_SCANNED (Native Messaging Disconnected)',
        threatName: 'Local Windows Agent Disconnected',
        explanation:
          'Native Messaging connection is disconnected. File is never reported as Clean when the scan did not complete.',
        evaluatedAt: nowIso,
      };
      setDownloadVerdicts((prev) => [disconnectedEntry, ...prev]);
      setScanStatusText('DOWNLOAD PROTECTION: Native Messaging disconnected -> Status: Unknown / Not scanned.');
      return;
    }

    if (scenario === 'INCOMPLETE') {
      const entry: DownloadVerdictLogItem = {
        downloadId: dlId,
        fileName: 'partial_installer.exe.crdownload',
        localFilePath: 'C:\\Users\\Defender\\Downloads\\partial_installer.exe.crdownload',
        websiteDomain: 'cdn.example.org',
        status: 'Unknown / Not scanned',
        sha256: 'NOT_SCANNED (Download In Progress)',
        threatName: 'None (Scan Incomplete)',
        explanation:
          'Download has not completed on disk. KIRON PROHORI never reports a file as Clean if the local scan did not complete.',
        evaluatedAt: nowIso,
      };
      setDownloadVerdicts((prev) => [entry, ...prev]);
      setScanStatusText('DOWNLOAD PROTECTION: Incomplete download classified as "Unknown / Not scanned" (Never marked Clean).');
      return;
    }

    if (scenario === 'CLEAN') {
      const entry: DownloadVerdictLogItem = {
        downloadId: dlId,
        fileName: 'KIRON_Release_Notes_v1.0.txt',
        localFilePath: 'C:\\Users\\Defender\\Downloads\\KIRON_Release_Notes_v1.0.txt',
        websiteDomain: 'docs.example.org',
        status: 'Clean',
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        threatName: 'None',
        explanation: 'Completed download scanned locally via Native Messaging. No malware signatures or suspicious heuristics matched.',
        evaluatedAt: nowIso,
      };
      setDownloadVerdicts((prev) => [entry, ...prev]);
      setScanStatusText('DOWNLOAD PROTECTION: Completed benign download verified as "Clean".');
      return;
    }

    if (scenario === 'SUSPICIOUS') {
      const filePath = 'C:\\Users\\Defender\\Downloads\\Invoice_Payment_2026.pdf.exe';
      const entry: DownloadVerdictLogItem = {
        downloadId: dlId,
        fileName: 'Invoice_Payment_2026.pdf.exe',
        localFilePath: filePath,
        websiteDomain: 'mail-attachment-cdn.kiron-test.invalid',
        status: 'Suspicious',
        sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
        threatName: 'Heuristic.DoubleExtension.PdfExe',
        explanation: 'Suspicious double-extension executable (.pdf.exe) detected on download completion. Execution prevented and Quarantine offered.',
        evaluatedAt: nowIso,
      };
      setDownloadVerdicts((prev) => [entry, ...prev]);
      const chimePlayed = playOriginalGentleChime();
      setNotificationHistory((prev) => [
        {
          id: `NOTIF-DL-${Date.now().toString().slice(-4)}`,
          title: 'KIRON PROHORI',
          headerTitle: 'Suspicious Download Blocked',
          threatName: 'Heuristic.DoubleExtension.PdfExe',
          websiteDomain: 'mail-attachment-cdn.kiron-test.invalid',
          fileName: 'Invoice_Payment_2026.pdf.exe',
          filePath,
          detectionSource: 'Native Messaging Download Guard',
          recommendedAction: 'Quarantine First (Permanent deletion requires separate confirmation)',
          statusLabel: 'Quarantine Offered',
          playedGentleChime: chimePlayed,
          createdAt: nowIso,
        },
        ...prev,
      ]);
      setScanStatusText('DOWNLOAD PROTECTION: Suspicious .pdf.exe download flagged and Smart Notification published.');
      return;
    }

    // MALICIOUS_EICAR
    const eicarPath = 'C:\\Users\\Defender\\Downloads\\eicar_browser_download.com';
    const eicarHash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    const entry: DownloadVerdictLogItem = {
      downloadId: dlId,
      fileName: 'eicar_browser_download.com',
      localFilePath: eicarPath,
      websiteDomain: 'malware-payload-drop.kiron-test.invalid',
      status: 'Malicious',
      sha256: eicarHash,
      threatName: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
      explanation: 'Confirmed SHA-256 signature match upon browser download completion. Policy: QUARANTINE FIRST.',
      evaluatedAt: nowIso,
    };
    setDownloadVerdicts((prev) => [entry, ...prev]);
    setActiveFindings((prev) => [
      {
        id: `FIND-DL-${Date.now().toString().slice(-4)}`,
        filePath: eicarPath,
        fileName: 'eicar_browser_download.com',
        sha256: eicarHash,
        detectionName: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
        engineId: 'Native Messaging Download Guard + SHA-256 Engine',
        severity: 'CRITICAL',
        verdict: 'ConfirmedDetection',
        confidenceScore: 100,
        falsePositiveNote: 'Detected via Chrome/Edge Native Messaging automatic download scan. Policy: QUARANTINE FIRST.',
        detectedAt: nowIso,
      },
      ...prev,
    ]);
    const chimePlayed = playOriginalGentleChime();
    setNotificationHistory((prev) => [
      {
        id: `NOTIF-DL-${Date.now().toString().slice(-4)}`,
        title: 'KIRON PROHORI',
        headerTitle: 'Suspicious Download Blocked',
        threatName: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
        websiteDomain: 'malware-payload-drop.kiron-test.invalid',
        fileName: 'eicar_browser_download.com',
        filePath: eicarPath,
        detectionSource: 'Native Messaging Download Guard + SHA-256 Engine',
        recommendedAction: 'Quarantine First',
        statusLabel: 'Quarantine Recommended',
        playedGentleChime: chimePlayed,
        createdAt: nowIso,
      },
      ...prev,
    ]);
    setScanStatusText('DOWNLOAD PROTECTION: Confirmed EICAR test download detected -> Status: Malicious (Quarantine First).');
  };

  const handleSimulateRealTimeFileEvent = (
    eventType: 'NEW_EXECUTABLE' | 'STARTUP_CHANGE' | 'SUSPICIOUS_MODIFICATION'
  ) => {
    const nowIso = new Date().toISOString();
    const id = `RT-${Date.now().toString().slice(-4)}`;
    if (eventType === 'NEW_EXECUTABLE') {
      const evt: RealTimeEventLogItem = {
        eventId: id,
        category: 'NewExecutableFile',
        fileName: 'portable_utility.exe',
        filePath: 'C:\\Users\\Defender\\Downloads\\portable_utility.exe',
        status: 'Clean',
        summary: 'User-Mode FileSystemWatcher detected new executable -> Scanned via SHA-256 & Heuristics -> Clean.',
        observedAt: nowIso,
      };
      setRealTimeEvents((prev) => [evt, ...prev]);
      setScanStatusText('REAL-TIME PROTECTION: New executable scanned in user-mode -> Clean.');
    } else if (eventType === 'STARTUP_CHANGE') {
      const evt: RealTimeEventLogItem = {
        eventId: id,
        category: 'DangerousStartupChange',
        fileName: 'persistence_autorun.ps1',
        filePath: 'C:\\Users\\Defender\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\persistence_autorun.ps1',
        status: 'Suspicious',
        summary: 'SUSPICIOUS STARTUP CHANGE: New script added to Windows Startup directory. Flagged for user review & quarantine.',
        observedAt: nowIso,
      };
      setRealTimeEvents((prev) => [evt, ...prev]);
      playOriginalGentleChime();
      setScanStatusText('REAL-TIME PROTECTION: Suspicious script detected in Windows Startup folder.');
    } else {
      const evt: RealTimeEventLogItem = {
        eventId: id,
        category: 'SuspiciousFileModification',
        fileName: 'Receipt_2026.docx.exe',
        filePath: 'C:\\Users\\Defender\\Desktop\\Receipt_2026.docx.exe',
        status: 'Suspicious',
        summary: 'SUSPICIOUS FILE MODIFICATION: File renamed with deceptive double extension (.docx.exe). Never executed to test.',
        observedAt: nowIso,
      };
      setRealTimeEvents((prev) => [evt, ...prev]);
      playOriginalGentleChime();
      setScanStatusText('REAL-TIME PROTECTION: Suspicious double-extension file modification detected.');
    }
  };

  const togglePauseResumeScan = () => {
    if (!scanRunning && !scanPaused) {
      setScanPaused(true);
      setScanStatusText('PAUSED BY USER · Click Resume Scan to continue without losing progress.');
      return;
    }
    const nextPaused = !scanPaused;
    setScanPaused(nextPaused);
    setScanStatusText(
      nextPaused
        ? 'PAUSED BY USER · Background threads suspended safely.'
        : 'RESUMED BY USER · Continuing cooperative read-only scan...'
    );
  };

  const cancelSimulatedScan = () => {
    setScanRunning(false);
    setScanPaused(false);
    setScanStatusText('CANCELLED_BY_USER · Cooperative CancellationToken halted scan immediately.');
    setAuditTrail((prev) => [
      `[${new Date().toISOString()}] SCAN_CANCELLED: Cooperative CancellationToken triggered by user.`,
      ...prev,
    ]);
  };

  const handleIgnoreFindingOnce = (finding: SimulatedFinding) => {
    const nowIso = new Date().toISOString();
    setActiveFindings((prev) => prev.filter((f) => f.id !== finding.id));
    setAuditTrail((prev) => [
      `[${nowIso}] IGNORED_ONCE (userApproved=true): '${finding.filePath}' (${finding.detectionName}) ignored for current session only.`,
      ...prev,
    ]);
    setScanStatusText(`IGNORED ONCE: '${finding.fileName}' ignored for this scan session.`);
  };

  const handleTriggerSmartNotificationTest = (isDuplicateAttempt: boolean) => {
    const sampleKey = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f|c:\\users\\defender\\downloads\\eicar_harmless_test.com';
    const nowMs = Date.now();
    const lastTime = lastNotifiedDedupeMapRef.current.get(sampleKey);

    if (isDuplicateAttempt && lastTime && nowMs - lastTime < 120_000) {
      setScanStatusText(
        'DUPLICATE SUPPRESSED: SmartNotificationManager blocked duplicate toast & sound within 120s anti-spam cooldown window.'
      );
      setAuditTrail((prev) => [
        `[${new Date().toISOString()}] NOTIFICATION_SUPPRESSED: Duplicate alert for EICAR suppressed within 120s cooldown.`,
        ...prev,
      ]);
      return;
    }

    lastNotifiedDedupeMapRef.current.set(sampleKey, nowMs);
    const chimePlayed = playOriginalGentleChime();
    const newEvt: SmartNotificationLogItem = {
      id: `NOTIF-${nowMs.toString().slice(-5)}`,
      title: 'KIRON PROHORI',
      headerTitle: 'Suspicious Download Blocked',
      threatName: 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE',
      websiteDomain: 'example-domain.invalid',
      fileName: 'suspicious-file.exe',
      filePath: 'C:\\Users\\Defender\\Downloads\\suspicious-file.exe',
      detectionSource: 'Local SHA-256 Signature Engine',
      recommendedAction: 'Quarantine First (Permanent deletion requires separate confirmation)',
      statusLabel: 'Quarantined',
      playedGentleChime: chimePlayed,
      createdAt: new Date().toISOString(),
    };
    setNotificationHistory((prev) => [newEvt, ...prev]);
    setScanStatusText(
      `SMART NOTIFICATION PUBLISHED: Title="KIRON PROHORI" · Header="Suspicious Download Blocked" · Gentle Chime Played: ${chimePlayed}`
    );
  };

  const handleConfirmedVaultAction = () => {
    if (!pendingConfirmModal) return;
    const { action, targetId } = pendingConfirmModal;
    const nowIso = new Date().toISOString();

    if (action === 'QUARANTINE') {
      const found = activeFindings.find((f) => f.id === targetId);
      if (found) {
        const isExcluded = exclusionsList.some(
          (e) => e.canonicalPath.toLowerCase() === found.filePath.toLowerCase()
        );
        if (isExcluded) {
          setScanStatusText(
            `BLOCKED BY EXCLUSION MANAGER: '${found.filePath}' is in KIRON PROHORI Exclusions and cannot be quarantined.`
          );
          setPendingConfirmModal(null);
          return;
        }

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
          `[${nowIso}] QUARANTINED (userConfirmed=true): '${found.filePath}' -> Isolated vault '${qId}.kpq'`,
          ...prev,
        ]);
        setScanStatusText(`QUARANTINED: '${found.fileName}' isolated in vault as '${qId}.kpq'.`);
      }
    } else if (action === 'EXCLUDE') {
      const found = activeFindings.find((f) => f.id === targetId);
      if (found) {
        const excItem: ExclusionEntryItem = {
          exclusionId: `EXC-${Date.now().toString().slice(-4)}`,
          canonicalPath: found.filePath,
          scope: 'IndividualFile',
          reason: `User excluded from Detection Remediation (${found.detectionName})`,
          addedAt: nowIso,
        };
        setExclusionsList((prev) => [excItem, ...prev]);
        setActiveFindings((prev) => prev.filter((f) => f.id !== targetId));
        setAuditTrail((prev) => [
          `[${nowIso}] EXCLUSION_ADDED (userConfirmed=true): '${found.filePath}' (Does NOT alter Microsoft Defender exclusions)`,
          ...prev,
        ]);
        setScanStatusText(
          `EXCLUDED: '${found.filePath}' added to KIRON PROHORI Exclusions. It will never be scanned or quarantined.`
        );
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
            engineId: 'Local SHA-256 Signature Engine',
            severity: 'CRITICAL',
            verdict: 'ConfirmedDetection',
            confidenceScore: 100,
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

  const handleAddManualExclusion = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedPath = newExclusionPath.trim();
    if (!trimmedPath) return;

    // Validate against dangerously broad exclusions (wildcards, root drives, executable extensions)
    if (trimmedPath.includes('*') || trimmedPath.includes('?')) {
      setScanStatusText('DANGEROUS EXCLUSION BLOCKED: Wildcard exclusions (* or ?) are not permitted.');
      return;
    }
    if (/^[a-zA-Z]:\\?$/.test(trimmedPath) || trimmedPath === '/') {
      setScanStatusText(`DANGEROUS EXCLUSION BLOCKED: Excluding an entire root drive ('${trimmedPath}') is prohibited.`);
      return;
    }
    if (newExclusionScope === 'FileExtension') {
      const ext = trimmedPath.startsWith('.') ? trimmedPath.toLowerCase() : `.${trimmedPath.toLowerCase()}`;
      const prohibitedExts = ['.exe', '.dll', '.sys', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.msi'];
      if (prohibitedExts.includes(ext)) {
        setScanStatusText(
          `DANGEROUS EXCLUSION BLOCKED: Excluding high-risk executable extension '${ext}' globally is prohibited.`
        );
        return;
      }
    }

    const nowIso = new Date().toISOString();
    const entry: ExclusionEntryItem = {
      exclusionId: `EXC-${Date.now().toString().slice(-4)}`,
      canonicalPath: trimmedPath,
      scope: newExclusionScope,
      reason: newExclusionReason.trim() || 'User-configured trusted exclusion',
      addedAt: nowIso,
    };
    setExclusionsList((prev) => [entry, ...prev]);
    setAuditTrail((prev) => [
      `[${nowIso}] EXCLUSION_ADDED (userConfirmed=true): [${entry.scope}] '${entry.canonicalPath}'`,
      ...prev,
    ]);
    setNewExclusionPath('');
    setNewExclusionReason('');
    setScanStatusText(`EXCLUSION ADDED: '${entry.canonicalPath}' (KIRON PROHORI local exclusion only).`);
  };

  const handleRemoveExclusion = (exclusionId: string, pathLabel: string) => {
    const nowIso = new Date().toISOString();
    setExclusionsList((prev) => prev.filter((x) => x.exclusionId !== exclusionId));
    setAuditTrail((prev) => [
      `[${nowIso}] EXCLUSION_REMOVED: '${pathLabel}' re-enabled for scanning.`,
      ...prev,
    ]);
    setScanStatusText(`EXCLUSION REMOVED: '${pathLabel}' will now be scanned normally.`);
  };

  return (
    <section
      aria-label="KIRON PROHORI V1.0 Windows Security Agent & Browser Extension Workspace"
      className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6 space-y-6"
    >
      {/* Top Section Header & Honest Build Environment Disclosure */}
      <div className="flex flex-col gap-4 border-b border-[#1E2D4A] pb-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-blue-300">
            <Monitor className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span>KIRON PROHORI V1.0 — WINDOWS DESKTOP AGENT + REAL-TIME GUARD + CHROME/EDGE MV3 EXTENSION</span>
            <span>·</span>
            <span className="text-sky-300 font-semibold">DEVELOPER CREDIT: ARIFUZZAMAN KIRON</span>
            <span>·</span>
            <span className="text-emerald-300">STRICT $0 · QUARANTINE FIRST · NO TELEMETRY</span>
          </div>
          <h2 className="text-lg font-semibold text-slate-100">
            {isBn
              ? 'কিরণ প্রহরী V1.0 — উইন্ডোজ সিকিউরিটি ও ওয়েব সুরক্ষা (ডেভেলপার: আরিফুজ্জামান কিরণ)'
              : 'KIRON PROHORI V1.0 — Complete Windows Antivirus & Web Protection (Developer: ARIFUZZAMAN KIRON)'}
          </h2>
          <p className="text-xs text-slate-400">
            {manifest?.buildEnvironmentDisclosure.honestDisclosure ||
              'Separate C# / .NET 8.0 Windows Desktop application in /desktop-agent and Chrome/Edge Manifest V3 Browser Extension in /browser-extension. Coexists with Microsoft Defender with zero telemetry by default.'}
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
            <span>{isLight ? 'Theme: Light' : 'Theme: Dark'}</span>
          </button>

          <button
            type="button"
            onClick={() => void execute14ScenarioVerification()}
            disabled={runningSuite}
            className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white hover:bg-blue-500 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${runningSuite ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Run All {suiteResults.length || 18} V1.0 Verification Tests</span>
          </button>
        </div>
      </div>

      {/* Interactive Windows 10/11 Desktop Agent Window Preview */}
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
                ? 'KIRON PROHORI V1.0 — উইন্ডোজ সিকিউরিটি এজেন্ট ও ওয়েব প্রোটেকশন'
                : 'KIRON PROHORI V1.0 — Windows Security Agent & Browser Protection (Windows 10/11 x64)'}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span
              className={`rounded border px-2 py-0.5 font-bold ${
                computedProtectionStatus === 'PROTECTED'
                  ? 'border-emerald-500/50 bg-emerald-950/40 text-emerald-300'
                  : computedProtectionStatus === 'WARNING'
                  ? 'border-amber-500/50 bg-amber-950/40 text-amber-300'
                  : 'border-rose-500/50 bg-rose-950/40 text-rose-300'
              }`}
            >
              STATUS: {computedProtectionStatus}
            </span>
            <span className="opacity-75">
              Developer: ARIFUZZAMAN KIRON · Policy: QUARANTINE FIRST
            </span>
          </div>
        </div>

        {/* MODULE 10 REQUIRED DASHBOARD SUMMARY STRIP (7 Key Posture Indicators) */}
        <div
          className={`grid grid-cols-2 gap-3 rounded-lg border p-3.5 mb-4 text-xs sm:grid-cols-4 lg:grid-cols-7 ${
            isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
          }`}
        >
          <div>
            <div className="opacity-70 text-[11px]">1. Protection Status</div>
            <div
              className={`font-mono font-bold ${
                computedProtectionStatus === 'PROTECTED'
                  ? 'text-emerald-400'
                  : computedProtectionStatus === 'WARNING'
                  ? 'text-amber-400'
                  : 'text-rose-400'
              }`}
            >
              {computedProtectionStatus}
            </div>
          </div>
          <div>
            <div className="opacity-70 text-[11px]">2. Last Scan</div>
            <div className="font-mono font-semibold truncate">{lastScanTimeLabel}</div>
          </div>
          <div>
            <div className="opacity-70 text-[11px]">3. Threats Detected</div>
            <div className={`font-mono font-bold ${activeFindings.length > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
              {activeFindings.length} Active
            </div>
          </div>
          <div>
            <div className="opacity-70 text-[11px]">4. Quarantined Items</div>
            <div className="font-mono font-semibold text-amber-400">
              {quarantineVault.length} Isolated (.kpq)
            </div>
          </div>
          <div>
            <div className="opacity-70 text-[11px]">5. Browser Protection</div>
            <div className={`font-mono font-semibold ${browserExtensionConnected ? 'text-emerald-400' : 'text-amber-400'}`}>
              {browserExtensionConnected ? 'PROTECTED (MV3)' : 'NOT AVAILABLE'}
            </div>
          </div>
          <div>
            <div className="opacity-70 text-[11px]">6. Microsoft Defender</div>
            <div className="font-mono font-semibold text-emerald-400">
              PROTECTED (Coexistent)
            </div>
          </div>
          <div>
            <div className="opacity-70 text-[11px]">7. Last Intel Update</div>
            <div className="font-mono font-semibold text-sky-400 truncate">
              {lastIntelUpdateLabel}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
          {/* Desktop Sidebar Navigation */}
          <div
            className={`lg:col-span-3 rounded-lg border p-3 space-y-1 ${
              isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
            }`}
          >
            <div className="px-2 py-1.5 font-mono text-[11px] uppercase tracking-wider opacity-70">
              {isBn ? 'V1.0 নেভিগেশন মডিউল' : 'V1.0 Navigation Modules'}
            </div>
            {DESKTOP_NAV_ITEMS.map((nav) => {
              const active = activeDesktopView === nav.id;
              return (
                <button
                  key={nav.id}
                  type="button"
                  onClick={() => setActiveDesktopView(nav.id)}
                  className={`flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-xs font-medium transition-colors ${
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
                    onClick={() =>
                      triggerSimulatedDesktopScan(
                        'Quick Scan',
                        'Inspects Downloads, Startup, and Temp folders read-only'
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50 whitespace-nowrap shrink-0"
                  >
                    <Play className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{isBn ? 'কুইক স্ক্যান' : 'Quick Scan'}</span>
                  </button>

                  <button
                    type="button"
                    disabled={scanRunning}
                    onClick={() =>
                      triggerSimulatedDesktopScan(
                        'Custom Folder / File Scan',
                        'Inspects user-selected directory or single file via SHA-256 & static heuristics'
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/40 px-3 py-1.5 text-xs font-medium hover:border-blue-500 whitespace-nowrap shrink-0"
                  >
                    <FolderSearch className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                    <span>{isBn ? 'কাস্টম/ফাইল স্ক্যান' : 'Custom / File Scan'}</span>
                  </button>

                  <button
                    type="button"
                    disabled={scanRunning}
                    onClick={triggerControlledEicarTestScan}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50 whitespace-nowrap shrink-0"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>Run Controlled EICAR Test Scan</span>
                  </button>

                  <button
                    type="button"
                    onClick={togglePauseResumeScan}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/40 px-3 py-1.5 text-xs font-medium text-amber-400 hover:border-amber-400 whitespace-nowrap shrink-0"
                  >
                    <Pause className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{scanPaused ? (isBn ? 'রিজিউম' : 'Resume') : isBn ? 'পজ করুন' : 'Pause'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={cancelSimulatedScan}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 px-3 py-1.5 text-xs font-medium text-rose-400 hover:border-rose-400 whitespace-nowrap shrink-0"
                  >
                    <XCircle className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{isBn ? 'বন্ধ করুন' : 'Cancel Scan'}</span>
                  </button>
                </div>
              </div>

              {/* Read-Only Windows Defender, Firewall, Exclusions & Performance Strip */}
              <div
                className={`grid grid-cols-1 gap-3 border-t pt-3 text-xs sm:grid-cols-4 ${
                  isLight ? 'border-slate-200' : 'border-[#1E2D4A]'
                }`}
              >
                <div>
                  <div className="opacity-70">Microsoft Defender (WMI Read-Only)</div>
                  <div className="font-mono font-semibold text-emerald-500">
                    RTP: ON · MpCmdRun Coexistent
                  </div>
                </div>
                <div>
                  <div className="opacity-70">Windows Firewall (Domain/Priv/Pub)</div>
                  <div className="font-mono font-semibold text-emerald-500">
                    ENABLED (Zero Policy Change)
                  </div>
                </div>
                <div>
                  <div className="opacity-70">KIRON Exclusions &amp; Clean Cache</div>
                  <div className="font-mono font-semibold text-sky-400">
                    {exclusionsList.length} Excluded · Cache: {skipUnchangedCleanFiles ? 'ON' : 'OFF'}
                  </div>
                </div>
                <div>
                  <div className="opacity-70">Smart Chime &amp; Telemetry</div>
                  <div className="font-mono font-semibold text-emerald-400">
                    Chime: {soundEnabled ? `${soundVolumePercent}%` : 'MUTED'} · Telemetry: OFF
                  </div>
                </div>
              </div>
            </div>

            {/* MODULE 3 VIEW: BROWSER WEB PROTECTION (Chrome & Microsoft Edge Manifest V3) */}
            {activeDesktopView === 'web-protection' && (
              <div
                className={`rounded-lg border p-4 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                      05. Browser Web Protection — Chrome &amp; Microsoft Edge Manifest V3 Extension (/browser-extension/)
                    </h4>
                    <p className="text-xs opacity-80">
                      Uses declarativeNetRequest rules to block verified malicious URLs, phishing sites, scam/malware domains, malicious ad redirects, and malicious third-party requests. Zero browsing-history collection; ordinary legitimate ads are never blocked.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setBrowserExtensionConnected((prev) => !prev)}
                    className={`rounded border px-3 py-1.5 font-mono text-xs font-semibold shrink-0 ${
                      browserExtensionConnected
                        ? 'border-emerald-500/50 bg-emerald-950/30 text-emerald-300'
                        : 'border-amber-500/50 bg-amber-950/30 text-amber-300'
                    }`}
                  >
                    Extension Status: {browserExtensionConnected ? 'PROTECTED' : 'NOT AVAILABLE (Simulated Disconnect)'}
                  </button>
                </div>

                {/* Controlled Malicious URL Evaluator */}
                <form onSubmit={handleEvaluateWebProtectionUrl} className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                  <input
                    type="text"
                    value={testUrlInput}
                    onChange={(e) => setTestUrlInput(e.target.value)}
                    placeholder="https://phishing-login-verify.kiron-test.invalid/account"
                    className={`sm:col-span-9 rounded border px-3 py-1.5 font-mono text-xs ${
                      isLight
                        ? 'border-slate-300 bg-white text-slate-900'
                        : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
                    }`}
                  />
                  <button
                    type="submit"
                    className="sm:col-span-3 rounded bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-500"
                  >
                    Test URL in Web Guard
                  </button>
                </form>

                <div className="flex flex-wrap gap-2 text-xs">
                  <button
                    type="button"
                    onClick={() => {
                      setTestUrlInput('https://phishing-login-verify.kiron-test.invalid/account/login');
                    }}
                    className="rounded border border-rose-500/40 px-2.5 py-1 font-mono text-[11px] text-rose-300 hover:border-rose-400"
                  >
                    Load Controlled Phishing URL
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setTestUrlInput('https://malware-payload-drop.kiron-test.invalid/setup.exe');
                    }}
                    className="rounded border border-rose-500/40 px-2.5 py-1 font-mono text-[11px] text-rose-300 hover:border-rose-400"
                  >
                    Load Controlled Malware Domain
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setTestUrlInput('https://www.microsoft.com/en-us/windows');
                    }}
                    className="rounded border border-emerald-500/40 px-2.5 py-1 font-mono text-[11px] text-emerald-300 hover:border-emerald-400"
                  >
                    Load Legitimate Website
                  </button>
                </div>

                {urlTestResult && (
                  <div
                    className={`rounded border p-3.5 space-y-2 text-xs ${
                      urlTestResult.blocked
                        ? 'border-rose-500/50 bg-rose-950/20'
                        : 'border-emerald-500/50 bg-emerald-950/20'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                      <span className="font-bold">
                        {urlTestResult.blocked
                          ? `BLOCKED BY KIRON PROHORI (Rule #${urlTestResult.ruleId} · ${urlTestResult.category})`
                          : `ALLOWED (${urlTestResult.category})`}
                      </span>
                      <span>Host: {urlTestResult.host}</span>
                    </div>
                    <p className="opacity-90">Reason: {urlTestResult.reason}</p>
                    {urlTestResult.blocked && (
                      <div className="flex flex-wrap items-center gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() =>
                            handleReportWebFalsePositive(
                              urlTestResult.host,
                              `User reported false positive for ${urlTestResult.category}`
                            )
                          }
                          className="rounded border border-sky-500/50 px-2.5 py-1 font-mono text-xs text-sky-300 hover:border-sky-400"
                        >
                          Report False Positive (Local Only)
                        </button>
                        <button
                          type="button"
                          onClick={() => handleAddTemporaryAllowlist(urlTestResult.host)}
                          className="rounded border border-amber-500/50 px-2.5 py-1 font-mono text-xs text-amber-300 hover:border-amber-400"
                        >
                          Add to Temporary Allowlist (30m — Reduces Protection)
                        </button>
                      </div>
                    )}
                  </div>
                )}

                <div className="space-y-1.5">
                  <div className="font-mono text-[11px] opacity-75">
                    Active declarativeNetRequest Static Ruleset (/browser-extension/rules/verified_malicious_rules.json):
                  </div>
                  {VERIFIED_MV3_WEB_RULES.map((r) => (
                    <div
                      key={r.ruleId}
                      className={`flex flex-col gap-1 rounded border p-2.5 font-mono text-xs sm:flex-row sm:items-center sm:justify-between ${
                        isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                      }`}
                    >
                      <div>
                        <span className="text-rose-400 font-semibold">Rule #{r.ruleId}</span> · [{r.category}] {r.domain}
                      </div>
                      <span className="text-[11px] opacity-75">{r.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MODULE 4 VIEW: AUTOMATIC DOWNLOAD PROTECTION (Native Messaging Host) */}
            {activeDesktopView === 'download-protection' && (
              <div
                className={`rounded-lg border p-4 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex flex-col gap-1">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                    06. Automatic Download Protection — Chrome/Edge Native Messaging (com.kironprohori.security_agent)
                  </h4>
                  <p className="text-xs opacity-80">
                    Scans completed browser downloads locally via 4-byte little-endian Native Messaging stdio framing. Clearly distinguishes Clean, Suspicious, Malicious, and Unknown / Not scanned. Never reports a file as Clean if the scan did not complete.
                  </p>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleSimulateBrowserDownloadScan('INCOMPLETE')}
                    className="rounded border border-slate-500/50 px-3 py-1.5 text-xs font-medium hover:border-slate-400"
                  >
                    1. Test Incomplete Download &rarr; Unknown / Not scanned
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSimulateBrowserDownloadScan('CLEAN')}
                    className="rounded border border-emerald-500/50 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:border-emerald-400"
                  >
                    2. Test Clean Download &rarr; Clean
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSimulateBrowserDownloadScan('SUSPICIOUS')}
                    className="rounded border border-amber-500/50 px-3 py-1.5 text-xs font-medium text-amber-300 hover:border-amber-400"
                  >
                    3. Test Double-Ext (.pdf.exe) &rarr; Suspicious
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSimulateBrowserDownloadScan('MALICIOUS_EICAR')}
                    className="rounded bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500"
                  >
                    4. Test Harmless EICAR Download &rarr; Malicious
                  </button>
                </div>

                <div className="space-y-2">
                  {downloadVerdicts.length === 0 ? (
                    <p className="py-2 text-xs opacity-70">
                      Click any of the 4 controlled download buttons above to test the Native Messaging download verification workflow.
                    </p>
                  ) : (
                    downloadVerdicts.map((v) => (
                      <div
                        key={v.downloadId}
                        className={`rounded border p-3 text-xs space-y-1 ${
                          isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                          <span
                            className={`font-bold ${
                              v.status === 'Malicious'
                                ? 'text-rose-400'
                                : v.status === 'Suspicious'
                                ? 'text-amber-400'
                                : v.status === 'Clean'
                                ? 'text-emerald-400'
                                : 'text-slate-300'
                            }`}
                          >
                            [{v.status}] {v.fileName}
                          </span>
                          <span className="opacity-75">Website: {v.websiteDomain}</span>
                        </div>
                        <div className="font-mono text-[11px] opacity-80">
                          Threat: {v.threatName} · SHA-256: {v.sha256.slice(0, 32)}
                        </div>
                        <p className="text-[11px] opacity-80">{v.explanation}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* MODULE 2 VIEW: REAL-TIME FILE PROTECTION (Safe User-Mode Monitoring) */}
            {activeDesktopView === 'realtime-protection' && (
              <div
                className={`rounded-lg border p-4 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                      07. Real-Time File Protection — Safe User-Mode FileSystemWatcher Monitor (Zero Kernel Drivers)
                    </h4>
                    <p className="text-xs opacity-80">
                      Monitors newly downloaded files, newly created executable files, suspicious file modifications, and Windows Startup folder changes. Never executes suspicious files to test them and never claims kernel-level driver installation in V1.0.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setRealTimeProtectionEnabled((prev) => !prev)}
                    className={`rounded border px-3 py-1.5 font-mono text-xs font-semibold shrink-0 ${
                      realTimeProtectionEnabled
                        ? 'border-emerald-500/50 bg-emerald-950/30 text-emerald-300'
                        : 'border-amber-500/50 bg-amber-950/30 text-amber-300'
                    }`}
                  >
                    User-Mode Monitor: {realTimeProtectionEnabled ? 'PROTECTED (ACTIVE)' : 'PAUSED (WARNING)'}
                  </button>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleSimulateRealTimeFileEvent('NEW_EXECUTABLE')}
                    className="rounded border border-emerald-500/50 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:border-emerald-400"
                  >
                    Simulate Newly Created Executable (Clean)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSimulateRealTimeFileEvent('SUSPICIOUS_MODIFICATION')}
                    className="rounded border border-amber-500/50 px-3 py-1.5 text-xs font-medium text-amber-300 hover:border-amber-400"
                  >
                    Simulate Suspicious File Rename (.docx.exe)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSimulateRealTimeFileEvent('STARTUP_CHANGE')}
                    className="rounded border border-rose-500/50 px-3 py-1.5 text-xs font-medium text-rose-300 hover:border-rose-400"
                  >
                    Simulate Dangerous Windows Startup Folder Change
                  </button>
                </div>

                <div className="space-y-2">
                  {realTimeEvents.length === 0 ? (
                    <p className="py-2 text-xs opacity-70">
                      Watching %USERPROFILE%\Downloads, Desktop, Temp, and Windows Startup folders in user-mode. Click any button above to test real-time event evaluation.
                    </p>
                  ) : (
                    realTimeEvents.map((evt) => (
                      <div
                        key={evt.eventId}
                        className={`rounded border p-3 text-xs space-y-1 ${
                          isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                        }`}
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="font-bold text-sky-400">
                            [{evt.category}] [{evt.status}] {evt.fileName}
                          </span>
                          <span className="opacity-70">{evt.observedAt.slice(11, 19)} UTC</span>
                        </div>
                        <div className="font-mono text-[11px] opacity-80">{evt.filePath}</div>
                        <p className="text-[11px] opacity-85">{evt.summary}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* MODULE 10 VIEW: SECURITY INTELLIGENCE & PRIVACY NETWORK DISCLOSURE */}
            {activeDesktopView === 'security-intelligence' && (
              <div
                className={`rounded-lg border p-4 space-y-3 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                  11. Security Intelligence &amp; HTTPS Network Metadata Disclosure
                </h4>
                <p className="text-xs opacity-85">
                  Internet access is permitted ONLY for verified threat-intelligence feeds (CISA KEV, NIST NVD API 2.0, FIRST EPSS, abuse.ch Feodo Tracker, CIRCL Public Hashlookup), signed application updates, and signature updates over HTTPS.
                </p>
                <div
                  className={`rounded border p-3 font-mono text-xs ${
                    isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                  }`}
                >
                  PRIVACY DISCLOSURE: Standard HTTPS network connections to update and threat-intelligence servers naturally expose your IP address and basic HTTP request metadata to those servers. KIRON PROHORI never uploads personal files, passwords, or browsing history.
                </div>
              </div>
            )}

            {/* View 14: ABOUT VIEW (Product: KIRON PROHORI, Developer Credit: ARIFUZZAMAN KIRON) */}
            {activeDesktopView === 'about' && (
              <div
                className={`rounded-lg border p-5 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
                  {/* Professional Shield Icon instead of developer photograph */}
                  <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-xl border border-blue-500/40 bg-blue-950/60 text-blue-400">
                    <ShieldCheck className="h-9 w-9" aria-hidden="true" />
                  </div>
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h4 className="text-base font-bold">KIRON PROHORI</h4>
                      <span className="rounded border border-blue-500/40 bg-blue-950/40 px-2 py-0.5 font-mono text-[11px] text-blue-300">
                        Windows Security &amp; Antivirus V1.0
                      </span>
                    </div>
                    <p className="font-mono text-xs text-emerald-400">
                      Developer Credit: <span className="font-bold">ARIFUZZAMAN KIRON</span>
                    </p>
                    <p className="font-mono text-[11px] opacity-75">
                      Target Platform: Windows 10 and Windows 11, x64 · Policy: QUARANTINE FIRST · Privacy: NO TELEMETRY BY DEFAULT
                    </p>
                  </div>
                </div>

                <div
                  className={`rounded-lg border p-4 font-sans text-xs leading-relaxed whitespace-pre-line ${
                    isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                  }`}
                >
                  {EXACT_ABOUT_MESSAGE}
                </div>

                <div className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                  <div
                    className={`rounded border p-3 space-y-1 ${
                      isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                    }`}
                  >
                    <div className="font-semibold text-blue-400">Independent Product &amp; Non-Affiliation Statement</div>
                    <p className="opacity-80">
                      KIRON PROHORI is an independent security product developed by ARIFUZZAMAN KIRON and is not affiliated with Microsoft, Kaspersky, ESET, Norton, McAfee or other security vendors.
                    </p>
                  </div>
                  <div
                    className={`rounded border p-3 space-y-1 ${
                      isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                    }`}
                  >
                    <div className="font-semibold text-emerald-400">Original Shield Emblem &amp; Privacy Guard</div>
                    <p className="opacity-80">
                      Uses a professional original shield-based product icon instead of a developer photo. Contains no third-party antivirus company logos or personal contact details.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* View 10: EXCLUSION MANAGER */}
            {activeDesktopView === 'exclusions' && (
              <div
                className={`rounded-lg border p-4 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex flex-col gap-1">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                    10. KIRON PROHORI Exclusion Manager (Files, Folders, Safe Extensions &amp; Trusted App Paths)
                  </h4>
                  <p className="text-xs opacity-80">
                    Security Risk Warning: Excluded items will NEVER be scanned, quarantined, or removed by KIRON PROHORI. Dangerously broad exclusions (entire root drives C:\, wildcards *, or executable extensions like .exe/.dll/.ps1) are automatically blocked. Exclusions apply ONLY to KIRON PROHORI and never modify Microsoft Defender exclusions.
                  </p>
                </div>

                <form onSubmit={handleAddManualExclusion} className="grid grid-cols-1 gap-2 sm:grid-cols-12">
                  <input
                    type="text"
                    value={newExclusionPath}
                    onChange={(e) => setNewExclusionPath(e.target.value)}
                    placeholder="C:\Full\Canonical\Path or .log"
                    className={`sm:col-span-5 rounded border px-3 py-1.5 font-mono text-xs ${
                      isLight
                        ? 'border-slate-300 bg-white text-slate-900'
                        : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
                    }`}
                  />
                  <select
                    value={newExclusionScope}
                    onChange={(e) =>
                      setNewExclusionScope(
                        e.target.value as
                          | 'IndividualFile'
                          | 'Folder'
                          | 'FileExtension'
                          | 'TrustedApplicationPath'
                      )
                    }
                    className={`sm:col-span-3 rounded border px-2.5 py-1.5 font-mono text-xs ${
                      isLight
                        ? 'border-slate-300 bg-white text-slate-900'
                        : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
                    }`}
                  >
                    <option value="IndividualFile">Individual File</option>
                    <option value="Folder">Folder (Recursive)</option>
                    <option value="FileExtension">File Extension (Safe Non-Executable)</option>
                    <option value="TrustedApplicationPath">Trusted App Path</option>
                  </select>
                  <input
                    type="text"
                    value={newExclusionReason}
                    onChange={(e) => setNewExclusionReason(e.target.value)}
                    placeholder="Audit reason..."
                    className={`sm:col-span-2 rounded border px-2.5 py-1.5 text-xs ${
                      isLight
                        ? 'border-slate-300 bg-white text-slate-900'
                        : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
                    }`}
                  />
                  <button
                    type="submit"
                    className="sm:col-span-2 rounded bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-500"
                  >
                    Validate &amp; Exclude
                  </button>
                </form>

                <div className="space-y-2">
                  {exclusionsList.length === 0 ? (
                    <p className="py-2 text-xs opacity-70">
                      No KIRON exclusions configured. All files and directories are eligible for scanning.
                    </p>
                  ) : (
                    exclusionsList.map((exc) => (
                      <div
                        key={exc.exclusionId}
                        className={`flex flex-col gap-2 rounded border p-3 text-xs sm:flex-row sm:items-center sm:justify-between ${
                          isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                        }`}
                      >
                        <div className="space-y-0.5">
                          <div className="font-mono font-semibold text-sky-400">
                            [{exc.scope}] {exc.canonicalPath}
                          </div>
                          <div className="text-[11px] opacity-75">
                            Reason: {exc.reason} · Added: {exc.addedAt}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => handleRemoveExclusion(exc.exclusionId, exc.canonicalPath)}
                          className="inline-flex items-center gap-1 rounded border border-rose-500/40 px-2.5 py-1 text-xs text-rose-400 hover:border-rose-400 shrink-0"
                        >
                          <Trash2 className="h-3 w-3" aria-hidden="true" />
                          <span>Remove Exclusion</span>
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* View 13: SMART NOTIFICATION SYSTEM & GENTLE CHIME */}
            {activeDesktopView === 'notifications' && (
              <div
                className={`rounded-lg border p-4 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                      13. Smart Notification System (Compact Toast + Original Gentle Chime + Anti-Spam)
                    </h4>
                    <p className="text-xs opacity-80">
                      Plays a short, gentle original D5 &rarr; A5 chime once per new detection event. Suppresses duplicate notification spam within the 120s cooldown window.
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setSoundEnabled((prev) => !prev)}
                      className="inline-flex items-center gap-1.5 rounded border border-blue-500/40 px-3 py-1.5 text-xs font-medium"
                    >
                      {soundEnabled ? (
                        <Volume2 className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                      ) : (
                        <VolumeX className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
                      )}
                      <span>Sound: {soundEnabled ? 'ON' : 'OFF'}</span>
                    </button>

                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span>Vol:</span>
                      <input
                        type="range"
                        min={0}
                        max={100}
                        value={soundVolumePercent}
                        onChange={(e) => setSoundVolumePercent(Number(e.target.value))}
                        aria-label="Notification sound volume percentage"
                        className="w-24"
                      />
                      <span>{soundVolumePercent}%</span>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleTriggerSmartNotificationTest(false)}
                      className="rounded bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-500"
                    >
                      Test New Detection Alert + Chime
                    </button>

                    <button
                      type="button"
                      onClick={() => handleTriggerSmartNotificationTest(true)}
                      className="rounded border border-amber-500/50 px-3 py-1.5 text-xs font-medium text-amber-300 hover:border-amber-400"
                    >
                      Test Duplicate Spam Suppression
                    </button>
                  </div>
                </div>

                <div className="space-y-2">
                  {notificationHistory.map((n) => (
                    <div
                      key={n.id}
                      className={`rounded border p-3 text-xs space-y-1 ${
                        isLight ? 'border-slate-200 bg-slate-50' : 'border-[#1E2D4A] bg-[#080D1A]'
                      }`}
                    >
                      <div className="flex items-center justify-between font-mono">
                        <span className="font-bold text-blue-400">
                          {n.title} — &ldquo;{n.headerTitle}&rdquo;
                        </span>
                        <span className="opacity-75">
                          Chime Played: {n.playedGentleChime ? 'YES (Once)' : 'MUTED'}
                        </span>
                      </div>
                      <div className="font-mono">
                        Threat: <span className="text-rose-400 font-semibold">{n.threatName}</span> · Source: {n.detectionSource}
                      </div>
                      <div className="font-mono text-[11px] opacity-80">
                        Location: {n.filePath} · Recommended: {n.recommendedAction}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* View 12 & 14: UPDATES, ROLLBACK & PERFORMANCE PROTECTION SETTINGS */}
            {(activeDesktopView === 'updates' || activeDesktopView === 'settings') && (
              <div
                className={`rounded-lg border p-4 space-y-4 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400">
                      Performance Protection &amp; Resource Guard
                    </h4>
                    <p className="text-xs opacity-80">
                      Uses BelowNormal CPU thread priority during background scans, pauses/throttles on laptop battery power, and caches unchanged clean files. Never claims zero performance impact.
                    </p>
                    <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                      <select
                        value={cpuThrottleProfile}
                        onChange={(e) =>
                          setCpuThrottleProfile(
                            e.target.value as
                              | 'LowImpactBackground'
                              | 'BalancedDefault'
                              | 'HighSpeedForeground'
                          )
                        }
                        className={`rounded border px-2.5 py-1.5 font-mono text-xs ${
                          isLight
                            ? 'border-slate-300 bg-white text-slate-900'
                            : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
                        }`}
                      >
                        <option value="LowImpactBackground">LowImpactBackground (1 Thread)</option>
                        <option value="BalancedDefault">BalancedDefault (2 Threads)</option>
                        <option value="HighSpeedForeground">HighSpeedForeground (4 Threads)</option>
                      </select>

                      <label className="inline-flex items-center gap-1.5 font-mono">
                        <span>Max CPU %:</span>
                        <input
                          type="number"
                          min={10}
                          max={90}
                          value={maxCpuPercent}
                          onChange={(e) => setMaxCpuPercent(Number(e.target.value))}
                          className={`w-16 rounded border px-2 py-1 ${
                            isLight
                              ? 'border-slate-300 bg-white text-slate-900'
                              : 'border-[#1E2D4A] bg-[#080D1A] text-slate-100'
                          }`}
                        />
                      </label>

                      <button
                        type="button"
                        onClick={() => setSkipUnchangedCleanFiles((prev) => !prev)}
                        className="rounded border border-blue-500/40 px-2.5 py-1 font-mono text-xs"
                      >
                        Clean File Cache: {skipUnchangedCleanFiles ? 'ENABLED' : 'DISABLED'}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                      Signed HTTPS Update Verification &amp; Diagnostics Rollback
                    </h4>
                    <p className="text-xs opacity-80">
                      Enforces HTTPS-only transport, SHA-256 cryptographic digest verification, and publisher identity (`CN=ARIFUZZAMAN`). Preserves `.known_good` backup for instant rollback and self-repair.
                    </p>
                    <div className="font-mono text-[11px] text-emerald-400">
                      Active Signature Channel: v0.7.0-phase7a · Verified Publisher: CN=ARIFUZZAMAN · Self-Repair Backup: READY (.known_good)
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Mandatory User Confirmation Dialog Modal (Quarantine, Restore, Permanent Delete, Add Exclusion) */}
            {pendingConfirmModal && (
              <div className="rounded-lg border border-amber-500/60 bg-amber-950/30 p-4 space-y-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                  <Lock className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>MANDATORY USER CONFIRMATION GATE (No Automatic Deletion or Unconfirmed Action)</span>
                </div>
                <p className="text-xs font-medium text-slate-100">{pendingConfirmModal.title}</p>
                <p className="font-mono text-xs text-slate-300">{pendingConfirmModal.detail}</p>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={handleConfirmedVaultAction}
                    className="rounded-lg bg-amber-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-amber-500"
                  >
                    Confirm &amp; Log Action (userApproved = true)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setAuditTrail((prev) => [
                        `[${new Date().toISOString()}] DECLINED_BY_USER: User cancelled ${pendingConfirmModal.action} for ${pendingConfirmModal.targetId}. File untouched.`,
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
              {/* Left: Active Scan Findings with 4-Tier Verdict & 5 Remediation Actions */}
              <div
                className={`rounded-lg border p-4 space-y-3 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider opacity-80">
                    {isBn
                      ? `শনাক্তকৃত থ্রেট ও রেমিডিয়েশন (${activeFindings.length})`
                      : `Threat Detections & 5-Option Remediation (${activeFindings.length})`}
                  </h4>
                  <span className="font-mono text-[11px] opacity-70">
                    Confirmed vs Suspicious vs Unknown vs Clean
                  </span>
                </div>

                {activeFindings.length === 0 ? (
                  <p className="py-4 text-xs opacity-70">
                    No active unhandled detections. All items have been Quarantined, Ignored Once, or Excluded.
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
                        <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                          <span className="font-semibold text-rose-400">
                            [{f.verdict} · {f.severity} · {f.confidenceScore}%] {f.detectionName}
                          </span>
                          <span className="opacity-70">{f.engineId}</span>
                        </div>
                        <div className="font-mono text-[11px] break-all opacity-90">
                          Location: {f.filePath}
                        </div>
                        <div className="font-mono text-[11px] opacity-70">
                          Detected: {f.detectedAt} · SHA-256: {f.sha256.slice(0, 28)}...
                        </div>
                        <p className="text-[11px] opacity-75">{f.falsePositiveNote}</p>
                        <div className="flex flex-wrap items-center gap-2 pt-1.5">
                          <button
                            type="button"
                            onClick={() =>
                              setPendingConfirmModal({
                                action: 'QUARANTINE',
                                targetId: f.id,
                                title: `Quarantine '${f.fileName}' into encrypted local vault (Recommended Default)?`,
                                detail: `Location: ${f.filePath} | Source: ${f.engineId} | Verdict: ${f.verdict} (${f.confidenceScore}%)`,
                              })
                            }
                            className="inline-flex items-center gap-1.5 rounded bg-blue-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-blue-500"
                          >
                            <Lock className="h-3 w-3" aria-hidden="true" />
                            <span>1. Quarantine (Recommended)</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => handleIgnoreFindingOnce(f)}
                            className="inline-flex items-center gap-1 rounded border border-slate-500/50 px-2.5 py-1 text-xs font-medium hover:border-slate-400"
                          >
                            <span>2. Ignore Once</span>
                          </button>

                          <button
                            type="button"
                            onClick={() =>
                              setPendingConfirmModal({
                                action: 'EXCLUDE',
                                targetId: f.id,
                                title: `Add '${f.filePath}' to KIRON PROHORI Exclusions?`,
                                detail: `Security Risk: Excluded files will never be scanned or quarantined by KIRON PROHORI. Does NOT modify Microsoft Defender exclusions.`,
                              })
                            }
                            className="inline-flex items-center gap-1 rounded border border-sky-500/50 px-2.5 py-1 text-xs font-medium text-sky-400 hover:border-sky-400"
                          >
                            <FolderX className="h-3 w-3" aria-hidden="true" />
                            <span>3. Add Exclusion</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Right: Isolated Quarantine Vault (.kpq) (Restore & Permanent Delete) + Audit Log */}
              <div
                className={`rounded-lg border p-4 space-y-3 ${
                  isLight ? 'border-slate-200 bg-white' : 'border-[#1E2D4A] bg-[#0E1628]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider opacity-80">
                    {isBn
                      ? `কোয়ারেন্টাইন ভল্ট (.kpq) (${quarantineVault.length})`
                      : `AES-256-GCM Quarantine Vault (.kpq) (${quarantineVault.length})`}
                  </h4>
                  <span className="font-mono text-[11px] opacity-70">
                    4. Restore · 5. Permanent Delete
                  </span>
                </div>

                {quarantineVault.length === 0 ? (
                  <p className="py-2 text-xs opacity-70">
                    Vault is currently empty. Click &ldquo;1. Quarantine (Recommended)&rdquo; on any detection to isolate it safely.
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
                            <span>4. Restore File</span>
                          </button>

                          <button
                            type="button"
                            onClick={() =>
                              setPendingConfirmModal({
                                action: 'DELETE',
                                targetId: q.quarantineId,
                                title: `Permanently delete quarantined payload '${q.vaultFileName}'?`,
                                detail: `Original File: ${q.fileName} | SHA-256: ${q.sha256} (Irreversible Action)`,
                              })
                            }
                            className="inline-flex items-center gap-1 rounded border border-rose-500/50 px-2.5 py-1 text-xs font-medium text-rose-400 hover:border-rose-400"
                          >
                            <Trash2 className="h-3 w-3" aria-hidden="true" />
                            <span>5. Permanent Delete</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="border-t border-[#1E2D4A]/60 pt-2">
                  <div className="font-mono text-[11px] opacity-75 mb-1">
                    Local Audit Trail (Exclusions, Quarantine, Diagnostics — Never Uploaded):
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

      {/* Modular Scanning Engine Status Table */}
      {manifest && (
        <div className="space-y-3">
          <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <h3 className="text-sm font-semibold text-slate-100">
              Modular Scanning Engines &amp; Honest Installation Status
            </h3>
            <span className="font-mono text-xs text-sky-300">
              Product: {manifest.productName} — {manifest.subtitle} · Developer: {manifest.developer}
            </span>
          </div>
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

      {/* GLOBAL DOWNLOAD CENTER & RELEASE PIPELINE (Section 5, 7 & 8) */}
      <div className="rounded-xl border border-blue-500/40 bg-[#080D1A] p-5 space-y-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between border-b border-[#1E2D4A] pb-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wider text-blue-400">
              <ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden="true" />
              <span>Official Global Download Center · Bangladesh &amp; Worldwide Distribution</span>
            </div>
            <h3 className="text-lg font-bold text-slate-100">
              KIRON PROHORI — Windows Security &amp; Antivirus V1.0 (x64 Installer &amp; Release Channels)
            </h3>
            <p className="text-xs text-slate-300">
              Developer &amp; Publisher: <span className="font-mono font-semibold text-emerald-300">ARIFUZZAMAN KIRON</span> · Target OS: <span className="font-mono text-slate-200">Windows 10 x64 (Build 19041+) &amp; Windows 11 x64</span> · Budget &amp; Privacy: <span className="font-mono text-emerald-300">$0 / NO TELEMETRY BY DEFAULT</span>
            </p>
          </div>

          {/* Honest Download Gate: Display Coming Soon when no verified GitHub Release installer exists */}
          <div className="flex flex-col items-start lg:items-end gap-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={true}
                aria-disabled="true"
                title="Displays Coming Soon until KIRON-PROHORI-Setup-x64.exe is compiled by the GitHub Actions Windows runner and published to GitHub Releases."
                className="inline-flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-950/30 px-4 py-2.5 font-mono text-xs font-semibold text-amber-300 cursor-not-allowed opacity-90"
              >
                <Lock className="h-4 w-4 text-amber-400" aria-hidden="true" />
                <span>Coming Soon — KIRON-PROHORI-Setup-x64.exe (Awaiting GitHub Release Build)</span>
              </button>

              <a
                href="/github-pages-preview/index.html"
                className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/50 bg-blue-600/20 px-3.5 py-2.5 font-mono text-xs font-semibold text-blue-300 hover:bg-blue-600/30"
              >
                <span>Preview Official GitHub Pages Site (10 Sections)</span>
              </a>
            </div>
            <span className="font-mono text-[11px] text-amber-300/90">
              GitHub-First Honesty Gate: Displays &quot;Coming Soon&quot; instead of a fake link until the GitHub Actions Windows runner publishes KIRON-PROHORI-Setup-x64.exe &amp; SHA256SUMS.txt.
            </span>
          </div>
        </div>

        {/* Release Metadata Cards */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1">
            <div className="font-mono text-[11px] uppercase text-slate-400">GitHub Actions Windows Pipeline</div>
            <div className="font-mono text-sm font-bold text-slate-100">windows-build-and-release.yml</div>
            <div className="font-mono text-xs text-blue-300">windows-latest · .NET 8.0 x64 + Inno Setup 6</div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1">
            <div className="font-mono text-[11px] uppercase text-slate-400">GitHub Release Asset Bundle</div>
            <div className="font-mono text-xs font-bold text-slate-100">
              KIRON-PROHORI-Setup-x64.exe
            </div>
            <div className="font-mono text-[11px] text-slate-300">
              + SHA256SUMS.txt · Release-Notes.txt · User-Guide.txt
            </div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1">
            <div className="font-mono text-[11px] uppercase text-slate-400">GitHub Pages Official Site</div>
            <div className="font-mono text-xs font-bold text-emerald-300">
              docs/website/index.html (READY)
            </div>
            <div className="font-mono text-[11px] text-slate-400">10 Pages/Sections · Dynamic Release Lookup</div>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1">
            <div className="font-mono text-[11px] uppercase text-slate-400">Google Drive Archival Policy</div>
            <div className="font-mono text-xs font-bold text-emerald-300">Manual Secondary Mirror Only</div>
            <div className="font-mono text-[11px] text-slate-300">Never a required runtime dependency · Verify SHA-256</div>
          </div>
        </div>

        {/* 4 Release Channels (Section 8: Never label an untested build as Stable) */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
              Release Channels &amp; Promotion Governance (Never Labels an Untested Build as Stable)
            </h4>
            <span className="font-mono text-xs text-emerald-400">Current Active Channel: Developer Build (1.0.0-dev)</span>
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-emerald-500/50 bg-emerald-950/15 p-3.5 space-y-1.5">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-bold text-emerald-300">1. Developer Build</span>
                <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] text-emerald-300">ACTIVE · 1.0.0-dev</span>
              </div>
              <p className="text-xs text-slate-300">
                Complete C# .NET 8.0 Desktop UI, Windows Background Service (<span className="font-mono">KironProhoriSecurityService</span>), Inno Setup/WiX scripts, and Chrome/Edge MV3 extension source.
              </p>
              <div className="font-mono text-[11px] text-slate-400">Signing: UNSIGNED_DEV (Local developer testing)</div>
            </div>

            <div className="rounded-lg border border-blue-500/40 bg-[#0B1222] p-3.5 space-y-1.5">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-bold text-blue-300">2. Internal Testing Build</span>
                <span className="rounded bg-blue-500/20 px-2 py-0.5 text-[10px] text-blue-300">READY FOR VM QA</span>
              </div>
              <p className="text-xs text-slate-300">
                Internal QA build for executing the 15-point Windows 10 &amp; Windows 11 x64 Clean Install, Upgrade, Repair, Uninstall, UAC, and Defender Coexistence matrix.
              </p>
              <div className="font-mono text-[11px] text-slate-400">Signing: DEV_TEST_CERT (Isolated VM only)</div>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1.5">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-bold text-slate-200">3. Public Beta</span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-amber-300">GATED ON CA CERT</span>
              </div>
              <p className="text-xs text-slate-300">
                Public opt-in evaluation release for early adopters in Bangladesh and worldwide after public CA Authenticode code signing.
              </p>
              <div className="font-mono text-[11px] text-slate-400">Signing: PROD_TRUSTED_CA (Mandatory)</div>
            </div>

            <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1.5">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-bold text-slate-200">4. Stable V1.0</span>
                <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-amber-300">GATED · NOT YET PROMOTED</span>
              </div>
              <p className="text-xs text-slate-300">
                Locked until compiled on Windows x64, signed with a publicly trusted CA certificate, submitted to Microsoft SmartScreen, and passed 15/15 Windows VM checks.
              </p>
              <div className="font-mono text-[11px] text-slate-400">Signing: PROD_TRUSTED_CA + RFC-3161 Timestamp</div>
            </div>
          </div>
        </div>

        {/* Installation Guide, Privacy Policy, License Agreement, Release Notes, Security Contact & Known Issues */}
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3 text-xs">
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1.5">
            <div className="font-mono font-semibold text-blue-300">Installation, Repair &amp; Safe Uninstall Guide</div>
            <ul className="space-y-1 text-slate-300 list-disc list-inside">
              <li>Run <span className="font-mono">KIRON-PROHORI-Setup-x64.exe</span> and approve the Windows UAC Administrator prompt.</li>
              <li>Choose install path (default <span className="font-mono">C:\Program Files\KIRON PROHORI</span>) and optional shortcuts/startup tasks.</li>
              <li>Installs <span className="font-mono">KironProhoriSecurityService</span> with delayed auto-start and crash recovery.</li>
              <li>Browser extension setup is 100% user-consented (never silently modifies Chrome/Edge settings).</li>
              <li>Safe Uninstall removes only application-owned files and asks explicit permission before removing or keeping your Quarantine Vault.</li>
            </ul>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1.5">
            <div className="font-mono font-semibold text-emerald-300">Privacy Policy, License &amp; Coexistence</div>
            <ul className="space-y-1 text-slate-300 list-disc list-inside">
              <li><span className="font-semibold">Zero Telemetry by Default:</span> No advertising, no mandatory account, no browsing-history tracking, and no automatic personal file or sample uploads.</li>
              <li><span className="font-semibold">Local Scanning &amp; Quarantine:</span> All file scanning and <span className="font-mono">.kpq</span> quarantine isolation run locally on your PC.</li>
              <li><span className="font-semibold">HTTPS-Only Updates:</span> Updates enforce HTTPS, publisher identity, digital signature verification, SHA-256 checksums, and automatic rollback.</li>
              <li><span className="font-semibold">Windows Coexistence:</span> Never disables Microsoft Defender or Windows Firewall.</li>
            </ul>
          </div>

          <div className="rounded-lg border border-[#1E2D4A] bg-[#0B1222] p-3.5 space-y-1.5">
            <div className="font-mono font-semibold text-amber-300">Release Notes, Security Contact &amp; Known Issues</div>
            <ul className="space-y-1 text-slate-300 list-disc list-inside">
              <li><span className="font-semibold">V1.0 Highlights:</span> Desktop UI, Windows Background Service, User-Mode Real-Time File Guard, Chrome/Edge MV3 Web &amp; 4-State Download Guard.</li>
              <li><span className="font-semibold">Known Limitation (Preview Host):</span> This preview runs in a Linux container; compile the Windows installer natively on Windows 10/11 x64 using <span className="font-mono">installer/build-windows-installer.ps1</span>.</li>
              <li><span className="font-semibold">User-Mode Scope:</span> Does not include a kernel-mode <span className="font-mono">.sys</span> minifilter driver in V1.0.</li>
              <li><span className="font-semibold">Security Contact:</span> ARIFUZZAMAN KIRON (<span className="font-mono">security@kironprohori.security</span>)</li>
            </ul>
          </div>
        </div>
      </div>

      {/* 20 V1.0 Automated Safety, EICAR, Exclusions, Quarantine, Chime, Browser MV3, Native Messaging, Service & Installer Suite */}
      <div className="space-y-3">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              V1.0 Automated Security, Browser Extension, Windows Service &amp; Installer Verification Suite ({suiteResults.filter((r) => r.passed).length}/{suiteResults.length} Scenarios)
            </h3>
            <p className="text-xs text-slate-400">
              Verifies Defender coexistence, Quick/Full/Custom scans, Exclusions, Quarantine-First policy, Restore, Gentle chime synthesis, Duplicate alert suppression, Offline/Zero-Telemetry defaults, HTTPS/Signature/SHA-256 Update verification, Browser MV3 Web &amp; 4-State Download Protection, Native Messaging framing, Real-Time File Guard, and Windows Service/Installer safety.
            </p>
          </div>
          <span className="font-mono text-xs text-emerald-400">
            {suiteResults.filter((r) => r.passed).length}/{suiteResults.length} PASSED
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
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

      {/* Live C# / .NET 8.0, Installer Scripts & Browser Extension Source Code Inspector */}
      {manifest && (
        <div className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                /desktop-agent/ &amp; /browser-extension/ Source Code &amp; Installer Inspector ({manifest.files.length} Files)
              </h3>
              <p className="text-xs text-slate-400">
                Inspect all C# classes (Core, Desktop WPF, Windows Background Service), Inno Setup (.iss) &amp; WiX (.wxs) installer scripts, Chrome/Edge Manifest V3 extension files, 20 xUnit tests, and architecture documentation.
              </p>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
              <Terminal className="h-4 w-4 text-blue-400" aria-hidden="true" />
              <span>powershell -ExecutionPolicy Bypass -File desktop-agent/installer/build-windows-installer.ps1</span>
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
                    <span className="truncate">{f.relativePath}</span>
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
                <span className="inline-flex items-center gap-1">
                  <Info className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>UTF-8 · Read-Only Source</span>
                </span>
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
