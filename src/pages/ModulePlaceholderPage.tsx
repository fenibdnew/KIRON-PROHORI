import React from 'react';
import {
  Unplug,
  FlaskConical,
  Loader2,
  AlertTriangle,
  Database,
  RefreshCw,
  DollarSign,
  CheckSquare,
  ArrowLeft,
  ArrowRight,
  ShieldCheck,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { ModuleDefinition, FoundationViewState } from '../types/navigation';
import { useApp } from '../context/AppContext';
import { PageHeader } from '../components/common/PageHeader';
import { StatusTag } from '../components/common/StatusTag';
import { LoadingState } from '../components/common/LoadingState';
import { EmptyState } from '../components/common/EmptyState';
import { DataTable } from '../components/common/DataTable';
import { CORE_MODULES } from '../data/moduleDefinitions';
import { DatabaseSecurityFoundationPanel } from '../components/security/DatabaseSecurityFoundationPanel';
import { PublicThreatConnectorsWorkspace } from '../components/connectors/PublicThreatConnectorsWorkspace';
import { IntelligenceCenterWorkspace } from '../components/intelligence/IntelligenceCenterWorkspace';
import { SecurityToolkitWorkspace } from '../components/toolkit/SecurityToolkitWorkspace';
import { AdminGovernanceWorkspace } from '../components/admin/AdminGovernanceWorkspace';
import { Phase6DeploymentReadinessPanel } from '../components/qa/Phase6DeploymentReadinessPanel';
import { Phase7WindowsAgentWorkspace } from '../components/agent/Phase7WindowsAgentWorkspace';

interface ModulePlaceholderPageProps {
  module: ModuleDefinition;
}

const DEMO_CHART_SCHEMA_DATA = [
  { bucket: 'Critical [DEMO]', schemaCount: 0, demoPreview: 4 },
  { bucket: 'High [DEMO]', schemaCount: 0, demoPreview: 9 },
  { bucket: 'Medium [DEMO]', schemaCount: 0, demoPreview: 14 },
  { bucket: 'Low [DEMO]', schemaCount: 0, demoPreview: 6 },
];

/**
 * Helper component that deliberately throws when user clicks "Error Boundary Test"
 * so the ErrorBoundary isolation & recovery can be verified in Phase 1.
 */
const IntentionalErrorTrigger: React.FC = () => {
  throw new Error(
    'Phase 0.1.0 ErrorBoundary Verification: Simulated module render exception.'
  );
};

export const ModulePlaceholderPage: React.FC<ModulePlaceholderPageProps> = ({
  module,
}) => {
  const { language, t, viewState, setViewState, setActiveRoute } = useApp();

  if (viewState === 'error_test') {
    return <IntentionalErrorTrigger />;
  }

  const isBn = language === 'bn';
  const title = isBn ? module.titleBn : module.titleEn;
  const subtitle = isBn ? module.subtitleBn : module.subtitleEn;
  const plannedSource = isBn ? module.plannedSourceBn : module.plannedSourceEn;
  const refreshStrategy = isBn ? module.refreshStrategyBn : module.refreshStrategyEn;
  const zeroCostNotes = isBn ? module.zeroCostNotesBn : module.zeroCostNotesEn;
  const deliverables = isBn
    ? module.phase2DeliverablesBn
    : module.phase2DeliverablesEn;

  const isDemoMode = viewState === 'demo_schema';
  const showChartBaseline =
    module.id === 'dashboard' ||
    module.id === 'cve-explorer' ||
    module.id === 'cisa-kev';

  const prevModule = CORE_MODULES.find((m) => m.order === module.order - 1);
  const nextModule = CORE_MODULES.find((m) => m.order === module.order + 1);

  const stateOptions: {
    id: FoundationViewState;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }[] = [
    { id: 'not_connected', label: t.stateNotConnected, icon: Unplug },
    { id: 'demo_schema', label: t.stateDemoSchema, icon: FlaskConical },
    { id: 'loading', label: t.stateLoading, icon: Loader2 },
    { id: 'error_test', label: t.stateErrorTest, icon: AlertTriangle },
  ];

  return (
    <div className="space-y-6">
      {/* Module Page Header */}
      <PageHeader
        orderNumber={module.order}
        title={title}
        subtitle={subtitle}
        status={module.defaultStatus}
      />

      {/* Interactive Foundation State Inspector Bar */}
      <div className="flex flex-col gap-3 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-xs">
          <span className="font-semibold text-slate-200">
            {t.stateInspectorLabel}:
          </span>{' '}
          <span className="text-slate-400">
            {isBn
              ? 'ফাউন্ডেশন শেলের এম্পটি, ডেমো স্কিমা, লোডিং এবং এরর বাউন্ডারি পরীক্ষা করুন'
              : 'Verify Not Connected empty state, DEMO schema table, loading skeleton, and Error Boundary'}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-1">
          {stateOptions.map((opt) => {
            const IconComp = opt.icon;
            const active = viewState === opt.id;
            return (
              <button
                key={opt.id}
                type="button"
                onClick={() => setViewState(opt.id)}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-300 hover:bg-[#141F38] hover:text-white'
                }`}
              >
                <IconComp className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{opt.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Conditional Loading Skeleton Preview */}
      {viewState === 'loading' ? (
        <LoadingState
          rows={5}
          label={
            isBn
              ? `${module.titleBn} — লোডিং স্কেলিটন প্রিভিউ...`
              : `${module.titleEn} — Loading Skeleton Preview...`
          }
        />
      ) : (
        <>
          {/* Honest Integrity Notice Banner */}
          <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-100">
                  <ShieldCheck className="h-4 w-4 text-blue-400 shrink-0" aria-hidden="true" />
                  <span>{t.noFakeStatsTitle}</span>
                </div>
                <p className="text-xs leading-relaxed text-slate-400">
                  {t.noFakeStatsDesc}
                </p>
              </div>
              <div className="shrink-0">
                <StatusTag
                  status={isDemoMode ? 'DEMO' : module.defaultStatus}
                />
              </div>
            </div>
          </div>

          {/* Phase 7A: Windows 10 & Windows 11 (64-bit) Endpoint Security Agent & Cloud Companion Hub */}
          <Phase7WindowsAgentWorkspace moduleId={module.id} />

          {/* Phase 6: Quality Assurance, Security Audit & Zero-Cost Deployment Readiness Console */}
          <Phase6DeploymentReadinessPanel moduleId={module.id} />

          {/* Phase 5: Secure Admin Center, Moderation Queue, Appeals & Platform Governance */}
          <AdminGovernanceWorkspace moduleId={module.id} />

          {/* Phase 4: Security Toolkit & Personal Features (URL Inspector, Hash Tool, 6-Track Checklist, Watchlist Dashboard, In-App Notifications, CSV/PDF Report Center, Profile & Theme) */}
          <SecurityToolkitWorkspace moduleId={module.id} />

          {/* Phase 3: Intelligence Center Functional Modules (CVE Explorer, CISA KEV Tracker, Malware Intel, Scam & Phishing, Security Advisories) */}
          <IntelligenceCenterWorkspace moduleId={module.id} />

          {/* Active Free Public Threat Intelligence Connectors Engine (CISA KEV · NIST NVD 2.0 · FIRST EPSS · URLhaus) */}
          <PublicThreatConnectorsWorkspace moduleId={module.id} />

          {/* Phase 1: Database & Security Foundation Console */}
          <DatabaseSecurityFoundationPanel moduleId={module.id} />

          {/* KPI Metric Strip — Honest Status Indicators */}
          <section aria-label="Module Telemetry Status Strip">
            <div
              className={`grid grid-cols-1 gap-4 ${
                module.metrics.length === 4
                  ? 'sm:grid-cols-2 lg:grid-cols-4'
                  : 'sm:grid-cols-3'
              }`}
            >
              {module.metrics.map((metric) => {
                const effectiveMetricStatus = isDemoMode
                  ? 'DEMO'
                  : module.defaultStatus === 'CONNECTED' &&
                    metric.status === 'NOT_CONNECTED'
                  ? 'CONNECTED'
                  : metric.status;
                const displayValue = isDemoMode
                  ? metric.demoValue
                  : metric.status === 'LOCAL_READY'
                  ? metric.demoValue
                  : effectiveMetricStatus === 'CONNECTED'
                  ? 'CONNECTED ($0 PUBLIC FEED)'
                  : effectiveMetricStatus === 'NOT_CONFIGURED'
                  ? 'NOT CONFIGURED (OPTIONAL KEY)'
                  : '— (NOT CONNECTED)';

                return (
                  <div
                    key={metric.id}
                    className="flex flex-col justify-between rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4"
                  >
                    <div className="flex items-center justify-between gap-2 text-xs text-slate-400">
                      <span className="font-medium text-slate-300 truncate">
                        {isBn ? metric.labelBn : metric.labelEn}
                      </span>
                      <span className="font-mono text-[11px] text-slate-400 shrink-0">
                        {metric.sourceLabel}
                      </span>
                    </div>

                    <div className="my-3 font-mono text-lg font-semibold tracking-tight text-slate-100 tabular-nums">
                      {displayValue}
                    </div>

                    <div className="border-t border-[#1E2D4A]/70 pt-2">
                      <StatusTag status={effectiveMetricStatus} />
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Optional Recharts Baseline Verification Container for Dashboard / CVE / KEV */}
          {showChartBaseline && (
            <section
              aria-label="Chart Architecture Baseline"
              className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5"
            >
              <div className="flex flex-col gap-2 border-b border-[#1E2D4A] pb-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-slate-100">
                    {t.chartPlaceholderTitle}
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-400">
                    {t.chartPlaceholderSubtitle}
                  </p>
                </div>
                <StatusTag status={isDemoMode ? 'DEMO' : module.defaultStatus} />
              </div>

              <div className="mt-4 h-56 w-full min-w-[200px]">
                <ResponsiveContainer width="100%" height="100%" minWidth={200} minHeight={200}>
                  <BarChart
                    data={DEMO_CHART_SCHEMA_DATA}
                    margin={{ top: 12, right: 16, left: -12, bottom: 4 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#1E2D4A"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="bucket"
                      stroke="#94A3B8"
                      fontSize={11}
                      tickLine={false}
                    />
                    <YAxis
                      stroke="#94A3B8"
                      fontSize={11}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#080D1A',
                        borderColor: '#1E2D4A',
                        borderRadius: '6px',
                        fontSize: '12px',
                        color: '#F1F5F9',
                      }}
                      formatter={(value) => [
                        isDemoMode
                          ? `${value} [DEMO SCHEMA ONLY]`
                          : '0 [NOT CONNECTED]',
                        isDemoMode ? 'Demo Schema Value' : 'Unconnected Feed',
                      ]}
                    />
                    <Bar
                      dataKey={isDemoMode ? 'demoPreview' : 'schemaCount'}
                      fill={isDemoMode ? '#3B82F6' : '#334155'}
                      radius={[4, 4, 0, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>
          )}

          {/* Honest Empty State Card when in Default Not Connected Mode */}
          {!isDemoMode && module.defaultStatus === 'NOT_CONNECTED' && (
            <EmptyState
              title={`${title} — ${t.emptyModuleHeading}`}
              description={t.emptyModuleDescription}
              plannedSource={plannedSource}
              onInspectDemoSchema={() => setViewState('demo_schema')}
              onPreviewLoading={() => setViewState('loading')}
            />
          )}

          {/* Data Table Schema & Column Contract */}
          <DataTable
            columns={module.tableColumns}
            rows={module.demoRows}
            isDemoMode={isDemoMode}
            onSwitchToDemo={() => setViewState('demo_schema')}
            onSwitchToNotConnected={() => setViewState('not_connected')}
          />

          {/* Module Architecture Specification & Phase 2 Scope */}
          <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Data Contract & Zero-Cost Compliance */}
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
              <h2 className="text-base font-semibold text-slate-100">
                {t.moduleSpecHeading}
              </h2>

              <div className="space-y-3 text-xs">
                <div className="border-b border-[#1E2D4A]/70 pb-3">
                  <div className="flex items-center gap-2 font-medium text-slate-300">
                    <Database className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                    <span>{t.plannedDataSource}</span>
                  </div>
                  <p className="mt-1 font-mono text-slate-200">{plannedSource}</p>
                </div>

                <div className="border-b border-[#1E2D4A]/70 pb-3">
                  <div className="flex items-center gap-2 font-medium text-slate-300">
                    <RefreshCw className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                    <span>{t.refreshCadence}</span>
                  </div>
                  <p className="mt-1 text-slate-300">{refreshStrategy}</p>
                </div>

                <div>
                  <div className="flex items-center gap-2 font-medium text-slate-300">
                    <DollarSign className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                    <span>{t.costGuardrail}</span>
                  </div>
                  <p className="mt-1 text-emerald-300/90">{zeroCostNotes}</p>
                </div>
              </div>
            </div>

            {/* Phase 2 Implementation Scope */}
            <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-base font-semibold text-slate-100">
                  {t.phase2Heading}
                </h2>
                <span className="font-mono text-xs text-slate-400">
                  Target: Phase 2
                </span>
              </div>

              <ul className="space-y-3 text-xs text-slate-300">
                {deliverables.map((item, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2.5 border-b border-[#1E2D4A]/60 pb-2.5 last:border-none last:pb-0"
                  >
                    <CheckSquare
                      className="mt-0.5 h-4 w-4 shrink-0 text-blue-400"
                      aria-hidden="true"
                    />
                    <span className="leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          {/* Sequential Module Stepper Footer */}
          <div className="flex items-center justify-between border-t border-[#1E2D4A] pt-4">
            {prevModule ? (
              <button
                type="button"
                onClick={() => setActiveRoute(prevModule.id)}
                className="inline-flex items-center gap-2 rounded-lg border border-[#1E2D4A] bg-[#0E1628] px-3.5 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/50 hover:text-white whitespace-nowrap shrink-0"
              >
                <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
                <span>
                  {String(prevModule.order).padStart(2, '0')}.{' '}
                  {isBn ? prevModule.titleBn : prevModule.titleEn}
                </span>
              </button>
            ) : (
              <div />
            )}

            {nextModule ? (
              <button
                type="button"
                onClick={() => setActiveRoute(nextModule.id)}
                className="inline-flex items-center gap-2 rounded-lg border border-[#1E2D4A] bg-[#0E1628] px-3.5 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/50 hover:text-white whitespace-nowrap shrink-0"
              >
                <span>
                  {String(nextModule.order).padStart(2, '0')}.{' '}
                  {isBn ? nextModule.titleBn : nextModule.titleEn}
                </span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setActiveRoute('about')}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3.5 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 whitespace-nowrap shrink-0"
              >
                <span>{t.legalPages.about}</span>
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
};
