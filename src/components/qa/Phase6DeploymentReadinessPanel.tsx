import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  DollarSign,
  Server,
  Globe,
  Terminal,
  RefreshCw,
} from 'lucide-react';
import {
  runPhase6ComprehensiveSuite,
  EXTERNAL_API_DEPENDENCIES_MATRIX,
} from '../../qa/phase6.test';
import { useApp } from '../../context/AppContext';

interface Phase6DeploymentReadinessPanelProps {
  moduleId: string;
}

export const Phase6DeploymentReadinessPanel: React.FC<
  Phase6DeploymentReadinessPanelProps
> = ({ moduleId }) => {
  const { language } = useApp();
  const isBn = language === 'bn';

  const [filterCategory, setFilterCategory] = useState<
    'ALL' | 'QA_TEST' | 'SECURITY_REVIEW' | 'COST_REVIEW'
  >('ALL');
  const [reRunCounter, setReRunCounter] = useState<number>(0);

  const suiteResult = useMemo(() => {
    void reRunCounter;
    return runPhase6ComprehensiveSuite();
  }, [reRunCounter]);

  if (moduleId !== 'admin-center' && moduleId !== 'help-docs') {
    return null;
  }

  const displayedChecks = suiteResult.checks.filter((c) =>
    filterCategory === 'ALL' ? true : c.category === filterCategory
  );

  return (
    <section
      aria-label="Phase 6 QA, Security Audit & Zero-Cost Deployment Readiness"
      className="rounded-lg border border-emerald-500/30 bg-[#0E1628] p-5 space-y-5"
    >
      {/* Header */}
      <div className="flex flex-col gap-3 border-b border-[#1E2D4A] pb-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            <h2 className="text-base font-semibold text-slate-100">
              {isBn
                ? 'ধাপ ৬: কোয়ালিটি অ্যাসুরেন্স, সিকিউরিটি রিভিউ ও শূন্য-খরচ ডিপ্লয়মেন্ট প্রস্তুতি'
                : 'Phase 6: Quality Assurance, Security Audit & Zero-Cost Deployment Readiness'}
            </h2>
            <span className="rounded border border-emerald-500/40 bg-emerald-950/50 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-emerald-300">
              {suiteResult.passedChecks}/{suiteResult.totalChecks} CHECKS PASSED
            </span>
          </div>
          <p className="text-xs text-slate-400">
            {isBn
              ? '১৮টি ফাংশনাল টেস্ট, ১০টি সিকিউরিটি অডিট এবং ৬টি $০ খরচ নীতিমালা স্বয়ংক্রিয়ভাবে যাচাইকৃত।'
              : 'Automated verification of 18 QA functional tests, 10 OWASP/Zero-Trust security checks, and 6 strict $0.00 cost guardrails.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              { id: 'ALL', label: `All (${suiteResult.totalChecks})` },
              { id: 'QA_TEST', label: 'QA Tests (18)' },
              { id: 'SECURITY_REVIEW', label: 'Security Review (10)' },
              { id: 'COST_REVIEW', label: 'Cost Review (6)' },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setFilterCategory(tab.id)}
              className={`rounded-md px-2.5 py-1.5 font-mono text-[11px] transition-colors ${
                filterCategory === tab.id
                  ? 'bg-blue-600 text-white'
                  : 'border border-[#1E2D4A] bg-[#080D1A] text-slate-300 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}

          <button
            type="button"
            onClick={() => setReRunCounter((n) => n + 1)}
            className="inline-flex items-center gap-1 rounded-md border border-emerald-500/40 bg-emerald-950/40 px-2.5 py-1.5 font-mono text-[11px] text-emerald-200 hover:bg-emerald-900/50"
          >
            <RefreshCw className="h-3 w-3" />
            <span>Re-Run Suite</span>
          </button>
        </div>
      </div>

      {/* 34-Check Verification Matrix */}
      <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
        {displayedChecks.map((chk) => (
          <div
            key={chk.id}
            className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-3 text-xs space-y-1"
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 font-semibold text-slate-100">
                {chk.passed ? (
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                )}
                <span>{chk.title}</span>
              </div>
              <span className="rounded border border-[#1E2D4A] bg-[#0E1628] px-1.5 py-0.5 font-mono text-[10px] text-slate-300 shrink-0">
                {chk.category}
              </span>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-400">
              {chk.evidence}
            </p>
          </div>
        ))}
      </div>

      {/* External API Dependencies & Free-Tier Restrictions Table */}
      <div className="space-y-3 border-t border-[#1E2D4A] pt-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              {isBn
                ? 'বাহ্যিক এপিআই নির্ভরতা ও ফ্রি-টিয়ার সীমাবদ্ধতা (External API Dependencies & Free-Tier Limits)'
                : 'External API Dependencies, Terms & Free-Tier Restrictions ($0.00 Cap)'}
            </h3>
          </div>
          <span className="font-mono text-xs text-emerald-300">
            0 PAID APIS · 0 BILLING UPGRADES
          </span>
        </div>

        <div className="overflow-x-auto rounded-lg border border-[#1E2D4A]">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#1E2D4A] bg-[#080D1A] text-[11px] text-slate-400">
                <th className="p-2.5">Public Source / Service</th>
                <th className="p-2.5">Auth & Cost Tier</th>
                <th className="p-2.5">Free-Tier Rate Limits & Quotas</th>
                <th className="p-2.5">Honest Fallback Behavior</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/60 bg-[#080D1A]/60">
              {EXTERNAL_API_DEPENDENCIES_MATRIX.map((dep) => (
                <tr key={dep.name} className="hover:bg-[#141F38]/40">
                  <td className="p-2.5">
                    <div className="font-semibold text-slate-100">{dep.name}</div>
                    <div className="font-mono text-[10px] text-slate-400 break-all">
                      {dep.endpoint}
                    </div>
                  </td>
                  <td className="p-2.5 font-mono text-[11px]">
                    <div className="text-emerald-300">{dep.costTier}</div>
                    <div className="text-slate-400 text-[10px]">
                      {dep.authRequirement}
                    </div>
                  </td>
                  <td className="p-2.5 text-[11px] text-slate-300">
                    {dep.freeTierRateLimit}
                  </td>
                  <td className="p-2.5 text-[11px] text-slate-400">
                    {dep.fallbackBehavior}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Zero-Cost Deployment Modes (Cloud Starter Tier vs Static Demo Fallback) */}
      <div className="grid grid-cols-1 gap-4 border-t border-[#1E2D4A] pt-4 lg:grid-cols-2">
        <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-2 text-xs">
          <div className="flex items-center gap-2 font-semibold text-slate-100">
            <Server className="h-4 w-4 text-blue-400" />
            <span>
              Option A: Eligible Google Cloud Starter Tier / No-Cost Full-Stack Mode
            </span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            Runs the full Node.js Express security gate (`server.ts`) + React SPA (`dist/`) + Firebase Auth & Cloud Firestore (No-Cost Spark Plan). Server proxy routes (`/api/connectors/*` and `/api/security/*`) enforce SSRF host allowlists and rate limits.
          </p>
          <div className="rounded bg-[#0E1628] p-2 font-mono text-[11px] text-slate-300">
            npm install &amp;&amp; npm run build &amp;&amp; npm start
          </div>
        </div>

        <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-2 text-xs">
          <div className="flex items-center gap-2 font-semibold text-slate-100">
            <Terminal className="h-4 w-4 text-amber-400" />
            <span>
              Option B: Free Static Hosting Fallback (No Credit Card / No Node Server)
            </span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            If deployed to static-only hosting (GitHub Pages, Firebase Hosting Spark static, Cloudflare Pages), the app builds to `dist/` via `npm run build`. It automatically labels server proxy routes as <code className="text-amber-300">STATIC DEMO FALLBACK (Server Proxy Offline)</code> while keeping client-side tools (URL Inspector, WebCrypto SHA-256, Checklists, CSV/PDF Reports) and direct Firestore Security Rules active.
          </p>
          <div className="rounded bg-[#0E1628] p-2 font-mono text-[11px] text-emerald-300">
            <DollarSign className="inline h-3 w-3" /> Zero credit card or paid billing required in either mode.
          </div>
        </div>
      </div>
    </section>
  );
};
