import React from 'react';
import { RefreshCw } from 'lucide-react';
import { DataStatus } from '../../types/navigation';
import { StatusTag } from './StatusTag';
import { useApp } from '../../context/AppContext';

interface PageHeaderProps {
  orderNumber: number;
  title: string;
  subtitle: string;
  status: DataStatus;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  orderNumber,
  title,
  subtitle,
  status,
}) => {
  const { t, isManualRefreshing, triggerManualRefreshCheck, viewState } = useApp();

  const effectiveStatus: DataStatus =
    viewState === 'demo_schema' ? 'DEMO' : status;

  const formattedOrder = String(orderNumber).padStart(2, '0');

  return (
    <div className="border-b border-[#1E2D4A] pb-5">
      {/* Top Meta Line — Clean unboxed typography with separators */}
      <div className="flex flex-wrap items-center justify-between gap-4 text-xs text-slate-400">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-slate-300">Module {formattedOrder}</span>
          <span aria-hidden="true">·</span>
          <span>{t.versionLabel}</span>
          <span aria-hidden="true">·</span>
          <StatusTag status={effectiveStatus} />
        </div>

        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-slate-400">
            {isManualRefreshing ? t.refreshingLabel : t.lastCheckedNever}
          </span>
          <button
            type="button"
            onClick={triggerManualRefreshCheck}
            disabled={isManualRefreshing}
            className="inline-flex items-center gap-2 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3.5 py-1.5 text-xs font-medium text-slate-100 transition-colors hover:border-blue-500/60 hover:bg-[#1A2847] disabled:opacity-60 whitespace-nowrap shrink-0"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 text-blue-400 ${
                isManualRefreshing ? 'animate-spin' : ''
              }`}
              aria-hidden="true"
            />
            <span>{t.manualRefreshBtn}</span>
          </button>
        </div>
      </div>

      {/* Main Heading & Subtitle */}
      <div className="mt-3">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100 sm:text-3xl">
          {formattedOrder}. {title}
        </h1>
        <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-slate-300">
          {subtitle}
        </p>
      </div>
    </div>
  );
};
