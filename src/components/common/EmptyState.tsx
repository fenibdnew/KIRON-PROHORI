import React from 'react';
import { Unplug, FlaskConical, Loader2 } from 'lucide-react';
import { useApp } from '../../context/AppContext';

interface EmptyStateProps {
  title: string;
  description: string;
  plannedSource: string;
  onInspectDemoSchema: () => void;
  onPreviewLoading: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  plannedSource,
  onInspectDemoSchema,
  onPreviewLoading,
}) => {
  const { t } = useApp();

  return (
    <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-8 text-center">
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-amber-800/60 bg-amber-950/40 text-amber-300">
        <Unplug className="h-6 w-6" aria-hidden="true" />
      </div>

      <div className="mt-3 font-mono text-xs font-medium text-amber-300">
        {t.statusNotConnected}
      </div>

      <h3 className="mt-2 text-lg font-semibold text-slate-100">{title}</h3>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-relaxed text-slate-400">
        {description}
      </p>

      <div className="mx-auto mt-5 max-w-lg border-t border-b border-[#1E2D4A] py-3 text-xs text-slate-400">
        <span className="font-medium text-slate-300">{t.plannedDataSource}: </span>
        <span className="font-mono text-slate-300">{plannedSource}</span>
      </div>

      <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
        <button
          type="button"
          onClick={onInspectDemoSchema}
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 whitespace-nowrap shrink-0"
        >
          <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
          <span>{t.previewSchemaAction}</span>
        </button>

        <button
          type="button"
          onClick={onPreviewLoading}
          className="inline-flex items-center gap-2 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-4 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/50 hover:text-white whitespace-nowrap shrink-0"
        >
          <Loader2 className="h-3.5 w-3.5" aria-hidden="true" />
          <span>{t.triggerLoadingPreviewAction}</span>
        </button>
      </div>
    </div>
  );
};
