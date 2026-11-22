import React from 'react';

interface LoadingStateProps {
  rows?: number;
  label?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  rows = 4,
  label = 'Loading module structural skeleton...',
}) => {
  return (
    <div
      role="status"
      aria-live="polite"
      className="space-y-6 rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-6"
    >
      <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-4">
        <div className="space-y-2">
          <div className="h-4 w-48 animate-pulse rounded bg-[#1A2642]" />
          <div className="h-3 w-72 animate-pulse rounded bg-[#141F38]" />
        </div>
        <span className="font-mono text-xs text-blue-300">{label}</span>
      </div>

      {/* KPI Metric Strip Skeleton */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[0, 1, 2].map((idx) => (
          <div
            key={idx}
            className="rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-4 space-y-2.5"
          >
            <div className="h-3 w-28 animate-pulse rounded bg-[#141F38]" />
            <div className="h-5 w-36 animate-pulse rounded bg-[#1A2642]" />
            <div className="h-2.5 w-20 animate-pulse rounded bg-[#141F38]" />
          </div>
        ))}
      </div>

      {/* High-Density Table Skeleton matching 42px row geometry */}
      <div className="overflow-hidden rounded-lg border border-[#1E2D4A] bg-[#080D1A]">
        <div className="grid grid-cols-4 gap-4 border-b border-[#1E2D4A] bg-[#0E1628] px-4 py-3">
          <div className="h-3 w-24 animate-pulse rounded bg-[#1A2642]" />
          <div className="h-3 w-32 animate-pulse rounded bg-[#1A2642]" />
          <div className="h-3 w-28 animate-pulse rounded bg-[#1A2642]" />
          <div className="ml-auto h-3 w-20 animate-pulse rounded bg-[#1A2642]" />
        </div>
        <div className="divide-y divide-[#1E2D4A]/60">
          {Array.from({ length: rows }).map((_, idx) => (
            <div
              key={idx}
              className="grid grid-cols-4 items-center gap-4 px-4 py-3"
            >
              <div className="h-3.5 w-28 animate-pulse rounded bg-[#141F38]" />
              <div className="h-3.5 w-44 animate-pulse rounded bg-[#141F38]" />
              <div className="h-3.5 w-32 animate-pulse rounded bg-[#141F38]" />
              <div className="ml-auto h-3.5 w-24 animate-pulse rounded bg-[#141F38]" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
