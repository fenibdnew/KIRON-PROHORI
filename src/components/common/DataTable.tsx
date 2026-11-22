import React, { useState, useMemo } from 'react';
import { Search, ArrowUpDown, FlaskConical, Unplug } from 'lucide-react';
import { TableColumnSchema } from '../../types/navigation';
import { useApp } from '../../context/AppContext';

interface DataTableProps {
  columns: TableColumnSchema[];
  rows: Record<string, string>[];
  isDemoMode: boolean;
  onSwitchToDemo: () => void;
  onSwitchToNotConnected: () => void;
}

export const DataTable: React.FC<DataTableProps> = ({
  columns,
  rows,
  isDemoMode,
  onSwitchToDemo,
  onSwitchToNotConnected,
}) => {
  const { language, t } = useApp();
  const [searchFilter, setSearchFilter] = useState('');
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState<boolean>(true);

  const filteredAndSortedRows = useMemo(() => {
    if (!isDemoMode) return [];
    const q = searchFilter.trim().toLowerCase();
    let list = rows;
    if (q) {
      list = rows.filter((row) =>
        Object.values(row).some((val) => val.toLowerCase().includes(q))
      );
    }
    if (sortColumn) {
      list = [...list].sort((a, b) => {
        const valA = a[sortColumn] || '';
        const valB = b[sortColumn] || '';
        return sortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
      });
    }
    return list;
  }, [rows, isDemoMode, searchFilter, sortColumn, sortAsc]);

  const handleSort = (colKey: string) => {
    if (sortColumn === colKey) {
      setSortAsc(!sortAsc);
    } else {
      setSortColumn(colKey);
      setSortAsc(true);
    }
  };

  return (
    <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628]">
      {/* Table Toolbar */}
      <div className="flex flex-col gap-3 border-b border-[#1E2D4A] px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-slate-100">
            {t.tableSchemaPreviewHeading}
          </h3>
          <span aria-hidden="true" className="text-slate-600">·</span>
          {isDemoMode ? (
            <span className="inline-flex items-center gap-1.5 font-mono text-xs text-blue-300">
              <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{t.statusDemo}</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 font-mono text-xs text-amber-300">
              <Unplug className="h-3.5 w-3.5" aria-hidden="true" />
              <span>{t.statusNotConnected}</span>
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {isDemoMode && (
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400"
                aria-hidden="true"
              />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder={t.tableFilterPlaceholder}
                aria-label={t.tableFilterPlaceholder}
                className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none sm:w-56"
              />
            </div>
          )}

          {isDemoMode ? (
            <button
              type="button"
              onClick={onSwitchToNotConnected}
              className="rounded-md border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-amber-500/50 hover:text-amber-200 whitespace-nowrap shrink-0"
            >
              {t.returnToHonestEmptyAction}
            </button>
          ) : (
            <button
              type="button"
              onClick={onSwitchToDemo}
              className="rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-blue-500 whitespace-nowrap shrink-0"
            >
              {t.previewSchemaAction}
            </button>
          )}
        </div>
      </div>

      {/* Responsive Table Grid */}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-[#1E2D4A] bg-[#080D1A]/70 text-slate-400">
              {columns.map((col) => (
                <th
                  key={col.key}
                  scope="col"
                  className={`px-5 py-3 font-medium ${
                    col.align === 'right' ? 'text-right' : 'text-left'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => handleSort(col.key)}
                    className={`inline-flex items-center gap-1.5 hover:text-slate-200 whitespace-nowrap ${
                      col.align === 'right' ? 'ml-auto' : ''
                    }`}
                  >
                    <span>{language === 'bn' ? col.headerBn : col.headerEn}</span>
                    <ArrowUpDown className="h-3 w-3 text-slate-500" aria-hidden="true" />
                  </button>
                </th>
              ))}
            </tr>
          </thead>

          <tbody className="divide-y divide-[#1E2D4A]/60 tabular-nums">
            {!isDemoMode ? (
              <tr>
                <td colSpan={columns.length} className="px-5 py-8 text-center">
                  <div className="mx-auto max-w-lg space-y-2">
                    <div className="font-mono text-xs font-medium text-amber-300">
                      {t.statusNotConnected} — 0 CONNECTED ROWS
                    </div>
                    <p className="text-xs text-slate-400">
                      {t.emptyModuleDescription}
                    </p>
                  </div>
                </td>
              </tr>
            ) : filteredAndSortedRows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-5 py-6 text-center text-slate-400">
                  No schema rows matched filter &ldquo;{searchFilter}&rdquo;.
                </td>
              </tr>
            ) : (
              filteredAndSortedRows.map((row, rIdx) => (
                <tr
                  key={rIdx}
                  className="transition-colors hover:bg-[#141F38]/70"
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={`px-5 py-3 ${
                        col.align === 'right' ? 'text-right' : 'text-left'
                      } ${
                        col.isMono
                          ? 'font-mono text-xs text-slate-200'
                          : 'text-slate-200'
                      }`}
                    >
                      {row[col.key] ?? '—'}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
