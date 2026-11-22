import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Flame,
  Bug,
  FishOff,
  FileWarning,
  Link2,
  FileDigit,
  ClipboardCheck,
  FileText,
  BookmarkCheck,
  Bell,
  Database,
  ShieldCheck,
  Settings,
  BookOpen,
  Search,
  X,
  Shield,
  Info,
  Lock,
  Scale,
  AlertOctagon,
} from 'lucide-react';
import { CORE_MODULES } from '../../data/moduleDefinitions';
import { NavGroupKey, RouteId } from '../../types/navigation';
import { useApp } from '../../context/AppContext';

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  LayoutDashboard,
  ShieldAlert,
  Flame,
  Bug,
  FishOff,
  FileWarning,
  Link2,
  FileDigit,
  ClipboardCheck,
  FileText,
  BookmarkCheck,
  Bell,
  Database,
  ShieldCheck,
  Settings,
  BookOpen,
};

const NAV_GROUPS_ORDER: NavGroupKey[] = [
  'intelligence_feeds',
  'defensive_tools',
  'user_workspace',
  'platform_governance',
];

export const Sidebar: React.FC = () => {
  const {
    activeRoute,
    setActiveRoute,
    language,
    t,
    sidebarOpen,
    setSidebarOpen,
    moduleSearchQuery,
    setModuleSearchQuery,
  } = useApp();

  const filteredModules = CORE_MODULES.filter((mod) => {
    const q = moduleSearchQuery.trim().toLowerCase();
    if (!q) return true;
    return (
      mod.titleEn.toLowerCase().includes(q) ||
      mod.titleBn.toLowerCase().includes(q) ||
      String(mod.order).includes(q)
    );
  });

  const legalItems: { id: RouteId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'about', label: t.legalPages.about, icon: Info },
    { id: 'privacy', label: t.legalPages.privacy, icon: Lock },
    { id: 'terms', label: t.legalPages.terms, icon: Scale },
    { id: 'security-disclaimer', label: t.legalPages.disclaimer, icon: AlertOctagon },
  ];

  return (
    <>
      {/* Mobile / Tablet Scrim Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside
        aria-label="Primary Module Navigation"
        className={`fixed inset-y-0 left-0 z-50 flex w-[276px] flex-col border-r border-[#1E2D4A] bg-[#0B1222] transition-transform duration-150 lg:static lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Identity Lockup */}
        <div className="flex items-center justify-between border-b border-[#1E2D4A] px-5 py-4">
          <button
            type="button"
            onClick={() => setActiveRoute('dashboard')}
            className="flex items-center gap-2.5 text-left focus:outline-none"
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-blue-600 text-white">
              <Shield className="h-4 w-4" aria-hidden="true" />
            </div>
            <div>
              <div className="font-display text-sm font-bold tracking-tight text-slate-100 whitespace-nowrap">
                KIRON PROHORI
              </div>
              <div className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                {t.versionLabel} · $0 Budget
              </div>
            </div>
          </button>

          <button
            type="button"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close sidebar"
            className="rounded-md p-1.5 text-slate-400 hover:bg-[#141F38] hover:text-white lg:hidden"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Module Filter Input */}
        <div className="border-b border-[#1E2D4A] p-3">
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400"
              aria-hidden="true"
            />
            <input
              type="text"
              value={moduleSearchQuery}
              onChange={(e) => setModuleSearchQuery(e.target.value)}
              placeholder={t.searchModulesPlaceholder}
              aria-label={t.searchModulesPlaceholder}
              className="w-full rounded-md border border-[#1E2D4A] bg-[#080D1A] py-1.5 pl-8 pr-7 text-xs text-slate-200 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none"
            />
            {moduleSearchQuery && (
              <button
                type="button"
                onClick={() => setModuleSearchQuery('')}
                aria-label="Clear filter"
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Scrollable 16 Core Modules List + 4 Legal Pages */}
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {NAV_GROUPS_ORDER.map((groupKey) => {
            const groupModules = filteredModules.filter((m) => m.group === groupKey);
            if (groupModules.length === 0) return null;

            return (
              <div key={groupKey} className="space-y-1">
                <div className="px-2.5 pb-1 text-[11px] font-semibold tracking-wide text-slate-400">
                  {t.navGroups[groupKey]}
                </div>
                {groupModules.map((mod) => {
                  const IconComponent = ICON_MAP[mod.iconName] || Shield;
                  const isActive = activeRoute === mod.id;
                  const numStr = String(mod.order).padStart(2, '0');

                  return (
                    <button
                      key={mod.id}
                      type="button"
                      onClick={() => setActiveRoute(mod.id)}
                      className={`group flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-xs font-medium transition-colors ${
                        isActive
                          ? 'bg-blue-600 text-white'
                          : 'text-slate-300 hover:bg-[#141F38] hover:text-white'
                      }`}
                    >
                      <span className="flex items-center gap-2.5 truncate">
                        <IconComponent
                          className={`h-4 w-4 shrink-0 ${
                            isActive
                              ? 'text-white'
                              : 'text-slate-400 group-hover:text-blue-400'
                          }`}
                        />
                        <span className="truncate">
                          {numStr}. {language === 'bn' ? mod.titleBn : mod.titleEn}
                        </span>
                      </span>
                      <span
                        className={`ml-2 shrink-0 font-mono text-[10px] ${
                          isActive
                            ? 'text-blue-100'
                            : mod.defaultStatus === 'CONNECTED'
                            ? 'text-emerald-400'
                            : mod.defaultStatus === 'NOT_CONFIGURED'
                            ? 'text-amber-300'
                            : mod.defaultStatus === 'NOT_CONNECTED'
                            ? 'text-amber-400/90'
                            : mod.defaultStatus === 'DEMO'
                            ? 'text-blue-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {mod.defaultStatus === 'CONNECTED'
                          ? 'CONNECTED'
                          : mod.defaultStatus === 'NOT_CONFIGURED'
                          ? 'NOT CONFIGURED'
                          : mod.defaultStatus === 'NOT_CONNECTED'
                          ? 'NOT CONNECTED'
                          : mod.defaultStatus === 'DEMO'
                          ? 'DEMO'
                          : 'LOCAL READY'}
                      </span>
                    </button>
                  );
                })}
              </div>
            );
          })}

          {/* Trust, Identity & Legal Pages */}
          <div className="space-y-1 border-t border-[#1E2D4A] pt-4">
            <div className="px-2.5 pb-1 text-[11px] font-semibold tracking-wide text-slate-400">
              {t.legalNavHeading}
            </div>
            {legalItems.map((item) => {
              const IconComp = item.icon;
              const isActive = activeRoute === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveRoute(item.id)}
                  className={`group flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-300 hover:bg-[#141F38] hover:text-white'
                  }`}
                >
                  <IconComp
                    className={`h-4 w-4 shrink-0 ${
                      isActive ? 'text-white' : 'text-slate-400 group-hover:text-blue-400'
                    }`}
                  />
                  <span className="truncate">{item.label}</span>
                </button>
              );
            })}
          </div>
        </nav>

        {/* Bottom Independent Identity & Zero-Cost Footer Card */}
        <div className="border-t border-[#1E2D4A] bg-[#080D1A] p-3.5 text-[11px] leading-relaxed text-slate-400">
          <div className="font-medium text-slate-300">{t.zeroCostPledge}</div>
          <p className="mt-1 text-slate-400">{t.independentNoticeShort}</p>
        </div>
      </aside>
    </>
  );
};
