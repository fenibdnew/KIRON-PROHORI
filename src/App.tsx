/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  LayoutDashboard,
  Link2,
  FileDigit,
  ClipboardCheck,
  BookmarkCheck,
  Menu,
} from 'lucide-react';
import { AppProvider, useApp } from './context/AppContext';
import { SecurityProvider } from './context/SecurityContext';
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { Footer } from './components/layout/Footer';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { ModulePlaceholderPage } from './pages/ModulePlaceholderPage';
import { LegalPages } from './pages/LegalPages';
import { AuthAndSecurityBanner } from './components/security/AuthAndSecurityBanner';
import { MODULE_MAP, CORE_MODULES } from './data/moduleDefinitions';
import { LegalPageId, RouteId } from './types/navigation';

const LEGAL_ROUTE_SET = new Set<string>([
  'about',
  'privacy',
  'terms',
  'security-disclaimer',
]);

const AppShellContent: React.FC = () => {
  const {
    activeRoute,
    setActiveRoute,
    language,
    themePreference,
    setViewState,
    setSidebarOpen,
  } = useApp();

  const isLegalRoute = LEGAL_ROUTE_SET.has(activeRoute);
  const currentModule = MODULE_MAP[activeRoute] || CORE_MODULES[0];

  const mobileNavItems: {
    id: RouteId;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
  }[] = [
    {
      id: 'dashboard',
      label: language === 'bn' ? 'ড্যাশবোর্ড' : 'Dashboard',
      icon: LayoutDashboard,
    },
    {
      id: 'url-inspector',
      label: language === 'bn' ? 'URL টুল' : 'URL Tool',
      icon: Link2,
    },
    {
      id: 'hash-lookup',
      label: language === 'bn' ? 'হ্যাশ টুল' : 'Hash Tool',
      icon: FileDigit,
    },
    {
      id: 'security-checklist',
      label: language === 'bn' ? 'চেকলিস্ট' : 'Checklist',
      icon: ClipboardCheck,
    },
    {
      id: 'my-watchlist',
      label: language === 'bn' ? 'ওয়াচলিস্ট' : 'Watchlist',
      icon: BookmarkCheck,
    },
  ];

  return (
    <div
      className={`flex min-h-screen text-slate-100 ${
        themePreference === 'high_contrast'
          ? 'bg-[#04070F] contrast-125'
          : 'bg-[#080D1A]'
      }`}
    >
      {/* Left Navigation Sidebar (Desktop Persistent + Tablet/Mobile Drawer) */}
      <Sidebar />

      {/* Main Content Workspace */}
      <div className="flex min-w-0 flex-1 flex-col pb-16 lg:pb-0">
        <TopBar />

        <main className="mx-auto w-full max-w-7xl flex-1 px-4 pt-6 sm:px-6 lg:px-8">
          <ErrorBoundary
            language={language}
            resetKey={activeRoute}
            onReset={() => setViewState('not_connected')}
          >
            <AuthAndSecurityBanner />
            {isLegalRoute ? (
              <LegalPages pageId={activeRoute as LegalPageId} />
            ) : (
              <ModulePlaceholderPage module={currentModule} />
            )}
          </ErrorBoundary>
        </main>

        <Footer />
      </div>

      {/* Responsive Mobile Bottom Quick Navigation Bar */}
      <nav
        aria-label="Mobile Quick Navigation Bar"
        className="fixed bottom-0 inset-x-0 z-30 flex items-center justify-around border-t border-[#1E2D4A] bg-[#0B1222]/95 px-2 py-2 backdrop-blur-md lg:hidden"
      >
        {mobileNavItems.map((item) => {
          const IconComp = item.icon;
          const active = activeRoute === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveRoute(item.id)}
              className={`flex flex-col items-center gap-0.5 rounded-md px-2 py-1 text-[10px] font-medium transition-colors ${
                active
                  ? 'text-blue-400 font-semibold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <IconComp className="h-4 w-4" aria-hidden="true" />
              <span>{item.label}</span>
            </button>
          );
        })}
        <button
          type="button"
          onClick={() => setSidebarOpen(true)}
          aria-label="Open all 16 modules drawer"
          className="flex flex-col items-center gap-0.5 rounded-md px-2 py-1 text-[10px] font-medium text-slate-300 hover:text-white"
        >
          <Menu className="h-4 w-4" aria-hidden="true" />
          <span>{language === 'bn' ? 'মেনু' : 'Modules'}</span>
        </button>
      </nav>
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <SecurityProvider>
        <AppShellContent />
      </SecurityProvider>
    </AppProvider>
  );
}
