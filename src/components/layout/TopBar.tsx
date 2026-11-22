import React from 'react';
import { Menu, Globe, Bell, Sun, Moon, User } from 'lucide-react';
import { useApp } from '../../context/AppContext';
import { useSecurity } from '../../context/SecurityContext';
import { MODULE_MAP } from '../../data/moduleDefinitions';

/**
 * Clean 3-Zone Top Bar Contract:
 * Zone 1: Brand / Breadcrumb Context (1 line)
 * Zone 2: 4–5 concise single-line text nav links
 * Zone 3: Theme preference, In-App Notifications badge, Profile & Language switcher (EN / বাংলা)
 */
export const TopBar: React.FC = () => {
  const {
    activeRoute,
    setActiveRoute,
    language,
    setLanguage,
    themePreference,
    setThemePreference,
    t,
    setSidebarOpen,
  } = useApp();
  const { notifications, userProfile, isSignedIn } = useSecurity();

  const unreadCount = notifications.filter((n) => !n.isRead).length;

  const currentModule = MODULE_MAP[activeRoute];
  const currentTitle = currentModule
    ? `${String(currentModule.order).padStart(2, '0')}. ${
        language === 'bn' ? currentModule.titleBn : currentModule.titleEn
      }`
    : activeRoute === 'about'
    ? t.legalPages.about
    : activeRoute === 'privacy'
    ? t.legalPages.privacy
    : activeRoute === 'terms'
    ? t.legalPages.terms
    : t.legalPages.disclaimer;

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 border-b border-[#1E2D4A] bg-[#0B1222]/95 px-4 py-3.5 backdrop-blur-sm sm:px-6">
      {/* Zone 1: Mobile Menu Trigger + Breadcrumb Wordmark */}
      <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
        <button
          type="button"
          onClick={() => setSidebarOpen(true)}
          aria-label="Open navigation menu"
          className="rounded-md border border-[#1E2D4A] bg-[#141F38] p-2 text-slate-200 hover:text-white lg:hidden"
        >
          <Menu className="h-4 w-4" />
        </button>

        <div className="flex items-center gap-2 text-sm">
          <button
            type="button"
            onClick={() => setActiveRoute('dashboard')}
            className="font-display font-bold tracking-tight text-slate-100 hover:text-blue-400 transition-colors whitespace-nowrap shrink-0"
          >
            KIRON PROHORI
          </button>
          <span aria-hidden="true" className="text-slate-600">/</span>
          <span className="font-medium text-slate-300 truncate max-w-[160px] sm:max-w-[320px]">
            {currentTitle}
          </span>
        </div>
      </div>

      {/* Zone 2: 5 Concise Single-Line Navigation Links */}
      <nav
        aria-label="Quick Top Navigation"
        className="hidden xl:flex items-center gap-6 text-xs font-medium text-slate-300"
      >
        <button
          type="button"
          onClick={() => setActiveRoute('dashboard')}
          className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
            activeRoute === 'dashboard' ? 'text-blue-400 underline' : ''
          }`}
        >
          {language === 'bn' ? 'ড্যাশবোর্ড' : 'Dashboard'}
        </button>
        <button
          type="button"
          onClick={() => setActiveRoute('url-inspector')}
          className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
            activeRoute === 'url-inspector' ? 'text-blue-400 underline' : ''
          }`}
        >
          {language === 'bn' ? 'URL ইন্সপেক্টর' : 'URL Inspector'}
        </button>
        <button
          type="button"
          onClick={() => setActiveRoute('hash-lookup')}
          className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
            activeRoute === 'hash-lookup' ? 'text-blue-400 underline' : ''
          }`}
        >
          {language === 'bn' ? 'হ্যাশ টুল' : 'Hash Tool'}
        </button>
        <button
          type="button"
          onClick={() => setActiveRoute('my-watchlist')}
          className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
            activeRoute === 'my-watchlist' ? 'text-blue-400 underline' : ''
          }`}
        >
          {language === 'bn' ? 'ওয়াচলিস্ট' : 'Watchlist'}
        </button>
        <button
          type="button"
          onClick={() => setActiveRoute('report-center')}
          className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
            activeRoute === 'report-center' ? 'text-blue-400 underline' : ''
          }`}
        >
          {language === 'bn' ? 'রিপোর্ট সেন্টার' : 'Reports'}
        </button>
      </nav>

      {/* Zone 3: Theme Toggle, In-App Notifications, Profile & Language Switcher */}
      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          onClick={() =>
            setThemePreference(
              themePreference === 'dark' ? 'high_contrast' : 'dark'
            )
          }
          aria-label="Toggle visual theme preference"
          title={
            themePreference === 'dark'
              ? 'Switch to High-Contrast Theme'
              : 'Switch to Tactical Dark Theme'
          }
          className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-2.5 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/50 hover:text-white"
        >
          {themePreference === 'dark' ? (
            <Moon className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
          ) : (
            <Sun className="h-3.5 w-3.5 text-amber-300" aria-hidden="true" />
          )}
          <span className="hidden sm:inline">
            {themePreference === 'dark' ? 'Dark' : 'High-Contrast'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveRoute('notifications')}
          aria-label={`In-app notifications (${unreadCount} unread)`}
          className="relative inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-2.5 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/50 hover:text-white"
        >
          <Bell className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
          {unreadCount > 0 && (
            <span className="rounded-full bg-blue-600 px-1.5 py-0.2 font-mono text-[10px] font-bold text-white">
              {unreadCount}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveRoute('settings')}
          aria-label="Open user profile and settings"
          className="hidden md:inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-2.5 py-2 text-xs font-medium text-slate-200 transition-colors hover:border-blue-500/50 hover:text-white"
        >
          <User className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
          <span className="max-w-[110px] truncate">
            {isSignedIn
              ? userProfile?.displayName || 'Profile'
              : 'Profile / Prefs'}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setLanguage(language === 'en' ? 'bn' : 'en')}
          aria-label="Switch language between English and Bengali"
          className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 whitespace-nowrap shrink-0"
        >
          <Globe className="h-3.5 w-3.5" aria-hidden="true" />
          <span>{language === 'en' ? 'EN · বাংলা' : 'বাংলা · EN'}</span>
        </button>
      </div>
    </header>
  );
};
