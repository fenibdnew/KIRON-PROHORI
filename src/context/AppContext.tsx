import React, { createContext, useContext, useState, useEffect } from 'react';
import { FoundationViewState, Language, RouteId } from '../types/navigation';
import { TRANSLATIONS, UIStrings } from '../i18n/translations';
import { CORE_MODULES } from '../data/moduleDefinitions';

const VALID_ROUTES = new Set<string>([
  ...CORE_MODULES.map((m) => m.id),
  'about',
  'privacy',
  'terms',
  'security-disclaimer',
]);

export type ThemePreference = 'dark' | 'high_contrast';

interface AppContextValue {
  activeRoute: RouteId;
  setActiveRoute: (route: RouteId) => void;
  language: Language;
  setLanguage: (lang: Language) => void;
  themePreference: ThemePreference;
  setThemePreference: (theme: ThemePreference) => void;
  t: UIStrings;
  viewState: FoundationViewState;
  setViewState: (state: FoundationViewState) => void;
  sidebarOpen: boolean;
  setSidebarOpen: (open: boolean) => void;
  moduleSearchQuery: string;
  setModuleSearchQuery: (q: string) => void;
  isManualRefreshing: boolean;
  triggerManualRefreshCheck: () => void;
}

const AppContext = createContext<AppContextValue | undefined>(undefined);

const STORAGE_KEY_LANG = 'kiron_prohori_lang_v1';
const STORAGE_KEY_THEME = 'kiron_prohori_theme_v1';

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeRoute, setActiveRouteState] = useState<RouteId>(() => {
    const hash = window.location.hash.replace('#/', '').replace('#', '');
    if (hash && VALID_ROUTES.has(hash)) {
      return hash as RouteId;
    }
    return 'dashboard';
  });

  const [language, setLanguageState] = useState<Language>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY_LANG);
      if (saved === 'bn' || saved === 'en') return saved;
    } catch {
      // Ignore storage access errors in restricted frames
    }
    return 'en';
  });

  const [themePreference, setThemePreferenceState] = useState<ThemePreference>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY_THEME);
      if (saved === 'high_contrast' || saved === 'dark') return saved;
    } catch {
      // Ignore storage restriction
    }
    return 'dark';
  });

  const [viewState, setViewState] = useState<FoundationViewState>('not_connected');
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);
  const [moduleSearchQuery, setModuleSearchQuery] = useState<string>('');
  const [isManualRefreshing, setIsManualRefreshing] = useState<boolean>(false);

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#/', '').replace('#', '');
      if (hash && VALID_ROUTES.has(hash)) {
        setActiveRouteState(hash as RouteId);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = themePreference;
  }, [themePreference]);

  const setActiveRoute = (route: RouteId) => {
    setActiveRouteState(route);
    try {
      window.location.hash = `/${route}`;
    } catch {
      // Fallback if hash update is restricted
    }
    setSidebarOpen(false);
    // If user was testing the error boundary, reset back to honest not_connected state on route switch
    if (viewState === 'error_test') {
      setViewState('not_connected');
    }
  };

  const setLanguage = (lang: Language) => {
    setLanguageState(lang);
    try {
      localStorage.setItem(STORAGE_KEY_LANG, lang);
    } catch {
      // Ignore storage restriction
    }
    document.documentElement.lang = lang;
  };

  const setThemePreference = (theme: ThemePreference) => {
    setThemePreferenceState(theme);
    try {
      localStorage.setItem(STORAGE_KEY_THEME, theme);
    } catch {
      // Ignore storage restriction
    }
    document.documentElement.dataset.theme = theme;
  };

  const triggerManualRefreshCheck = () => {
    if (isManualRefreshing) return;
    setIsManualRefreshing(true);
    setTimeout(() => {
      setIsManualRefreshing(false);
    }, 650);
  };

  return (
    <AppContext.Provider
      value={{
        activeRoute,
        setActiveRoute,
        language,
        setLanguage,
        themePreference,
        setThemePreference,
        t: TRANSLATIONS[language],
        viewState,
        setViewState,
        sidebarOpen,
        setSidebarOpen,
        moduleSearchQuery,
        setModuleSearchQuery,
        isManualRefreshing,
        triggerManualRefreshCheck,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = (): AppContextValue => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
