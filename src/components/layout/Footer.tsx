import React from 'react';
import { useApp } from '../../context/AppContext';

export const Footer: React.FC = () => {
  const { setActiveRoute, activeRoute, t } = useApp();

  return (
    <footer className="mt-12 border-t border-[#1E2D4A] bg-[#0B1222] px-6 py-6 text-xs text-slate-400">
      <div className="mx-auto flex max-w-7xl flex-col justify-between gap-4 lg:flex-row lg:items-center">
        <div className="space-y-1">
          <div className="font-medium text-slate-200">
            KIRON PROHORI · {t.appSubtitle} ({t.versionLabel})
          </div>
          <p className="max-w-3xl text-xs text-slate-400">
            {t.independentNoticeFull}
          </p>
        </div>

        <nav
          aria-label="Legal and Platform Trust Links"
          className="flex flex-wrap items-center gap-5 text-xs font-medium text-slate-300"
        >
          <button
            type="button"
            onClick={() => setActiveRoute('about')}
            className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
              activeRoute === 'about' ? 'text-blue-400 underline' : ''
            }`}
          >
            {t.legalPages.about}
          </button>
          <button
            type="button"
            onClick={() => setActiveRoute('privacy')}
            className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
              activeRoute === 'privacy' ? 'text-blue-400 underline' : ''
            }`}
          >
            {t.legalPages.privacy}
          </button>
          <button
            type="button"
            onClick={() => setActiveRoute('terms')}
            className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
              activeRoute === 'terms' ? 'text-blue-400 underline' : ''
            }`}
          >
            {t.legalPages.terms}
          </button>
          <button
            type="button"
            onClick={() => setActiveRoute('security-disclaimer')}
            className={`hover:text-white hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0 ${
              activeRoute === 'security-disclaimer' ? 'text-blue-400 underline' : ''
            }`}
          >
            {t.legalPages.disclaimer}
          </button>
        </nav>
      </div>
    </footer>
  );
};
