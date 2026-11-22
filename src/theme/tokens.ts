/**
 * KIRON PROHORI — Design Tokens (Phase 0.1.0 Foundation)
 * Sophisticated Navy Dark Theme with Blue Accents & Accessible Contrast
 */

export const DESIGN_TOKENS = {
  brand: {
    name: 'KIRON PROHORI',
    nameBn: 'কিরণ প্রহরী',
    version: '0.1.0',
    phase: 'Phase 1 — Foundation Shell',
    phaseBn: 'ধাপ ১ — ফাউন্ডেশন শেল',
    budgetPolicy: '$0.00 Strict Zero-Cost Architecture',
  },
  colors: {
    canvas: '#080D1A',      // 60% Primary deep navy background
    surface: '#0E1628',     // 30% Structural card/sidebar surface
    elevated: '#141F38',    // Hover / interactive surface
    border: '#1E2D4A',      // Hairline structural border
    accent: '#2563EB',      // 10% High-intent primary blue action
    accentHover: '#3B82F6', // Interactive focus/hover blue
    status: {
      notConnected: {
        text: 'text-amber-300',
        bg: 'bg-amber-950/60',
        border: 'border-amber-800/70',
      },
      demo: {
        text: 'text-blue-300',
        bg: 'bg-blue-950/60',
        border: 'border-blue-800/70',
      },
      localReady: {
        text: 'text-emerald-300',
        bg: 'bg-emerald-950/60',
        border: 'border-emerald-800/70',
      },
      critical: {
        text: 'text-rose-300',
        bg: 'bg-rose-950/60',
        border: 'border-rose-800/70',
      },
    },
  },
  typography: {
    displayFont: "'Plus Jakarta Sans', 'Hind Siliguri', sans-serif",
    bodyFont: "'Public Sans', 'Hind Siliguri', sans-serif",
    monoFont: "'JetBrains Mono', monospace",
  },
  layout: {
    sidebarWidth: '272px',
    maxContainerWidth: '1440px',
    tableRowHeight: '42px',
  },
} as const;
