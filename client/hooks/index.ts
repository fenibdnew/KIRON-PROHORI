/**
 * KIRON PROHORI — Client React Hooks & Context Providers (/client/hooks/index.ts)
 * Exports application state, bilingual (EN/BN) localization, and security/RBAC contexts.
 */

export { useApp, AppProvider } from '../../src/context/AppContext';
export { useSecurity, SecurityProvider } from '../../src/context/SecurityContext';
