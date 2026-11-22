/**
 * KIRON PROHORI — Scam & Phishing Alert Center Module (/client/modules/scam/index.ts)
 * Suspicious URL structural analysis, threat feed cross-matching, and moderated community scam reports.
 */

export {
  parseAndInspectSuspiciousUrl,
  filterAndSortAdvisories,
} from '../../../src/intelligence/engine';
export type {
  SuspiciousUrlAnalysisResult,
  FeedMatchHit,
  VerifiedSecurityAdvisory,
} from '../../../src/intelligence/engine';
export * from '../../../src/security/validation';
