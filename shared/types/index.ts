/**
 * KIRON PROHORI — Shared Domain Types (/shared/types/index.ts)
 * Independent Cyber Threat Intelligence Platform (v0.1.0, Strict $0 Budget)
 */

export * from '../../src/types/navigation';
export * from '../../src/types/security';
export type {
  ConnectorId,
  ConnectorOperationalState,
  DataFreshnessInfo,
  ParsedKevRecord,
  ParsedNvdCveRecord,
  ParsedEpssRecord,
  ParsedUrlhausRecord,
} from '../../src/connectors/parsers';
export type {
  NormalizedCveIntelligenceRecord,
  AuthorizedThreatIndicator,
  SuspiciousUrlAnalysisResult,
  VerifiedSecurityAdvisory,
} from '../../src/intelligence/engine';
export type {
  SafeUrlInspectionReport,
  SecurityChecklistTrack,
  PersonalizedWatchlistMatch,
  DefensiveReportPayload,
} from '../../src/toolkit/engine';
export type {
  SourceFreshnessMatrixRow,
} from '../../src/admin/engine';
