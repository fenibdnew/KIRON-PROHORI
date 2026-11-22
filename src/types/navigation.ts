export type Language = 'en' | 'bn';

export type FoundationViewState = 'not_connected' | 'demo_schema' | 'loading' | 'error_test';

export type DataStatus =
  | 'CONNECTED'
  | 'NOT_CONFIGURED'
  | 'NOT_CONNECTED'
  | 'SYNCING'
  | 'ERROR'
  | 'STALE_DATA'
  | 'DEMO'
  | 'LOCAL_READY';

export type CoreModuleId =
  | 'dashboard'
  | 'cve-explorer'
  | 'cisa-kev'
  | 'malware-intel'
  | 'scam-phishing'
  | 'security-advisories'
  | 'url-inspector'
  | 'hash-lookup'
  | 'security-checklist'
  | 'report-center'
  | 'my-watchlist'
  | 'notifications'
  | 'data-sources'
  | 'admin-center'
  | 'settings'
  | 'help-docs';

export type LegalPageId =
  | 'about'
  | 'privacy'
  | 'terms'
  | 'security-disclaimer';

export type RouteId = CoreModuleId | LegalPageId;

export type NavGroupKey =
  | 'intelligence_feeds'
  | 'defensive_tools'
  | 'user_workspace'
  | 'platform_governance';

export interface TableColumnSchema {
  key: string;
  headerEn: string;
  headerBn: string;
  align?: 'left' | 'right';
  isMono?: boolean;
}

export interface ModuleMetricSpec {
  id: string;
  labelEn: string;
  labelBn: string;
  sourceLabel: string;
  status: DataStatus;
  demoValue: string;
}

export interface ModuleDefinition {
  id: CoreModuleId;
  order: number;
  group: NavGroupKey;
  iconName: string;
  titleEn: string;
  titleBn: string;
  subtitleEn: string;
  subtitleBn: string;
  defaultStatus: DataStatus;
  plannedSourceEn: string;
  plannedSourceBn: string;
  refreshStrategyEn: string;
  refreshStrategyBn: string;
  zeroCostNotesEn: string;
  zeroCostNotesBn: string;
  metrics: ModuleMetricSpec[];
  tableColumns: TableColumnSchema[];
  demoRows: Record<string, string>[];
  phase2DeliverablesEn: string[];
  phase2DeliverablesBn: string[];
}
