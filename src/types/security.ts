export type UserRole = 'guest' | 'user' | 'analyst' | 'moderator' | 'admin';

export type StoragePersistenceMode = 'FIRESTORE_LIVE' | 'LOCAL_DEMO_EPHEMERAL';

export interface UserProfileDoc {
  uid: string;
  email: string;
  displayName: string;
  organization: string;
  preferredLanguage: 'en' | 'bn';
  createdAt: string;
  updatedAt: string;
}

export interface RoleDoc {
  uid: string;
  role: 'user' | 'analyst' | 'moderator' | 'admin';
  assignedBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface WatchlistDoc {
  watchlistId: string;
  userId: string;
  itemType: 'vendor_keyword' | 'cve_id' | 'domain_pattern' | 'product_cpe';
  targetValue: string;
  notes: string;
  severityFilter: 'ALL' | 'MEDIUM_PLUS' | 'HIGH_PLUS' | 'CRITICAL_ONLY';
  createdAt: string;
  updatedAt: string;
}

export interface ScamReportDoc {
  reportId: string;
  reporterUid: string;
  title: string;
  category:
    | 'phishing_url'
    | 'otp_scam'
    | 'brand_impersonation'
    | 'invoice_fraud'
    | 'fake_job'
    | 'other';
  defangedIndicator: string;
  description: string;
  moderationStatus: 'pending' | 'approved' | 'rejected' | 'needs_more_info';
  moderatorNotes: string;
  reviewedBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface DataSourceDoc {
  sourceId: string;
  name: string;
  endpointUrl: string;
  sourceType: 'nvd_cve' | 'cisa_kev' | 'urlhaus' | 'osv_advisory' | 'community_phish';
  isEnabled: boolean;
  costTier: 'FREE_PUBLIC_ZERO_COST';
  lastSyncStatus: 'NOT_CONNECTED' | 'READY' | 'SYNCED' | 'ERROR';
  updatedBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuditLogDoc {
  auditId: string;
  actorUid: string;
  action: string;
  targetCollection: string;
  targetId: string;
  summary: string;
  createdAt: string;
}

export interface NotificationDoc {
  notificationId: string;
  userId: string;
  title: string;
  message: string;
  category: 'watchlist_match' | 'moderation_update' | 'security_notice' | 'system';
  isRead: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface FeedbackDoc {
  feedbackId: string;
  userId: string;
  category: 'bug_report' | 'feature_request' | 'false_positive' | 'documentation' | 'appeal_request';
  message: string;
  status: 'open' | 'reviewed' | 'closed';
  createdAt: string;
  updatedAt: string;
}

export interface AppSettingDoc {
  settingId: string;
  key: string;
  value: string;
  description: string;
  updatedBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface CveRecordDoc {
  cveId: string;
  title: string;
  description: string;
  vendor: string;
  product: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvssScore: number;
  cvssVector: string;
  source: string;
  publishedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface KevEntryDoc {
  kevId: string;
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  shortDescription: string;
  requiredAction: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  dateAdded: string;
  dueDate: string;
  createdAt: string;
  updatedAt: string;
}

export interface ThreatIndicatorDoc {
  indicatorId: string;
  indicatorType: 'url' | 'domain' | 'ip' | 'sha256' | 'md5';
  defangedValue: string;
  malwareFamily: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityAdvisoryDoc {
  advisoryId: string;
  title: string;
  summary: string;
  ecosystem: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sourceUrl: string;
  publishedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface SyncLogDoc {
  logId: string;
  sourceId: string;
  triggeredBy: string;
  status: 'STARTED' | 'COMPLETED' | 'FAILED';
  recordsProcessed: number;
  message: string;
  createdAt: string;
}

export interface SecurityVerificationResult {
  id: string;
  tier: 'unauthenticated' | 'normal_user' | 'admin' | 'server_gate';
  title: string;
  targetPath: string;
  passed: boolean;
  actualOutcome: string;
  expectedOutcome: string;
  timestamp: string;
}
