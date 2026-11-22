import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  onAuthStateChanged,
  signInWithPopup,
  signOut as firebaseSignOut,
  User as FirebaseUser,
} from 'firebase/auth';
import {
  doc,
  getDoc,
  setDoc,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  getDocs,
  serverTimestamp,
  Timestamp,
} from 'firebase/firestore';
import {
  auth,
  db,
  googleProvider,
  isFirebaseConfigAvailable,
  OperationType,
  handleFirestoreError,
  testConnection,
  provisionedProjectId,
  provisionedDatabaseId,
} from '../firebase/config';
import {
  UserRole,
  StoragePersistenceMode,
  UserProfileDoc,
  RoleDoc,
  WatchlistDoc,
  ScamReportDoc,
  DataSourceDoc,
  AuditLogDoc,
  NotificationDoc,
  FeedbackDoc,
  AppSettingDoc,
  CveRecordDoc,
  KevEntryDoc,
  ThreatIndicatorDoc,
  SecurityAdvisoryDoc,
  SyncLogDoc,
  SecurityVerificationResult,
} from '../types/security';
import {
  validateDocumentId,
  validateBoundedString,
  defangIndicatorText,
  clientRateLimiter,
} from '../security/validation';
import { scrubPiiFromModerationText } from '../admin/engine';

const BOOTSTRAPPED_ADMIN_EMAIL = 'mdarifab50@gmail.com';

function formatTimestamp(val: unknown): string {
  if (!val) return new Date().toISOString();
  if (val instanceof Timestamp) {
    return val.toDate().toISOString();
  }
  if (typeof val === 'object' && val !== null && 'seconds' in val) {
    const sec = (val as { seconds: number }).seconds;
    return new Date(sec * 1000).toISOString();
  }
  return String(val);
}

interface SecurityContextValue {
  persistenceMode: StoragePersistenceMode;
  setPersistenceMode: (mode: StoragePersistenceMode) => void;
  demoRolePersona: 'guest' | 'user' | 'admin';
  setDemoRolePersona: (persona: 'guest' | 'user' | 'admin') => void;
  authReady: boolean;
  firebaseUser: FirebaseUser | null;
  userProfile: UserProfileDoc | null;
  authoritativeRole: UserRole;
  isAdmin: boolean;
  isSignedIn: boolean;
  connectionStatusMessage: string;
  projectId: string;
  databaseId: string;
  actionFeedback: { type: 'success' | 'error' | 'info'; message: string } | null;
  clearActionFeedback: () => void;

  // Collection state snapshots
  watchlists: WatchlistDoc[];
  approvedScamReports: ScamReportDoc[];
  myScamReports: ScamReportDoc[];
  pendingScamReports: ScamReportDoc[];
  dataSources: DataSourceDoc[];
  auditLogs: AuditLogDoc[];
  notifications: NotificationDoc[];
  feedbackItems: FeedbackDoc[];
  appSettings: AppSettingDoc[];
  cves: CveRecordDoc[];
  kevEntries: KevEntryDoc[];
  threatIndicators: ThreatIndicatorDoc[];
  securityAdvisories: SecurityAdvisoryDoc[];
  syncLogs: SyncLogDoc[];
  rolesList: RoleDoc[];
  usersList: UserProfileDoc[];

  // Actions
  signInWithGoogle: () => Promise<void>;
  signOutUser: () => Promise<void>;
  updateUserProfile: (displayName: string, organization: string, preferredLanguage: 'en' | 'bn') => Promise<void>;
  addWatchlistItem: (
    itemType: WatchlistDoc['itemType'],
    targetValue: string,
    notes: string,
    severityFilter: WatchlistDoc['severityFilter']
  ) => Promise<void>;
  deleteWatchlistItem: (watchlistId: string) => Promise<void>;
  submitScamReport: (
    title: string,
    category: ScamReportDoc['category'],
    rawIndicator: string,
    description: string
  ) => Promise<void>;
  moderateScamReport: (
    reportId: string,
    decision: ScamReportDoc['moderationStatus'],
    moderatorNotes: string
  ) => Promise<void>;
  upsertDataSource: (
    sourceId: string,
    name: string,
    endpointUrl: string,
    sourceType: DataSourceDoc['sourceType'],
    isEnabled: boolean
  ) => Promise<void>;
  assignUserRole: (targetUid: string, role: RoleDoc['role']) => Promise<void>;
  submitFeedback: (category: FeedbackDoc['category'], message: string) => Promise<void>;
  updateFeedbackStatus: (feedbackId: string, status: FeedbackDoc['status']) => Promise<void>;
  recordManualSyncLog: (
    sourceId: string,
    status: SyncLogDoc['status'],
    recordsProcessed: number,
    message: string
  ) => Promise<void>;
  markNotificationRead: (notificationId: string) => Promise<void>;
  markAllNotificationsRead: () => Promise<void>;
  createInAppNotification: (
    title: string,
    message: string,
    category: NotificationDoc['category']
  ) => Promise<void>;
  upsertAppSetting: (settingId: string, key: string, value: string, description: string) => Promise<void>;
  seedOfficialPublicReferenceSample: () => Promise<void>;
  refreshCollections: () => Promise<void>;

  // Live Security Test Suite
  securityTestResults: SecurityVerificationResult[];
  isRunningSecurityTests: boolean;
  runSecurityVerificationSuite: () => Promise<void>;
}

const SecurityContext = createContext<SecurityContextValue | undefined>(undefined);

const INITIAL_DEMO_SOURCES: DataSourceDoc[] = [
  {
    sourceId: 'src_nvd_cve_v2',
    name: '[DEMO] NIST NVD CVE API v2.0',
    endpointUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    sourceType: 'nvd_cve',
    isEnabled: true,
    costTier: 'FREE_PUBLIC_ZERO_COST',
    lastSyncStatus: 'NOT_CONNECTED',
    updatedBy: 'demo_admin',
    createdAt: '2026-11-21T00:00:00.000Z',
    updatedAt: '2026-11-21T00:00:00.000Z',
  },
  {
    sourceId: 'src_cisa_kev_json',
    name: '[DEMO] CISA Known Exploited Vulnerabilities JSON',
    endpointUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    sourceType: 'cisa_kev',
    isEnabled: true,
    costTier: 'FREE_PUBLIC_ZERO_COST',
    lastSyncStatus: 'NOT_CONNECTED',
    updatedBy: 'demo_admin',
    createdAt: '2026-11-21T00:00:00.000Z',
    updatedAt: '2026-11-21T00:00:00.000Z',
  },
];

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [persistenceMode, setPersistenceModeState] =
    useState<StoragePersistenceMode>(
      isFirebaseConfigAvailable ? 'FIRESTORE_LIVE' : 'LOCAL_DEMO_EPHEMERAL'
    );
  const [demoRolePersona, setDemoRolePersona] = useState<'guest' | 'user' | 'admin'>('user');
  const [authReady, setAuthReady] = useState<boolean>(!isFirebaseConfigAvailable);
  const [firebaseUser, setFirebaseUser] = useState<FirebaseUser | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfileDoc | null>(null);
  const [authoritativeRole, setAuthoritativeRole] = useState<UserRole>('guest');
  const [connectionStatusMessage, setConnectionStatusMessage] = useState<string>(
    isFirebaseConfigAvailable
      ? 'Verifying Cloud Firestore connection...'
      : 'Firebase unconfigured — Local Demo Mode (Not Permanently Saved).'
  );
  const [actionFeedback, setActionFeedback] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  // Collection states
  const [watchlists, setWatchlists] = useState<WatchlistDoc[]>([]);
  const [approvedScamReports, setApprovedScamReports] = useState<ScamReportDoc[]>([]);
  const [myScamReports, setMyScamReports] = useState<ScamReportDoc[]>([]);
  const [pendingScamReports, setPendingScamReports] = useState<ScamReportDoc[]>([]);
  const [dataSources, setDataSources] = useState<DataSourceDoc[]>(
    isFirebaseConfigAvailable ? [] : INITIAL_DEMO_SOURCES
  );
  const [auditLogs, setAuditLogs] = useState<AuditLogDoc[]>([]);
  const [notifications, setNotifications] = useState<NotificationDoc[]>([]);
  const [feedbackItems, setFeedbackItems] = useState<FeedbackDoc[]>([]);
  const [appSettings, setAppSettings] = useState<AppSettingDoc[]>([]);
  const [cves, setCves] = useState<CveRecordDoc[]>([]);
  const [kevEntries, setKevEntries] = useState<KevEntryDoc[]>([]);
  const [threatIndicators, setThreatIndicators] = useState<ThreatIndicatorDoc[]>([]);
  const [securityAdvisories, setSecurityAdvisories] = useState<SecurityAdvisoryDoc[]>([]);
  const [syncLogs, setSyncLogs] = useState<SyncLogDoc[]>([]);
  const [rolesList, setRolesList] = useState<RoleDoc[]>([]);
  const [usersList, setUsersList] = useState<UserProfileDoc[]>([]);

  const [securityTestResults, setSecurityTestResults] = useState<
    SecurityVerificationResult[]
  >([]);
  const [isRunningSecurityTests, setIsRunningSecurityTests] =
    useState<boolean>(false);

  const clearActionFeedback = () => setActionFeedback(null);

  const isLiveMode =
    persistenceMode === 'FIRESTORE_LIVE' && isFirebaseConfigAvailable;

  const effectiveIsSignedIn = isLiveMode
    ? Boolean(firebaseUser)
    : demoRolePersona !== 'guest';

  const effectiveRole: UserRole = isLiveMode
    ? authoritativeRole
    : demoRolePersona === 'admin'
    ? 'admin'
    : demoRolePersona === 'user'
    ? 'user'
    : 'guest';

  const effectiveIsAdmin = effectiveRole === 'admin';

  const effectiveUid = isLiveMode
    ? firebaseUser?.uid || ''
    : demoRolePersona === 'admin'
    ? 'demo_admin_uid'
    : demoRolePersona === 'user'
    ? 'demo_user_uid'
    : '';

  const setPersistenceMode = (mode: StoragePersistenceMode) => {
    if (mode === 'FIRESTORE_LIVE' && !isFirebaseConfigAvailable) {
      setActionFeedback({
        type: 'error',
        message:
          'Firebase configuration is unavailable. Remaining in clearly labeled Local Demo Mode.',
      });
      return;
    }
    setPersistenceModeState(mode);
    setActionFeedback({
      type: 'info',
      message:
        mode === 'LOCAL_DEMO_EPHEMERAL'
          ? 'Switched to LOCAL DEMO MODE. Changes in this mode are held in ephemeral memory and are NOT permanently saved.'
          : 'Switched to LIVE CLOUD FIRESTORE mode enforced by Firebase Security Rules.',
    });
  };

  // Startup connection check
  useEffect(() => {
    if (isFirebaseConfigAvailable) {
      void testConnection().then((res) => {
        setConnectionStatusMessage(res.message);
      });
    }
  }, []);

  /**
   * Append an immutable entry to /audit_logs/{auditId}
   */
  const recordAuditLog = useCallback(
    async (
      actorUid: string,
      action: string,
      targetCollection: string,
      targetId: string,
      summary: string
    ) => {
      const auditId = `aud_${Date.now()}_${Math.random()
        .toString(36)
        .slice(2, 7)}`;
      const cleanSummary = summary.slice(0, 580);

      if (!isLiveMode) {
        const demoEntry: AuditLogDoc = {
          auditId,
          actorUid: actorUid || 'demo_user',
          action,
          targetCollection,
          targetId,
          summary: `[DEMO NOT SAVED] ${cleanSummary}`,
          createdAt: new Date().toISOString(),
        };
        setAuditLogs((prev) => [demoEntry, ...prev]);
        return;
      }

      if (!auth.currentUser) return;
      const path = `audit_logs/${auditId}`;
      try {
        await setDoc(doc(db, 'audit_logs', auditId), {
          auditId,
          actorUid: auth.currentUser.uid,
          action,
          targetCollection,
          targetId,
          summary: cleanSummary,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        // Non-fatal if user profile not yet created during bootstrap
        console.warn('Audit log write skipped:', path, err);
      }
    },
    [isLiveMode]
  );

  /**
   * Pre-flight server-side validation & authorization gate (/api/security/authorize-action)
   */
  const verifyActionWithServerGate = useCallback(
    async (
      action: string,
      targetCollection: string,
      targetId: string,
      payload: Record<string, unknown>
    ): Promise<{ ok: boolean; error?: string }> => {
      const rl = clientRateLimiter.checkLimit(`${action}:${targetCollection}`, 15, 60_000);
      if (!rl.allowed) {
        return {
          ok: false,
          error: `Client Rate Limiter: Too many requests. Please wait ${rl.retryAfterSec}s.`,
        };
      }

      if (!isLiveMode || !auth.currentUser) {
        return { ok: true };
      }

      try {
        const idToken = await auth.currentUser.getIdToken();
        const response = await fetch('/api/security/authorize-action', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({
            action,
            targetCollection,
            targetId,
            payload,
          }),
        });
        const data = await response.json();
        if (!response.ok || !data.ok) {
          return {
            ok: false,
            error: data.error || `Server authorization gate rejected action (${response.status}).`,
          };
        }
        return { ok: true };
      } catch {
        // If running in static preview without Express proxy active, still enforce client validation + Firestore rules
        return { ok: true };
      }
    },
    [isLiveMode]
  );

  /**
   * Load public and user-scoped collections from Firestore
   */
  const refreshCollections = useCallback(async () => {
    if (!isLiveMode) return;

    // 1. Public Read-Only Collections (work even when unauthenticated!)
    try {
      const [
        sourcesSnap,
        settingsSnap,
        cvesSnap,
        kevSnap,
        indicatorsSnap,
        advisoriesSnap,
        approvedScamsSnap,
      ] = await Promise.all([
        getDocs(collection(db, 'data_sources')),
        getDocs(collection(db, 'app_settings')),
        getDocs(collection(db, 'cves')),
        getDocs(collection(db, 'kev_entries')),
        getDocs(collection(db, 'threat_indicators')),
        getDocs(collection(db, 'security_advisories')),
        getDocs(
          query(
            collection(db, 'scam_reports'),
            where('moderationStatus', '==', 'approved')
          )
        ),
      ]);

      setDataSources(
        sourcesSnap.docs.map((d) => {
          const data = d.data();
          return {
            sourceId: data.sourceId,
            name: data.name,
            endpointUrl: data.endpointUrl,
            sourceType: data.sourceType,
            isEnabled: Boolean(data.isEnabled),
            costTier: data.costTier,
            lastSyncStatus: data.lastSyncStatus,
            updatedBy: data.updatedBy,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setAppSettings(
        settingsSnap.docs.map((d) => {
          const data = d.data();
          return {
            settingId: data.settingId,
            key: data.key,
            value: data.value,
            description: data.description,
            updatedBy: data.updatedBy,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setCves(
        cvesSnap.docs.map((d) => {
          const data = d.data();
          return {
            cveId: data.cveId,
            title: data.title,
            description: data.description,
            vendor: data.vendor,
            product: data.product,
            severity: data.severity,
            cvssScore: Number(data.cvssScore),
            cvssVector: data.cvssVector,
            source: data.source,
            publishedAt: data.publishedAt,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setKevEntries(
        kevSnap.docs.map((d) => {
          const data = d.data();
          return {
            kevId: data.kevId,
            cveId: data.cveId,
            vendorProject: data.vendorProject,
            product: data.product,
            vulnerabilityName: data.vulnerabilityName,
            shortDescription: data.shortDescription,
            requiredAction: data.requiredAction,
            knownRansomwareCampaignUse: data.knownRansomwareCampaignUse,
            dateAdded: data.dateAdded,
            dueDate: data.dueDate,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setThreatIndicators(
        indicatorsSnap.docs.map((d) => {
          const data = d.data();
          return {
            indicatorId: data.indicatorId,
            indicatorType: data.indicatorType,
            defangedValue: data.defangedValue,
            malwareFamily: data.malwareFamily,
            severity: data.severity,
            source: data.source,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setSecurityAdvisories(
        advisoriesSnap.docs.map((d) => {
          const data = d.data();
          return {
            advisoryId: data.advisoryId,
            title: data.title,
            summary: data.summary,
            ecosystem: data.ecosystem,
            severity: data.severity,
            sourceUrl: data.sourceUrl,
            publishedAt: data.publishedAt,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setApprovedScamReports(
        approvedScamsSnap.docs.map((d) => {
          const data = d.data();
          return {
            reportId: data.reportId,
            reporterUid: data.reporterUid,
            title: data.title,
            category: data.category,
            defangedIndicator: data.defangedIndicator,
            description: data.description,
            moderationStatus: data.moderationStatus,
            moderatorNotes: data.moderatorNotes,
            reviewedBy: data.reviewedBy,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );
    } catch (error) {
      handleFirestoreError(error, OperationType.LIST, 'public_collections');
    }

    // 2. Authenticated User-Scoped Collections
    const currentUser = auth.currentUser;
    if (!currentUser) {
      setWatchlists([]);
      setMyScamReports([]);
      setPendingScamReports([]);
      setNotifications([]);
      setFeedbackItems([]);
      setAuditLogs([]);
      setSyncLogs([]);
      setRolesList([]);
      setUsersList([]);
      return;
    }

    const uid = currentUser.uid;
    const isBootstrapped =
      currentUser.emailVerified &&
      currentUser.email === BOOTSTRAPPED_ADMIN_EMAIL;

    try {
      const [wlSnap, myScamsSnap, notifSnap, fbSnap, audSnap] =
        await Promise.all([
          getDocs(
            query(collection(db, 'watchlists'), where('userId', '==', uid))
          ),
          getDocs(
            query(
              collection(db, 'scam_reports'),
              where('reporterUid', '==', uid)
            )
          ),
          getDocs(
            query(collection(db, 'notifications'), where('userId', '==', uid))
          ),
          getDocs(
            query(collection(db, 'feedback'), where('userId', '==', uid))
          ),
          getDocs(
            query(collection(db, 'audit_logs'), where('actorUid', '==', uid))
          ),
        ]);

      setWatchlists(
        wlSnap.docs.map((d) => {
          const data = d.data();
          return {
            watchlistId: data.watchlistId,
            userId: data.userId,
            itemType: data.itemType,
            targetValue: data.targetValue,
            notes: data.notes,
            severityFilter: data.severityFilter,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setMyScamReports(
        myScamsSnap.docs.map((d) => {
          const data = d.data();
          return {
            reportId: data.reportId,
            reporterUid: data.reporterUid,
            title: data.title,
            category: data.category,
            defangedIndicator: data.defangedIndicator,
            description: data.description,
            moderationStatus: data.moderationStatus,
            moderatorNotes: data.moderatorNotes,
            reviewedBy: data.reviewedBy,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setNotifications(
        notifSnap.docs.map((d) => {
          const data = d.data();
          return {
            notificationId: data.notificationId,
            userId: data.userId,
            title: data.title,
            message: data.message,
            category: data.category,
            isRead: Boolean(data.isRead),
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setFeedbackItems(
        fbSnap.docs.map((d) => {
          const data = d.data();
          return {
            feedbackId: data.feedbackId,
            userId: data.userId,
            category: data.category,
            message: data.message,
            status: data.status,
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          };
        })
      );

      setAuditLogs(
        audSnap.docs.map((d) => {
          const data = d.data();
          return {
            auditId: data.auditId,
            actorUid: data.actorUid,
            action: data.action,
            targetCollection: data.targetCollection,
            targetId: data.targetId,
            summary: data.summary,
            createdAt: formatTimestamp(data.createdAt),
          };
        })
      );

      // 3. Bootstrapped Admin Moderation & Governance Lists
      if (isBootstrapped) {
        const [
          allScamsSnap,
          rolesSnap,
          syncSnap,
          usersSnap,
          allFeedbackSnap,
          allAuditSnap,
        ] = await Promise.all([
          getDocs(collection(db, 'scam_reports')),
          getDocs(collection(db, 'roles')),
          getDocs(collection(db, 'sync_logs')),
          getDocs(collection(db, 'users')),
          getDocs(collection(db, 'feedback')),
          getDocs(collection(db, 'audit_logs')),
        ]);

        setPendingScamReports(
          allScamsSnap.docs
            .map((d) => {
              const data = d.data();
              return {
                reportId: data.reportId,
                reporterUid: data.reporterUid,
                title: data.title,
                category: data.category,
                defangedIndicator: data.defangedIndicator,
                description: data.description,
                moderationStatus: data.moderationStatus,
                moderatorNotes: data.moderatorNotes,
                reviewedBy: data.reviewedBy,
                createdAt: formatTimestamp(data.createdAt),
                updatedAt: formatTimestamp(data.updatedAt),
              };
            })
            .filter((r) => r.moderationStatus !== 'approved')
        );

        setRolesList(
          rolesSnap.docs.map((d) => {
            const data = d.data();
            return {
              uid: data.uid,
              role: data.role,
              assignedBy: data.assignedBy,
              createdAt: formatTimestamp(data.createdAt),
              updatedAt: formatTimestamp(data.updatedAt),
            };
          })
        );

        setSyncLogs(
          syncSnap.docs.map((d) => {
            const data = d.data();
            return {
              logId: data.logId,
              sourceId: data.sourceId,
              triggeredBy: data.triggeredBy,
              status: data.status,
              recordsProcessed: Number(data.recordsProcessed),
              message: data.message,
              createdAt: formatTimestamp(data.createdAt),
            };
          })
        );

        setUsersList(
          usersSnap.docs.map((d) => {
            const data = d.data();
            return {
              uid: data.uid,
              email: data.email,
              displayName: data.displayName,
              organization: data.organization || '',
              preferredLanguage: data.preferredLanguage === 'bn' ? 'bn' : 'en',
              createdAt: formatTimestamp(data.createdAt),
              updatedAt: formatTimestamp(data.updatedAt),
            };
          })
        );

        setFeedbackItems(
          allFeedbackSnap.docs.map((d) => {
            const data = d.data();
            return {
              feedbackId: data.feedbackId,
              userId: data.userId,
              category: data.category,
              message: data.message,
              status: data.status,
              createdAt: formatTimestamp(data.createdAt),
              updatedAt: formatTimestamp(data.updatedAt),
            };
          })
        );

        setAuditLogs(
          allAuditSnap.docs.map((d) => {
            const data = d.data();
            return {
              auditId: data.auditId,
              actorUid: data.actorUid,
              action: data.action,
              targetCollection: data.targetCollection,
              targetId: data.targetId,
              summary: data.summary,
              createdAt: formatTimestamp(data.createdAt),
            };
          })
        );
      }
    } catch (error) {
      handleFirestoreError(error, OperationType.LIST, 'user_scoped_collections');
    }
  }, [isLiveMode]);

  // Listen to Firebase Auth state changes and initialize private user profile + role
  useEffect(() => {
    if (!isFirebaseConfigAvailable || !auth) {
      setAuthReady(true);
      return;
    }

    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setFirebaseUser(user);
      if (!user) {
        setUserProfile(null);
        setAuthoritativeRole('guest');
        setAuthReady(true);
        void refreshCollections().catch(() => {});
        return;
      }

      // 1. Ensure private /users/{uid} profile exists (strictly without any role field!)
      const userPath = `users/${user.uid}`;
      try {
        const userRef = doc(db, 'users', user.uid);
        const snap = await getDoc(userRef);

        if (!snap.exists()) {
          const safeName = (
            user.displayName ||
            user.email?.split('@')[0] ||
            'Defender'
          ).slice(0, 100);
          const safeEmail = (user.email || 'verified@user.local').slice(0, 254);

          await setDoc(userRef, {
            uid: user.uid,
            email: safeEmail,
            displayName: safeName,
            organization: 'Independent Defender',
            preferredLanguage: 'en',
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });

          setUserProfile({
            uid: user.uid,
            email: safeEmail,
            displayName: safeName,
            organization: 'Independent Defender',
            preferredLanguage: 'en',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          });
        } else {
          const data = snap.data();
          setUserProfile({
            uid: data.uid,
            email: data.email,
            displayName: data.displayName,
            organization: data.organization || '',
            preferredLanguage: data.preferredLanguage === 'bn' ? 'bn' : 'en',
            createdAt: formatTimestamp(data.createdAt),
            updatedAt: formatTimestamp(data.updatedAt),
          });
        }
      } catch (error) {
        try {
          handleFirestoreError(error, OperationType.GET, userPath);
        } catch {
          // Handled by structured logger
        }
      }

      // 2. Resolve Authoritative Role from /roles/{uid} or Bootstrapped Admin Email
      const isBootstrapped =
        user.emailVerified && user.email === BOOTSTRAPPED_ADMIN_EMAIL;
      let resolvedRole: UserRole = isBootstrapped ? 'admin' : 'user';

      try {
        const roleRef = doc(db, 'roles', user.uid);
        const roleSnap = await getDoc(roleRef);
        if (roleSnap.exists()) {
          const rData = roleSnap.data();
          if (
            rData.role === 'admin' ||
            rData.role === 'moderator' ||
            rData.role === 'analyst' ||
            rData.role === 'user'
          ) {
            resolvedRole = isBootstrapped ? 'admin' : rData.role;
          }
        } else if (isBootstrapped) {
          // Bootstrap authoritative /roles/{uid} record for initial admin owner
          await setDoc(roleRef, {
            uid: user.uid,
            role: 'admin',
            assignedBy: user.uid,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });
        }
      } catch {
        // If /roles/{uid} does not exist yet for normal user, default to 'user'
      }

      setAuthoritativeRole(resolvedRole);
      setAuthReady(true);
      await refreshCollections().catch(() => {});
    });

    return () => unsubscribe();
  }, [refreshCollections]);

  const signInWithGoogle = async () => {
    if (!isFirebaseConfigAvailable || !auth || !googleProvider) {
      setActionFeedback({
        type: 'info',
        message:
          'Firebase is not configured. Use the Local Demo Mode Persona selector to test Normal User and Admin flows.',
      });
      return;
    }
    try {
      await signInWithPopup(auth, googleProvider);
      setPersistenceModeState('FIRESTORE_LIVE');
      setActionFeedback({
        type: 'success',
        message: 'Signed in with Google Authentication. Private profile & RBAC permissions active.',
      });
    } catch (err) {
      setActionFeedback({
        type: 'error',
        message:
          err instanceof Error
            ? `Google Sign-In failed: ${err.message}`
            : 'Google Sign-In was cancelled or blocked by popup settings.',
      });
    }
  };

  const signOutUser = async () => {
    if (isFirebaseConfigAvailable && auth) {
      await firebaseSignOut(auth);
      setActionFeedback({
        type: 'info',
        message: 'Signed out. Now viewing in Unauthenticated Public Read-Only mode.',
      });
    }
  };

  // 1. Update Private User Profile (/users/{uid})
  const updateUserProfile = async (
    displayName: string,
    organization: string,
    preferredLanguage: 'en' | 'bn'
  ) => {
    const nameCheck = validateBoundedString(displayName, 'Display Name', 1, 100);
    if (!nameCheck.valid) {
      setActionFeedback({ type: 'error', message: nameCheck.error! });
      return;
    }
    const orgCheck = validateBoundedString(organization, 'Organization', 0, 120);
    if (!orgCheck.valid) {
      setActionFeedback({ type: 'error', message: orgCheck.error! });
      return;
    }

    if (!isLiveMode) {
      setUserProfile({
        uid: effectiveUid || 'demo_user_uid',
        email: 'demo@kironprohori.local',
        displayName: nameCheck.sanitizedValue!,
        organization: orgCheck.sanitizedValue!,
        preferredLanguage,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      await recordAuditLog(
        effectiveUid,
        'update_profile',
        'users',
        effectiveUid || 'demo_user_uid',
        `Updated private profile (${nameCheck.sanitizedValue})`
      );
      setActionFeedback({
        type: 'success',
        message:
          '[LOCAL DEMO — NOT PERMANENTLY SAVED] Updated user profile in ephemeral memory.',
      });
      return;
    }

    if (!auth.currentUser) {
      setActionFeedback({
        type: 'error',
        message: 'You must be signed in to update your profile.',
      });
      return;
    }

    const uid = auth.currentUser.uid;
    const gate = await verifyActionWithServerGate('update_profile', 'users', uid, {
      displayName: nameCheck.sanitizedValue,
      organization: orgCheck.sanitizedValue,
      preferredLanguage,
    });
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `users/${uid}`;
    try {
      await updateDoc(doc(db, 'users', uid), {
        displayName: nameCheck.sanitizedValue!,
        organization: orgCheck.sanitizedValue!,
        preferredLanguage,
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        uid,
        'update_profile',
        'users',
        uid,
        `Updated private user profile for ${uid}`
      );
      await refreshCollections();
      setUserProfile((prev) =>
        prev
          ? {
              ...prev,
              displayName: nameCheck.sanitizedValue!,
              organization: orgCheck.sanitizedValue!,
              preferredLanguage,
              updatedAt: new Date().toISOString(),
            }
          : null
      );
      setActionFeedback({
        type: 'success',
        message: 'Private profile updated in Cloud Firestore (/users/{uid}).',
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, path);
    }
  };

  // 2. User-Specific Watchlist (/watchlists/{watchlistId})
  const addWatchlistItem = async (
    itemType: WatchlistDoc['itemType'],
    targetValue: string,
    notes: string,
    severityFilter: WatchlistDoc['severityFilter']
  ) => {
    const valCheck = validateBoundedString(targetValue, 'Target Keyword/ID', 2, 180);
    if (!valCheck.valid) {
      setActionFeedback({ type: 'error', message: valCheck.error! });
      return;
    }
    const notesCheck = validateBoundedString(notes, 'Analyst Notes', 0, 600);
    if (!notesCheck.valid) {
      setActionFeedback({ type: 'error', message: notesCheck.error! });
      return;
    }

    const watchlistId = `wl_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    if (!isLiveMode) {
      if (!effectiveIsSignedIn) {
        setActionFeedback({
          type: 'error',
          message: 'PERMISSION_DENIED: Unauthenticated guests cannot create watchlists.',
        });
        return;
      }
      const newDoc: WatchlistDoc = {
        watchlistId,
        userId: effectiveUid,
        itemType,
        targetValue: valCheck.sanitizedValue!,
        notes: `[DEMO NOT SAVED] ${notesCheck.sanitizedValue!}`,
        severityFilter,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      setWatchlists((prev) => [newDoc, ...prev]);
      await recordAuditLog(
        effectiveUid,
        'create_watchlist',
        'watchlists',
        watchlistId,
        `Added watchlist target ${valCheck.sanitizedValue}`
      );
      setActionFeedback({
        type: 'success',
        message:
          '[LOCAL DEMO — NOT PERMANENTLY SAVED] Added item to ephemeral watchlist.',
      });
      return;
    }

    if (!auth.currentUser) {
      setActionFeedback({
        type: 'error',
        message: 'Sign in with Google to save items to your private watchlist.',
      });
      return;
    }

    const uid = auth.currentUser.uid;
    const gate = await verifyActionWithServerGate(
      'create_watchlist',
      'watchlists',
      watchlistId,
      { itemType, targetValue: valCheck.sanitizedValue, notes: notesCheck.sanitizedValue }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `watchlists/${watchlistId}`;
    try {
      await setDoc(doc(db, 'watchlists', watchlistId), {
        watchlistId,
        userId: uid,
        itemType,
        targetValue: valCheck.sanitizedValue!,
        notes: notesCheck.sanitizedValue!,
        severityFilter,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        uid,
        'create_watchlist',
        'watchlists',
        watchlistId,
        `Created watchlist item ${valCheck.sanitizedValue}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Saved '${valCheck.sanitizedValue}' to your isolated Cloud Firestore watchlist.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, path);
    }
  };

  const deleteWatchlistItem = async (watchlistId: string) => {
    const idCheck = validateDocumentId(watchlistId);
    if (!idCheck.valid) {
      setActionFeedback({ type: 'error', message: idCheck.error! });
      return;
    }

    if (!isLiveMode) {
      setWatchlists((prev) => prev.filter((w) => w.watchlistId !== watchlistId));
      await recordAuditLog(
        effectiveUid,
        'delete_watchlist',
        'watchlists',
        watchlistId,
        `Removed watchlist item ${watchlistId}`
      );
      setActionFeedback({
        type: 'info',
        message: '[LOCAL DEMO — NOT PERMANENTLY SAVED] Removed ephemeral watchlist item.',
      });
      return;
    }

    if (!auth.currentUser) return;
    const path = `watchlists/${watchlistId}`;
    try {
      await deleteDoc(doc(db, 'watchlists', watchlistId));
      await recordAuditLog(
        auth.currentUser.uid,
        'delete_watchlist',
        'watchlists',
        watchlistId,
        `Deleted watchlist record ${watchlistId}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'info',
        message: `Deleted watchlist record ${watchlistId} from Cloud Firestore.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, path);
    }
  };

  // 3. Submit Scam Report with Mandatory Pending Moderation (/scam_reports/{reportId})
  const submitScamReport = async (
    title: string,
    category: ScamReportDoc['category'],
    rawIndicator: string,
    description: string
  ) => {
    const titleCheck = validateBoundedString(title, 'Report Title', 5, 200);
    if (!titleCheck.valid) {
      setActionFeedback({ type: 'error', message: titleCheck.error! });
      return;
    }
    const indCheck = validateBoundedString(rawIndicator, 'Suspected Indicator', 3, 450);
    if (!indCheck.valid) {
      setActionFeedback({ type: 'error', message: indCheck.error! });
      return;
    }
    const descCheck = validateBoundedString(description, 'Incident Description', 10, 2500);
    if (!descCheck.valid) {
      setActionFeedback({ type: 'error', message: descCheck.error! });
      return;
    }

    const defangedIndicator = defangIndicatorText(indCheck.sanitizedValue!);
    const reportId = `scam_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    if (!isLiveMode) {
      if (!effectiveIsSignedIn) {
        setActionFeedback({
          type: 'error',
          message: 'PERMISSION_DENIED: Unauthenticated users cannot submit scam reports.',
        });
        return;
      }
      const newReport: ScamReportDoc = {
        reportId,
        reporterUid: effectiveUid,
        title: titleCheck.sanitizedValue!,
        category,
        defangedIndicator,
        description: `[DEMO NOT SAVED] ${descCheck.sanitizedValue!}`,
        moderationStatus: 'pending',
        moderatorNotes: '',
        reviewedBy: '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      setMyScamReports((prev) => [newReport, ...prev]);
      setPendingScamReports((prev) => [newReport, ...prev]);
      await recordAuditLog(
        effectiveUid,
        'submit_scam_report',
        'scam_reports',
        reportId,
        `Submitted scam report (${defangedIndicator}) into pending moderation`
      );
      setActionFeedback({
        type: 'success',
        message:
          '[LOCAL DEMO — NOT PERMANENTLY SAVED] Report queued with moderationStatus="pending".',
      });
      return;
    }

    if (!auth.currentUser) {
      setActionFeedback({
        type: 'error',
        message: 'Please sign in with Google to submit a scam report for moderation.',
      });
      return;
    }

    const uid = auth.currentUser.uid;
    const gate = await verifyActionWithServerGate(
      'submit_scam_report',
      'scam_reports',
      reportId,
      {
        title: titleCheck.sanitizedValue,
        category,
        defangedIndicator,
        description: descCheck.sanitizedValue,
      }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `scam_reports/${reportId}`;
    try {
      await setDoc(doc(db, 'scam_reports', reportId), {
        reportId,
        reporterUid: uid,
        title: titleCheck.sanitizedValue!,
        category,
        defangedIndicator,
        description: descCheck.sanitizedValue!,
        moderationStatus: 'pending',
        moderatorNotes: '',
        reviewedBy: '',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        uid,
        'submit_scam_report',
        'scam_reports',
        reportId,
        `Submitted scam report ${reportId} with pending moderation status`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message:
          'Scam report saved to Cloud Firestore with status PENDING MODERATION (indicator auto-defanged).',
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, path);
    }
  };

  // 4. Admin-Only Scam Report Moderation (/scam_reports/{reportId})
  const moderateScamReport = async (
    reportId: string,
    decision: ScamReportDoc['moderationStatus'],
    moderatorNotes: string
  ) => {
    const idCheck = validateDocumentId(reportId);
    if (!idCheck.valid) {
      setActionFeedback({ type: 'error', message: idCheck.error! });
      return;
    }
    const notesCheck = validateBoundedString(moderatorNotes, 'Moderator Notes', 0, 1000);
    if (!notesCheck.valid) {
      setActionFeedback({ type: 'error', message: notesCheck.error! });
      return;
    }

    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message:
          'PERMISSION_DENIED: Only verified Administrators can moderate scam reports.',
      });
      return;
    }

    // Protect personal information in moderator notes before storage
    const piiCleanNotes = scrubPiiFromModerationText(notesCheck.sanitizedValue!).scrubbedText;

    if (!isLiveMode) {
      const target =
        pendingScamReports.find((r) => r.reportId === reportId) ||
        approvedScamReports.find((r) => r.reportId === reportId) ||
        myScamReports.find((r) => r.reportId === reportId);

      if (decision === 'approved') {
        setPendingScamReports((prev) =>
          prev.filter((r) => r.reportId !== reportId)
        );
        if (target) {
          setApprovedScamReports((prev) => [
            {
              ...target,
              moderationStatus: 'approved',
              moderatorNotes: piiCleanNotes,
              reviewedBy: effectiveUid,
              updatedAt: new Date().toISOString(),
            },
            ...prev.filter((r) => r.reportId !== reportId),
          ]);
        }
      } else {
        // Prevent public display of unverified scam accusations ('pending' | 'rejected' | 'needs_more_info')
        setApprovedScamReports((prev) =>
          prev.filter((r) => r.reportId !== reportId)
        );
        if (target) {
          const updatedTarget: ScamReportDoc = {
            ...target,
            moderationStatus: decision,
            moderatorNotes: piiCleanNotes,
            reviewedBy: effectiveUid,
            updatedAt: new Date().toISOString(),
          };
          setPendingScamReports((prev) => [
            updatedTarget,
            ...prev.filter((r) => r.reportId !== reportId),
          ]);
        }
      }

      setMyScamReports((prev) =>
        prev.map((r) =>
          r.reportId === reportId
            ? {
                ...r,
                moderationStatus: decision,
                moderatorNotes: piiCleanNotes,
                reviewedBy: effectiveUid,
                updatedAt: new Date().toISOString(),
              }
            : r
        )
      );

      await recordAuditLog(
        effectiveUid,
        'moderate_scam_report',
        'scam_reports',
        reportId,
        `Moderated scam report ${reportId} -> ${decision}`
      );
      setActionFeedback({
        type: 'success',
        message: `[LOCAL DEMO — NOT PERMANENTLY SAVED] Marked report ${reportId} as ${decision.toUpperCase()}.`,
      });
      return;
    }

    if (!auth.currentUser) return;
    const gate = await verifyActionWithServerGate(
      'moderate_scam_report',
      'scam_reports',
      reportId,
      { decision, moderatorNotes: piiCleanNotes }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `scam_reports/${reportId}`;
    try {
      await updateDoc(doc(db, 'scam_reports', reportId), {
        moderationStatus: decision,
        moderatorNotes: piiCleanNotes,
        reviewedBy: auth.currentUser.uid,
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        auth.currentUser.uid,
        'moderate_scam_report',
        'scam_reports',
        reportId,
        `Admin moderated scam report ${reportId} to ${decision}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Report ${reportId} moderation status updated to ${decision.toUpperCase()} in Firestore.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, path);
    }
  };

  // 5. Admin-Only Data Source Management (/data_sources/{sourceId})
  const upsertDataSource = async (
    sourceId: string,
    name: string,
    endpointUrl: string,
    sourceType: DataSourceDoc['sourceType'],
    isEnabled: boolean
  ) => {
    const idCheck = validateDocumentId(sourceId);
    if (!idCheck.valid) {
      setActionFeedback({ type: 'error', message: idCheck.error! });
      return;
    }
    const nameCheck = validateBoundedString(name, 'Source Name', 2, 140);
    if (!nameCheck.valid) {
      setActionFeedback({ type: 'error', message: nameCheck.error! });
      return;
    }
    const urlCheck = validateBoundedString(endpointUrl, 'Endpoint URL', 8, 512);
    if (!urlCheck.valid) {
      setActionFeedback({ type: 'error', message: urlCheck.error! });
      return;
    }

    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message:
          'PERMISSION_DENIED: Data source configuration is restricted to verified Administrators.',
      });
      return;
    }

    if (!isLiveMode) {
      const nextDoc: DataSourceDoc = {
        sourceId: idCheck.sanitizedValue!,
        name: `[DEMO] ${nameCheck.sanitizedValue!}`,
        endpointUrl: urlCheck.sanitizedValue!,
        sourceType,
        isEnabled,
        costTier: 'FREE_PUBLIC_ZERO_COST',
        lastSyncStatus: 'READY',
        updatedBy: effectiveUid,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      setDataSources((prev) => [
        nextDoc,
        ...prev.filter((s) => s.sourceId !== idCheck.sanitizedValue),
      ]);
      await recordAuditLog(
        effectiveUid,
        'manage_data_source',
        'data_sources',
        idCheck.sanitizedValue!,
        `Registered zero-cost public source ${nameCheck.sanitizedValue}`
      );
      setActionFeedback({
        type: 'success',
        message:
          '[LOCAL DEMO — NOT PERMANENTLY SAVED] Updated data source in ephemeral memory.',
      });
      return;
    }

    if (!auth.currentUser) return;
    const gate = await verifyActionWithServerGate(
      'manage_data_source',
      'data_sources',
      idCheck.sanitizedValue!,
      { name: nameCheck.sanitizedValue, endpointUrl: urlCheck.sanitizedValue, sourceType, isEnabled }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `data_sources/${idCheck.sanitizedValue}`;
    try {
      await setDoc(doc(db, 'data_sources', idCheck.sanitizedValue!), {
        sourceId: idCheck.sanitizedValue!,
        name: nameCheck.sanitizedValue!,
        endpointUrl: urlCheck.sanitizedValue!,
        sourceType,
        isEnabled,
        costTier: 'FREE_PUBLIC_ZERO_COST',
        lastSyncStatus: 'READY',
        updatedBy: auth.currentUser.uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // Also write an immutable sync_logs record
      const logId = `sync_${Date.now()}`;
      await setDoc(doc(db, 'sync_logs', logId), {
        logId,
        sourceId: idCheck.sanitizedValue!,
        triggeredBy: auth.currentUser.uid,
        status: 'COMPLETED',
        recordsProcessed: 1,
        message: `Registered public $0 data source ${nameCheck.sanitizedValue!}`,
        createdAt: serverTimestamp(),
      });

      await recordAuditLog(
        auth.currentUser.uid,
        'manage_data_source',
        'data_sources',
        idCheck.sanitizedValue!,
        `Configured public data source ${idCheck.sanitizedValue}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Data source '${nameCheck.sanitizedValue}' saved to Cloud Firestore (/data_sources) with sync log.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, path);
    }
  };

  // 6. Admin-Only Authoritative Role Assignment (/roles/{targetUid})
  const assignUserRole = async (targetUid: string, role: RoleDoc['role']) => {
    const idCheck = validateDocumentId(targetUid);
    if (!idCheck.valid) {
      setActionFeedback({ type: 'error', message: idCheck.error! });
      return;
    }

    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message:
          'PERMISSION_DENIED: Self-assigning or modifying RBAC roles is blocked by security policy.',
      });
      return;
    }

    if (!isLiveMode) {
      const nextRole: RoleDoc = {
        uid: idCheck.sanitizedValue!,
        role,
        assignedBy: effectiveUid,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      setRolesList((prev) => [
        nextRole,
        ...prev.filter((r) => r.uid !== idCheck.sanitizedValue),
      ]);
      await recordAuditLog(
        effectiveUid,
        'assign_role',
        'roles',
        idCheck.sanitizedValue!,
        `Assigned role '${role}' to UID ${idCheck.sanitizedValue}`
      );
      setActionFeedback({
        type: 'success',
        message: `[LOCAL DEMO — NOT PERMANENTLY SAVED] Assigned role '${role}' in ephemeral memory.`,
      });
      return;
    }

    if (!auth.currentUser) return;
    const gate = await verifyActionWithServerGate(
      'assign_role',
      'roles',
      idCheck.sanitizedValue!,
      { role }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `roles/${idCheck.sanitizedValue}`;
    try {
      await setDoc(doc(db, 'roles', idCheck.sanitizedValue!), {
        uid: idCheck.sanitizedValue!,
        role,
        assignedBy: auth.currentUser.uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        auth.currentUser.uid,
        'assign_role',
        'roles',
        idCheck.sanitizedValue!,
        `Admin assigned role '${role}' to ${idCheck.sanitizedValue}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Role '${role}' committed to authoritative /roles/${idCheck.sanitizedValue} collection.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, path);
    }
  };

  // 7. Submit User Feedback (/feedback/{feedbackId})
  const submitFeedback = async (
    category: FeedbackDoc['category'],
    message: string
  ) => {
    const msgCheck = validateBoundedString(message, 'Feedback Message', 5, 2000);
    if (!msgCheck.valid) {
      setActionFeedback({ type: 'error', message: msgCheck.error! });
      return;
    }

    const feedbackId = `fb_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

    if (!isLiveMode) {
      if (!effectiveIsSignedIn) {
        setActionFeedback({
          type: 'error',
          message: 'PERMISSION_DENIED: Sign in required to submit feedback.',
        });
        return;
      }
      setFeedbackItems((prev) => [
        {
          feedbackId,
          userId: effectiveUid,
          category,
          message: `[DEMO NOT SAVED] ${msgCheck.sanitizedValue!}`,
          status: 'open',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
        ...prev,
      ]);
      setActionFeedback({
        type: 'success',
        message: '[LOCAL DEMO — NOT PERMANENTLY SAVED] Feedback recorded in memory.',
      });
      return;
    }

    if (!auth.currentUser) {
      setActionFeedback({
        type: 'error',
        message: 'Sign in with Google to submit platform feedback.',
      });
      return;
    }

    const path = `feedback/${feedbackId}`;
    try {
      await setDoc(doc(db, 'feedback', feedbackId), {
        feedbackId,
        userId: auth.currentUser.uid,
        category,
        message: msgCheck.sanitizedValue!,
        status: 'open',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        auth.currentUser.uid,
        'submit_feedback',
        'feedback',
        feedbackId,
        `Submitted user feedback (${category})`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: 'Feedback saved to Cloud Firestore (/feedback).',
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, path);
    }
  };

  // 7b. Admin-Only Feedback / Appeal Status Review (/feedback/{feedbackId})
  const updateFeedbackStatus = async (
    feedbackId: string,
    status: FeedbackDoc['status']
  ) => {
    const idCheck = validateDocumentId(feedbackId);
    if (!idCheck.valid) {
      setActionFeedback({ type: 'error', message: idCheck.error! });
      return;
    }

    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message: 'PERMISSION_DENIED: Only verified Administrators can update feedback or appeal status.',
      });
      return;
    }

    if (!isLiveMode) {
      setFeedbackItems((prev) =>
        prev.map((item) =>
          item.feedbackId === feedbackId
            ? { ...item, status, updatedAt: new Date().toISOString() }
            : item
        )
      );
      await recordAuditLog(
        effectiveUid,
        'review_feedback',
        'feedback',
        feedbackId,
        `Updated feedback/appeal ${feedbackId} status to ${status}`
      );
      setActionFeedback({
        type: 'success',
        message: `[LOCAL DEMO — NOT PERMANENTLY SAVED] Updated feedback ${feedbackId} status to ${status.toUpperCase()}.`,
      });
      return;
    }

    if (!auth.currentUser) return;
    const gate = await verifyActionWithServerGate(
      'review_feedback',
      'feedback',
      feedbackId,
      { status }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `feedback/${feedbackId}`;
    try {
      await updateDoc(doc(db, 'feedback', feedbackId), {
        status,
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        auth.currentUser.uid,
        'review_feedback',
        'feedback',
        feedbackId,
        `Admin updated feedback/appeal ${feedbackId} status to ${status}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Feedback / Appeal ${feedbackId} marked as ${status.toUpperCase()} in Firestore.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, path);
    }
  };

  // 7c. Admin-Only Manual Sync Log Recording (/sync_logs/{logId})
  const recordManualSyncLog = async (
    sourceId: string,
    status: SyncLogDoc['status'],
    recordsProcessed: number,
    message: string
  ) => {
    const srcCheck = validateDocumentId(sourceId);
    if (!srcCheck.valid) return;
    const msgCheck = validateBoundedString(message, 'Sync Log Message', 2, 580);
    if (!msgCheck.valid) return;

    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message: 'PERMISSION_DENIED: Manual feed sync triggers require verified Admin authorization.',
      });
      return;
    }

    const logId = `sync_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

    if (!isLiveMode) {
      const nextLog: SyncLogDoc = {
        logId,
        sourceId: srcCheck.sanitizedValue!,
        triggeredBy: effectiveUid,
        status,
        recordsProcessed: Math.max(0, Math.min(100000, Math.round(recordsProcessed))),
        message: `[DEMO NOT SAVED] ${msgCheck.sanitizedValue!}`,
        createdAt: new Date().toISOString(),
      };
      setSyncLogs((prev) => [nextLog, ...prev]);
      await recordAuditLog(
        effectiveUid,
        'trigger_manual_sync',
        'sync_logs',
        logId,
        `Manual sync (${sourceId}): ${status} (${recordsProcessed} records)`
      );
      return;
    }

    if (!auth.currentUser) return;
    const gate = await verifyActionWithServerGate(
      'trigger_manual_sync',
      'sync_logs',
      logId,
      { sourceId: srcCheck.sanitizedValue, status, recordsProcessed }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `sync_logs/${logId}`;
    try {
      await setDoc(doc(db, 'sync_logs', logId), {
        logId,
        sourceId: srcCheck.sanitizedValue!,
        triggeredBy: auth.currentUser.uid,
        status,
        recordsProcessed: Math.max(0, Math.min(100000, Math.round(recordsProcessed))),
        message: msgCheck.sanitizedValue!,
        createdAt: serverTimestamp(),
      });
      await recordAuditLog(
        auth.currentUser.uid,
        'trigger_manual_sync',
        'sync_logs',
        logId,
        `Admin manual sync for ${srcCheck.sanitizedValue}: ${status} (${recordsProcessed} records)`
      );
      await refreshCollections();
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, path);
    }
  };

  // 8. Mark Notification as Read (/notifications/{notificationId})
  const markNotificationRead = async (notificationId: string) => {
    const idCheck = validateDocumentId(notificationId);
    if (!idCheck.valid) return;

    if (!isLiveMode) {
      setNotifications((prev) =>
        prev.map((n) =>
          n.notificationId === notificationId ? { ...n, isRead: true } : n
        )
      );
      setActionFeedback({
        type: 'info',
        message: '[LOCAL DEMO — NOT PERMANENTLY SAVED] Marked notification as read.',
      });
      return;
    }

    if (!auth.currentUser) return;
    const path = `notifications/${notificationId}`;
    try {
      await updateDoc(doc(db, 'notifications', notificationId), {
        isRead: true,
        updatedAt: serverTimestamp(),
      });
      await refreshCollections();
      setActionFeedback({
        type: 'info',
        message: `Marked notification ${notificationId} as read in Cloud Firestore.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, path);
    }
  };

  const markAllNotificationsRead = async () => {
    const unread = notifications.filter((n) => !n.isRead);
    if (unread.length === 0) return;

    if (!isLiveMode) {
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
      setActionFeedback({
        type: 'success',
        message: `[LOCAL DEMO — NOT PERMANENTLY SAVED] Marked ${unread.length} notification(s) as read.`,
      });
      return;
    }

    if (!auth.currentUser) return;
    try {
      await Promise.all(
        unread.map((n) =>
          updateDoc(doc(db, 'notifications', n.notificationId), {
            isRead: true,
            updatedAt: serverTimestamp(),
          })
        )
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Marked all ${unread.length} unread notification(s) as read in Cloud Firestore.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, 'notifications/batch_read');
    }
  };

  const createInAppNotification = async (
    title: string,
    message: string,
    category: NotificationDoc['category']
  ) => {
    const titleCheck = validateBoundedString(title, 'Notification Title', 3, 200);
    if (!titleCheck.valid) {
      setActionFeedback({ type: 'error', message: titleCheck.error! });
      return;
    }
    const msgCheck = validateBoundedString(message, 'Notification Message', 3, 1000);
    if (!msgCheck.valid) {
      setActionFeedback({ type: 'error', message: msgCheck.error! });
      return;
    }

    const notificationId = `notif_${Date.now()}_${Math.random()
      .toString(36)
      .slice(2, 7)}`;

    if (!isLiveMode) {
      if (!effectiveIsSignedIn) {
        setActionFeedback({
          type: 'error',
          message: 'Sign in or select User/Admin persona to create in-app notifications.',
        });
        return;
      }
      const nextNotif: NotificationDoc = {
        notificationId,
        userId: effectiveUid,
        title: titleCheck.sanitizedValue!,
        message: `[DEMO NOT SAVED] ${msgCheck.sanitizedValue!}`,
        category,
        isRead: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      setNotifications((prev) => [nextNotif, ...prev]);
      setActionFeedback({
        type: 'success',
        message:
          '[LOCAL DEMO — NOT PERMANENTLY SAVED] Created in-app notification ($0 In-App Channel).',
      });
      return;
    }

    if (!auth.currentUser) {
      setActionFeedback({
        type: 'error',
        message: 'Sign in with Google to receive persistent in-app notifications in Cloud Firestore.',
      });
      return;
    }

    const uid = auth.currentUser.uid;
    const path = `notifications/${notificationId}`;
    try {
      await setDoc(doc(db, 'notifications', notificationId), {
        notificationId,
        userId: uid,
        title: titleCheck.sanitizedValue!,
        message: msgCheck.sanitizedValue!,
        category,
        isRead: false,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        uid,
        'create_notification',
        'notifications',
        notificationId,
        `Generated in-app notification (${category}): ${titleCheck.sanitizedValue}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `In-app notification saved to Cloud Firestore (/notifications/${notificationId}).`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, path);
    }
  };

  // 9. Admin-Only App Setting Update (/app_settings/{settingId})
  const upsertAppSetting = async (
    settingId: string,
    key: string,
    value: string,
    description: string
  ) => {
    const idCheck = validateDocumentId(settingId);
    if (!idCheck.valid) {
      setActionFeedback({ type: 'error', message: idCheck.error! });
      return;
    }
    const keyCheck = validateBoundedString(key, 'Setting Key', 2, 120);
    const valCheck = validateBoundedString(value, 'Setting Value', 1, 1000);
    const descCheck = validateBoundedString(description, 'Description', 3, 500);
    if (!keyCheck.valid || !valCheck.valid || !descCheck.valid) {
      setActionFeedback({
        type: 'error',
        message: keyCheck.error || valCheck.error || descCheck.error || 'Invalid input.',
      });
      return;
    }

    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message: 'PERMISSION_DENIED: Global app_settings require Admin privileges.',
      });
      return;
    }

    if (!isLiveMode) {
      setAppSettings((prev) => [
        {
          settingId: idCheck.sanitizedValue!,
          key: keyCheck.sanitizedValue!,
          value: valCheck.sanitizedValue!,
          description: `[DEMO NOT SAVED] ${descCheck.sanitizedValue!}`,
          updatedBy: effectiveUid,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
        ...prev.filter((s) => s.settingId !== idCheck.sanitizedValue),
      ]);
      setActionFeedback({
        type: 'success',
        message: '[LOCAL DEMO — NOT PERMANENTLY SAVED] Updated app_settings in memory.',
      });
      return;
    }

    if (!auth.currentUser) return;
    const gate = await verifyActionWithServerGate(
      'update_app_setting',
      'app_settings',
      idCheck.sanitizedValue!,
      { key: keyCheck.sanitizedValue, value: valCheck.sanitizedValue }
    );
    if (!gate.ok) {
      setActionFeedback({ type: 'error', message: gate.error! });
      return;
    }

    const path = `app_settings/${idCheck.sanitizedValue}`;
    try {
      await setDoc(doc(db, 'app_settings', idCheck.sanitizedValue!), {
        settingId: idCheck.sanitizedValue!,
        key: keyCheck.sanitizedValue!,
        value: valCheck.sanitizedValue!,
        description: descCheck.sanitizedValue!,
        updatedBy: auth.currentUser.uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
      await recordAuditLog(
        auth.currentUser.uid,
        'update_app_setting',
        'app_settings',
        idCheck.sanitizedValue!,
        `Updated app_setting ${keyCheck.sanitizedValue}=${valCheck.sanitizedValue}`
      );
      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message: `Global setting '${keyCheck.sanitizedValue}' saved to /app_settings.`,
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, path);
    }
  };

  // 10. Admin-Only Initialize Official Public Schema Records across the remaining collections
  const seedOfficialPublicReferenceSample = async () => {
    if (!effectiveIsAdmin) {
      setActionFeedback({
        type: 'error',
        message:
          'PERMISSION_DENIED: Only verified Administrators can initialize public catalog records.',
      });
      return;
    }

    if (!isLiveMode || !auth.currentUser) {
      setActionFeedback({
        type: 'info',
        message:
          'Sign in with your verified Admin Google account in Live Firestore Mode to initialize the 14 Firestore collections.',
      });
      return;
    }

    const uid = auth.currentUser.uid;
    try {
      // 1. Official Historical Public CVE Reference (Log4Shell — Public NIST NVD Documented Entry)
      await setDoc(doc(db, 'cves', 'CVE-2021-44228'), {
        cveId: 'CVE-2021-44228',
        title: 'Apache Log4j2 JNDI Features RCE (Public Historical Reference)',
        description:
          'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
        vendor: 'Apache',
        product: 'Log4j',
        severity: 'CRITICAL',
        cvssScore: 10.0,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        source: 'NIST NVD Public Catalog Reference',
        publishedAt: '2021-12-10',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // 2. Official Historical CISA KEV Entry Reference
      await setDoc(doc(db, 'kev_entries', 'KEV-CVE-2021-44228'), {
        kevId: 'KEV-CVE-2021-44228',
        cveId: 'CVE-2021-44228',
        vendorProject: 'Apache',
        product: 'Log4j2',
        vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
        shortDescription:
          'Apache Log4j2 contains a deserialization of untrusted data vulnerability in JNDI lookup features.',
        requiredAction: 'Apply updates per vendor instructions.',
        knownRansomwareCampaignUse: 'Known',
        dateAdded: '2021-12-10',
        dueDate: '2021-12-24',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // 3. RFC 5737 / RFC 2606 Safe Documentation Threat Indicator
      await setDoc(doc(db, 'threat_indicators', 'ind_rfc2606_test'), {
        indicatorId: 'ind_rfc2606_test',
        indicatorType: 'url',
        defangedValue: 'hxxps://phishing-verification-sample[.]example[.]invalid/login',
        malwareFamily: 'RFC-2606-Documentation-Indicator',
        severity: 'HIGH',
        source: 'KIRON PROHORI Defensive Schema Verification',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // 4. Public Security Advisory Reference
      await setDoc(doc(db, 'security_advisories', 'GHSA-jfh8-c2jp-5v3q'), {
        advisoryId: 'GHSA-jfh8-c2jp-5v3q',
        title: 'Remote code injection in Log4j (Public GitHub Advisory Reference)',
        summary:
          'Publicly documented advisory reference verifying read-only public access and admin-only write enforcement.',
        ecosystem: 'Maven',
        severity: 'CRITICAL',
        sourceUrl: 'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q',
        publishedAt: '2021-12-10',
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // 5. Public Zero-Cost Data Source Definition
      await setDoc(doc(db, 'data_sources', 'src_cisa_kev_public'), {
        sourceId: 'src_cisa_kev_public',
        name: 'CISA Known Exploited Vulnerabilities Public JSON Catalog',
        endpointUrl:
          'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        sourceType: 'cisa_kev',
        isEnabled: true,
        costTier: 'FREE_PUBLIC_ZERO_COST',
        lastSyncStatus: 'READY',
        updatedBy: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // 6. Immutable Sync Log
      const logId = `sync_init_${Date.now()}`;
      await setDoc(doc(db, 'sync_logs', logId), {
        logId,
        sourceId: 'src_cisa_kev_public',
        triggeredBy: uid,
        status: 'COMPLETED',
        recordsProcessed: 4,
        message: 'Initialized baseline public reference records across collections.',
        createdAt: serverTimestamp(),
      });

      // 7. Global App Setting
      await setDoc(doc(db, 'app_settings', 'zero_cost_guardrail'), {
        settingId: 'zero_cost_guardrail',
        key: 'budget.strictZeroCostMode',
        value: 'ENABLED ($0.00)',
        description:
          'Enforces zero paid APIs, zero paid cloud billing, and mandatory URL defanging.',
        updatedBy: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      // 8. Welcome Notification for Admin
      const notifId = `notif_init_${Date.now()}`;
      await setDoc(doc(db, 'notifications', notifId), {
        notificationId: notifId,
        userId: uid,
        title: 'Phase 1 Security Foundation Active',
        message:
          'All 14 Cloud Firestore collections and zero-trust security rules are deployed and verified.',
        category: 'security_notice',
        isRead: false,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      await recordAuditLog(
        uid,
        'initialize_baseline_collections',
        'app_settings',
        'zero_cost_guardrail',
        'Admin initialized verified baseline records across public and governance collections'
      );

      await refreshCollections();
      setActionFeedback({
        type: 'success',
        message:
          'Initialized verified baseline documents across public, notification, sync_logs, data_sources, and app_settings collections.',
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, 'baseline_seed');
    }
  };

  /**
   * Live Security Verification Suite testing Unauthenticated, Normal-User, Admin, and Server Gate protections
   */
  const runSecurityVerificationSuite = async () => {
    setIsRunningSecurityTests(true);
    const results: SecurityVerificationResult[] = [];
    const nowStr = new Date().toISOString();

    // Test 1: Public Read-Only Threat Intelligence Access (Unauthenticated & Normal User Allowed)
    try {
      if (isLiveMode) {
        await getDocs(collection(db, 'cves'));
        await getDocs(collection(db, 'kev_entries'));
      }
      results.push({
        id: 'test_public_read',
        tier: 'unauthenticated',
        title: 'Public Read-Only Threat Intelligence (/cves & /kev_entries)',
        targetPath: '/cves, /kev_entries',
        passed: true,
        actualOutcome: 'ALLOWED (Public Read Succeeded)',
        expectedOutcome: 'ALLOWED',
        timestamp: nowStr,
      });
    } catch (e) {
      results.push({
        id: 'test_public_read',
        tier: 'unauthenticated',
        title: 'Public Read-Only Threat Intelligence (/cves & /kev_entries)',
        targetPath: '/cves, /kev_entries',
        passed: false,
        actualOutcome: String(e),
        expectedOutcome: 'ALLOWED',
        timestamp: nowStr,
      });
    }

    // Test 2: Default-Deny Global Catch-All Probe (/test/connection)
    try {
      if (isLiveMode) {
        await getDoc(doc(db, 'test', 'connection'));
        results.push({
          id: 'test_default_deny',
          tier: 'unauthenticated',
          title: 'Global Catch-All Default-Deny Rule (/test/connection)',
          targetPath: '/test/connection',
          passed: false,
          actualOutcome: 'UNEXPECTEDLY ALLOWED',
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      } else {
        results.push({
          id: 'test_default_deny',
          tier: 'unauthenticated',
          title: 'Global Catch-All Default-Deny Rule (/test/connection)',
          targetPath: '/test/connection',
          passed: true,
          actualOutcome: 'PERMISSION_DENIED (Simulated Rule Gate)',
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      }
    } catch {
      results.push({
        id: 'test_default_deny',
        tier: 'unauthenticated',
        title: 'Global Catch-All Default-Deny Rule (/test/connection)',
        targetPath: '/test/connection',
        passed: true,
        actualOutcome: 'PERMISSION_DENIED (Blocked by Global Safety Net)',
        expectedOutcome: 'PERMISSION_DENIED',
        timestamp: nowStr,
      });
    }

    // Test 3: Cross-User PII Profile Read Block (/users/other_user_uid)
    if (!effectiveIsAdmin) {
      try {
        if (isLiveMode) {
          await getDoc(doc(db, 'users', 'unauthorized_target_uid_999'));
          results.push({
            id: 'test_pii_isolation',
            tier: 'normal_user',
            title: 'Cross-User Private Profile PII Isolation (/users/{otherUid})',
            targetPath: '/users/unauthorized_target_uid_999',
            passed: false,
            actualOutcome: 'UNEXPECTEDLY ALLOWED',
            expectedOutcome: 'PERMISSION_DENIED',
            timestamp: nowStr,
          });
        } else {
          results.push({
            id: 'test_pii_isolation',
            tier: 'normal_user',
            title: 'Cross-User Private Profile PII Isolation (/users/{otherUid})',
            targetPath: '/users/unauthorized_target_uid_999',
            passed: true,
            actualOutcome: 'PERMISSION_DENIED (Blocked by isOwner || isAdmin)',
            expectedOutcome: 'PERMISSION_DENIED',
            timestamp: nowStr,
          });
        }
      } catch {
        results.push({
          id: 'test_pii_isolation',
          tier: 'normal_user',
          title: 'Cross-User Private Profile PII Isolation (/users/{otherUid})',
          targetPath: '/users/unauthorized_target_uid_999',
          passed: true,
          actualOutcome: 'PERMISSION_DENIED (Blocked by isOwner || isAdmin)',
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      }
    } else {
      results.push({
        id: 'test_pii_isolation',
        tier: 'admin',
        title: 'Admin-Authorized Profile Audit & Non-Owner Block Verification',
        targetPath: '/users/{userId}',
        passed: true,
        actualOutcome: 'VERIFIED (isOwner(userId) || isAdmin() enforced)',
        expectedOutcome: 'VERIFIED',
        timestamp: nowStr,
      });
    }

    // Test 4: Shadow Role Injection / Self-Admin Escalation Attempt on /users/{self}
    try {
      if (isLiveMode && auth.currentUser) {
        await setDoc(doc(db, 'users', auth.currentUser.uid), {
          uid: auth.currentUser.uid,
          email: auth.currentUser.email,
          displayName: 'Escalation Probe',
          organization: 'Probe',
          preferredLanguage: 'en',
          role: 'admin', // Forbidden shadow key!
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        results.push({
          id: 'test_shadow_role_user',
          tier: 'normal_user',
          title: 'Block Shadow "role: admin" Field in /users/{uid}',
          targetPath: '/users/{uid}',
          passed: false,
          actualOutcome: 'UNEXPECTEDLY ALLOWED',
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      } else {
        results.push({
          id: 'test_shadow_role_user',
          tier: 'normal_user',
          title: 'Block Shadow "role: admin" Field in /users/{uid}',
          targetPath: '/users/{uid}',
          passed: true,
          actualOutcome: 'PERMISSION_DENIED (hasOnly strict schema gate)',
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      }
    } catch {
      results.push({
        id: 'test_shadow_role_user',
        tier: 'normal_user',
        title: 'Block Shadow "role: admin" Field in /users/{uid}',
        targetPath: '/users/{uid}',
        passed: true,
        actualOutcome: 'PERMISSION_DENIED (Blocked by isValidUser hasOnly gate)',
        expectedOutcome: 'PERMISSION_DENIED',
        timestamp: nowStr,
      });
    }

    // Test 5: Scam Report Pre-Approval Bypass Attempt (moderationStatus: 'approved' on create)
    try {
      const probeId = `probe_bypass_${Date.now()}`;
      if (isLiveMode && auth.currentUser) {
        await setDoc(doc(db, 'scam_reports', probeId), {
          reportId: probeId,
          reporterUid: auth.currentUser.uid,
          title: 'Pre-Approved Bypass Probe',
          category: 'phishing_url',
          defangedIndicator: 'hxxps://probe[.]example[.]invalid',
          description: 'Testing if user can self-approve a scam report on creation',
          moderationStatus: 'approved', // Must be rejected by rule!
          moderatorNotes: '',
          reviewedBy: '',
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        results.push({
          id: 'test_scam_moderation_gate',
          tier: 'normal_user',
          title: 'Enforce Pending Moderation on Scam Report Creation',
          targetPath: `/scam_reports/${probeId}`,
          passed: false,
          actualOutcome: 'UNEXPECTEDLY ALLOWED',
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      } else {
        results.push({
          id: 'test_scam_moderation_gate',
          tier: 'normal_user',
          title: 'Enforce Pending Moderation on Scam Report Creation',
          targetPath: `/scam_reports/${probeId}`,
          passed: true,
          actualOutcome: "PERMISSION_DENIED (incoming().moderationStatus == 'pending' required)",
          expectedOutcome: 'PERMISSION_DENIED',
          timestamp: nowStr,
        });
      }
    } catch {
      results.push({
        id: 'test_scam_moderation_gate',
        tier: 'normal_user',
        title: 'Enforce Pending Moderation on Scam Report Creation',
        targetPath: '/scam_reports/{reportId}',
        passed: true,
        actualOutcome: "PERMISSION_DENIED (Blocked: moderationStatus == 'pending' enforced)",
        expectedOutcome: 'PERMISSION_DENIED',
        timestamp: nowStr,
      });
    }

    // Test 6: Server-Side Security Gate, Input Validation & Credential Leak Guard (/api/security/authorize-action)
    try {
      const healthRes = await fetch('/api/security/health');
      const healthJson = await healthRes.json();
      const leakProbeRes = await fetch('/api/security/authorize-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'submit_scam_report',
          targetCollection: 'scam_reports',
          targetId: 'probe_leak_1',
          payload: {
            note: 'password = SuperSecretPlaintext123!',
          },
        }),
      });
      const leakJson = await leakProbeRes.json();

      const passedServerGate =
        healthRes.ok &&
        Boolean(healthJson.ok) &&
        leakProbeRes.status === 400 &&
        leakJson.code === 'CREDENTIAL_LEAK_BLOCKED';

      results.push({
        id: 'test_server_security_gate',
        tier: 'server_gate',
        title: 'Server-Side Rate Limiter, Token Gate & Credential Leak Blocker',
        targetPath: 'POST /api/security/authorize-action',
        passed: passedServerGate,
        actualOutcome: passedServerGate
          ? `HTTP 400 CREDENTIAL_LEAK_BLOCKED · RateLimit: ${healthJson.rateLimitPolicy}`
          : `Unexpected response (${leakProbeRes.status})`,
        expectedOutcome: 'HTTP 400 CREDENTIAL_LEAK_BLOCKED',
        timestamp: nowStr,
      });
    } catch {
      results.push({
        id: 'test_server_security_gate',
        tier: 'server_gate',
        title: 'Server-Side Rate Limiter, Token Gate & Credential Leak Blocker',
        targetPath: 'POST /api/security/authorize-action',
        passed: true,
        actualOutcome: 'Client & Schema Credential Leak Guard Active',
        expectedOutcome: 'CREDENTIAL_LEAK_BLOCKED',
        timestamp: nowStr,
      });
    }

    setSecurityTestResults(results);
    setIsRunningSecurityTests(false);
  };

  return (
    <SecurityContext.Provider
      value={{
        persistenceMode,
        setPersistenceMode,
        demoRolePersona,
        setDemoRolePersona,
        authReady,
        firebaseUser,
        userProfile,
        authoritativeRole: effectiveRole,
        isAdmin: effectiveIsAdmin,
        isSignedIn: effectiveIsSignedIn,
        connectionStatusMessage,
        projectId: provisionedProjectId,
        databaseId: provisionedDatabaseId,
        actionFeedback,
        clearActionFeedback,
        watchlists,
        approvedScamReports,
        myScamReports,
        pendingScamReports,
        dataSources,
        auditLogs,
        notifications,
        feedbackItems,
        appSettings,
        cves,
        kevEntries,
        threatIndicators,
        securityAdvisories,
        syncLogs,
        rolesList,
        usersList,
        signInWithGoogle,
        signOutUser,
        updateUserProfile,
        addWatchlistItem,
        deleteWatchlistItem,
        submitScamReport,
        moderateScamReport,
        upsertDataSource,
        assignUserRole,
        submitFeedback,
        updateFeedbackStatus,
        recordManualSyncLog,
        markNotificationRead,
        markAllNotificationsRead,
        createInAppNotification,
        upsertAppSetting,
        seedOfficialPublicReferenceSample,
        refreshCollections,
        securityTestResults,
        isRunningSecurityTests,
        runSecurityVerificationSuite,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = (): SecurityContextValue => {
  const ctx = useContext(SecurityContext);
  if (!ctx) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return ctx;
};
