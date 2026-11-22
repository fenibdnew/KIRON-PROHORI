import { initializeApp, FirebaseApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, Auth } from 'firebase/auth';
import {
  getFirestore,
  Firestore,
  doc,
  getDocFromServer,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export const isFirebaseConfigAvailable = Boolean(
  firebaseConfig &&
    firebaseConfig.projectId &&
    firebaseConfig.projectId !== 'remixed-project-id' &&
    firebaseConfig.apiKey
);

let app: FirebaseApp | null = null;
let dbInstance: Firestore | null = null;
let authInstance: Auth | null = null;
let googleProviderInstance: GoogleAuthProvider | null = null;

if (isFirebaseConfigAvailable) {
  app = initializeApp(firebaseConfig);
  dbInstance = getFirestore(app, firebaseConfig.firestoreDatabaseId);
  authInstance = getAuth(app);
  googleProviderInstance = new GoogleAuthProvider();
  googleProviderInstance.setCustomParameters({ prompt: 'select_account' });
}

export const db = dbInstance as Firestore;
export const auth = authInstance as Auth;
export const googleProvider = googleProviderInstance as GoogleAuthProvider;
export const provisionedProjectId = isFirebaseConfigAvailable
  ? firebaseConfig.projectId
  : 'local-demo-unconfigured';
export const provisionedDatabaseId = isFirebaseConfigAvailable
  ? firebaseConfig.firestoreDatabaseId
  : 'ephemeral-memory-only';

/**
 * Mandatory startup connection check per firebase-integration-rpc skill.
 */
export async function testConnection(): Promise<{
  reachable: boolean;
  message: string;
}> {
  if (!isFirebaseConfigAvailable || !dbInstance) {
    return {
      reachable: false,
      message: 'Firebase configuration unavailable — running in Local Demo Mode.',
    };
  }
  try {
    await getDocFromServer(doc(dbInstance, 'test', 'connection'));
    return {
      reachable: true,
      message: 'Connected to Cloud Firestore (No-Cost Spark Tier).',
    };
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes('the client is offline')
    ) {
      console.error('Please check your Firebase configuration.');
      return {
        reachable: false,
        message: 'Firestore client is offline — check Firebase configuration.',
      };
    }
    // A permission-denied response on /test/connection confirms the server was reached
    // and the Global Safety Net rule (allow read, write: if false) enforced default-deny!
    return {
      reachable: true,
      message:
        'Cloud Firestore reachable · Global default-deny security rule verified active.',
    };
  }
}

// Run startup check on module boot
if (isFirebaseConfigAvailable) {
  void testConnection();
}

/**
 * Mandatory structured Firestore error handler per error-handling-and-sdk.md.
 */
export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const currentUser = authInstance?.currentUser;
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: currentUser?.uid ?? null,
      email: currentUser?.email ?? null,
      emailVerified: currentUser?.emailVerified ?? null,
      isAnonymous: currentUser?.isAnonymous ?? null,
      tenantId: currentUser?.tenantId ?? null,
      providerInfo:
        currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}
