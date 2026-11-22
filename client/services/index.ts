/**
 * KIRON PROHORI — Client Services (/client/services/index.ts)
 * Firebase Authentication/Firestore integration and zero-cost startup connection checks.
 */

export {
  db as firestoreDb,
  auth as firebaseAuth,
  googleProvider,
  isFirebaseConfigAvailable,
  provisionedProjectId,
  provisionedDatabaseId,
  OperationType,
  testConnection,
  handleFirestoreError,
} from '../../src/firebase/config';
