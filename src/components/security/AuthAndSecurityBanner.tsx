import React from 'react';
import {
  ShieldCheck,
  LogIn,
  LogOut,
  Database,
  FlaskConical,
  AlertTriangle,
  UserCheck,
  Lock,
  X,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { useApp } from '../../context/AppContext';
import { isFirebaseConfigAvailable } from '../../firebase/config';

export const AuthAndSecurityBanner: React.FC = () => {
  const {
    persistenceMode,
    setPersistenceMode,
    demoRolePersona,
    setDemoRolePersona,
    firebaseUser,
    userProfile,
    authoritativeRole,
    isAdmin,
    isSignedIn,
    connectionStatusMessage,
    projectId,
    signInWithGoogle,
    signOutUser,
    actionFeedback,
    clearActionFeedback,
  } = useSecurity();

  const { language } = useApp();
  const isBn = language === 'bn';
  const isDemoMode = persistenceMode === 'LOCAL_DEMO_EPHEMERAL';

  return (
    <div className="space-y-3 mb-6">
      {/* Main Auth & Database Foundation Bar */}
      <div className="rounded-lg border border-[#1E2D4A] bg-[#0E1628] p-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          {/* Left: Connection & Identity Status */}
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-blue-300">
                <Database className="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
                <span>
                  {isDemoMode
                    ? isBn
                      ? 'লোকাল ডেমো মোড (অস্থায়ী মেমোরি)'
                      : 'LOCAL DEMO MODE (EPHEMERAL)'
                    : isBn
                    ? 'সংযুক্ত ক্লাউড ফায়ারস্টোর ($০ স্পার্ক টিয়ার)'
                    : 'CONNECTED: CLOUD FIRESTORE ($0 SPARK TIER)'}
                </span>
              </span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="font-mono text-xs text-slate-400">
                Project: {projectId}
              </span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="inline-flex items-center gap-1 font-mono text-xs text-emerald-300">
                <Lock className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                <span>
                  RBAC Role:{' '}
                  {authoritativeRole.toUpperCase()}
                  {isAdmin ? ' (Verified Admin)' : ''}
                </span>
              </span>
            </div>

            <p className="text-xs text-slate-400">{connectionStatusMessage}</p>
          </div>

          {/* Right: Persistence Mode Switcher & Google Sign-In Controls */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Mode Toggle: Connected Firestore vs Clearly Labeled Local Demo */}
            <div className="flex items-center gap-1 rounded-lg border border-[#1E2D4A] bg-[#080D1A] p-1">
              <button
                type="button"
                onClick={() => setPersistenceMode('FIRESTORE_LIVE')}
                disabled={!isFirebaseConfigAvailable}
                className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  !isDemoMode
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-300 hover:bg-[#141F38] hover:text-white disabled:opacity-40'
                }`}
              >
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{isBn ? 'ক্লাউড ফায়ারস্টোর' : 'Cloud Firestore'}</span>
              </button>

              <button
                type="button"
                onClick={() => setPersistenceMode('LOCAL_DEMO_EPHEMERAL')}
                className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  isDemoMode
                    ? 'bg-amber-600 text-white'
                    : 'text-slate-300 hover:bg-[#141F38] hover:text-white'
                }`}
              >
                <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{isBn ? 'লোকাল ডেমো (অস্থায়ী)' : 'Local Demo (Not Saved)'}</span>
              </button>
            </div>

            {/* Google Auth Button or Demo Persona Switcher */}
            {!isDemoMode ? (
              firebaseUser ? (
                <div className="flex items-center gap-2">
                  <div className="hidden sm:flex items-center gap-1.5 rounded-md border border-[#1E2D4A] bg-[#080D1A] px-3 py-1.5 text-xs text-slate-200">
                    <UserCheck className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                    <span className="truncate max-w-[180px]">
                      {userProfile?.displayName || firebaseUser.email}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => void signOutUser()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[#1E2D4A] bg-[#141F38] px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-rose-500/60 hover:text-white whitespace-nowrap shrink-0"
                  >
                    <LogOut className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{isBn ? 'সাইন আউট' : 'Sign Out'}</span>
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => void signInWithGoogle()}
                  className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-3.5 py-1.5 text-xs font-medium text-white transition-colors hover:bg-blue-500 whitespace-nowrap shrink-0"
                >
                  <LogIn className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>
                    {isBn ? 'গুগল দিয়ে সাইন ইন করুন' : 'Sign in with Google'}
                  </span>
                </button>
              )
            ) : (
              <div className="flex items-center gap-1 rounded-lg border border-amber-800/70 bg-[#080D1A] p-1">
                {(['guest', 'user', 'admin'] as const).map((persona) => (
                  <button
                    key={persona}
                    type="button"
                    onClick={() => setDemoRolePersona(persona)}
                    className={`rounded-md px-2.5 py-1 font-mono text-[11px] font-medium transition-colors whitespace-nowrap shrink-0 ${
                      demoRolePersona === persona
                        ? 'bg-amber-600 text-white'
                        : 'text-slate-300 hover:text-white'
                    }`}
                  >
                    {persona === 'guest'
                      ? 'Guest [DEMO]'
                      : persona === 'user'
                      ? 'Normal User [DEMO]'
                      : 'Admin [DEMO]'}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Explicit Warning When in Local Demo Mode: Never Pretend Data Is Permanently Saved */}
      {isDemoMode && (
        <div
          role="status"
          className="flex items-start gap-3 rounded-lg border border-amber-700/80 bg-amber-950/50 px-4 py-3 text-xs text-amber-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <div className="flex-1">
            <span className="font-semibold">
              {isBn
                ? 'লোকাল ডেমো মোড সতর্কতা (স্থায়ীভাবে সংরক্ষিত নয়): '
                : 'LOCAL DEMO MODE NOTICE (NOT PERMANENTLY SAVED): '}
            </span>
            <span>
              {isBn
                ? 'আপনি বর্তমানে অস্থায়ী লোকাল ডেমো মোডে আছেন। এখানে তৈরি কোনো প্রোফাইল, ওয়াচলিস্ট বা স্ক্যাম রিপোর্ট স্থায়ীভাবে ডেটাবেসে সংরক্ষিত হয় না। স্থায়ী সংরক্ষণের জন্য "Live Firestore" নির্বাচন করে গুগল দিয়ে সাইন ইন করুন।'
                : 'You are interacting with an ephemeral in-memory demo sandbox. Records created in this mode are NOT permanently saved to Cloud Firestore. Switch to "Live Firestore" and sign in with Google for persistent storage.'}
            </span>
          </div>
        </div>
      )}

      {/* Action Feedback Banner */}
      {actionFeedback && (
        <div
          role="alert"
          className={`flex items-center justify-between gap-3 rounded-lg border px-4 py-3 text-xs ${
            actionFeedback.type === 'error'
              ? 'border-rose-800/80 bg-rose-950/60 text-rose-200'
              : actionFeedback.type === 'success'
              ? 'border-emerald-800/80 bg-emerald-950/60 text-emerald-200'
              : 'border-blue-800/80 bg-blue-950/60 text-blue-200'
          }`}
        >
          <span className="font-mono">{actionFeedback.message}</span>
          <button
            type="button"
            onClick={clearActionFeedback}
            aria-label="Dismiss notification"
            className="rounded p-1 hover:bg-white/10"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </div>
  );
};
