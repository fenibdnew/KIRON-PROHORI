import React from 'react';
import {
  Unplug,
  FlaskConical,
  CheckCircle2,
  RefreshCw,
  AlertTriangle,
  Clock,
  KeyRound,
} from 'lucide-react';
import { DataStatus } from '../../types/navigation';
import { useApp } from '../../context/AppContext';

interface StatusTagProps {
  status: DataStatus;
  customLabel?: string;
}

/**
 * Accessible semantic status indicator pairing explicit icon + text label.
 * Uses only honest statuses: CONNECTED, NOT CONFIGURED, NOT CONNECTED, SYNCING, ERROR, STALE DATA, DEMO, LOCAL READY.
 * Never displays fake LIVE status.
 */
export const StatusTag: React.FC<StatusTagProps> = ({ status, customLabel }) => {
  const { t } = useApp();

  if (status === 'CONNECTED') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-emerald-300 whitespace-nowrap shrink-0">
        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
        <span>{customLabel || 'CONNECTED'}</span>
      </span>
    );
  }

  if (status === 'NOT_CONFIGURED') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-amber-300 whitespace-nowrap shrink-0">
        <KeyRound className="h-3.5 w-3.5 text-amber-400 shrink-0" aria-hidden="true" />
        <span>{customLabel || 'NOT CONFIGURED'}</span>
      </span>
    );
  }

  if (status === 'SYNCING') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-blue-300 whitespace-nowrap shrink-0">
        <RefreshCw className="h-3.5 w-3.5 text-blue-400 animate-spin shrink-0" aria-hidden="true" />
        <span>{customLabel || 'SYNCING'}</span>
      </span>
    );
  }

  if (status === 'ERROR') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-rose-300 whitespace-nowrap shrink-0">
        <AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0" aria-hidden="true" />
        <span>{customLabel || 'ERROR'}</span>
      </span>
    );
  }

  if (status === 'STALE_DATA') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-amber-300 whitespace-nowrap shrink-0">
        <Clock className="h-3.5 w-3.5 text-amber-400 shrink-0" aria-hidden="true" />
        <span>{customLabel || 'STALE DATA'}</span>
      </span>
    );
  }

  if (status === 'NOT_CONNECTED') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-amber-300 whitespace-nowrap shrink-0">
        <Unplug className="h-3.5 w-3.5 text-amber-400 shrink-0" aria-hidden="true" />
        <span>{customLabel || t.statusNotConnected || 'NOT CONNECTED'}</span>
      </span>
    );
  }

  if (status === 'DEMO') {
    return (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-blue-300 whitespace-nowrap shrink-0">
        <FlaskConical className="h-3.5 w-3.5 text-blue-400 shrink-0" aria-hidden="true" />
        <span>{customLabel || t.statusDemo}</span>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs font-medium text-emerald-300 whitespace-nowrap shrink-0">
      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" aria-hidden="true" />
      <span>{customLabel || t.statusLocalReady}</span>
    </span>
  );
};
