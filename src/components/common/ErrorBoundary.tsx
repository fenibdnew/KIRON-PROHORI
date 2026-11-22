import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';
import { Language } from '../../types/navigation';
import { TRANSLATIONS } from '../../i18n/translations';

interface Props {
  children: ReactNode;
  language: Language;
  onReset?: () => void;
  resetKey?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[KIRON PROHORI ErrorBoundary]:', error, errorInfo);
  }

  public componentDidUpdate(prevProps: Props) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.hasError) {
      this.setState({ hasError: false, error: null });
    }
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      const strings = TRANSLATIONS[this.props.language].errorBoundary;
      return (
        <div
          role="alert"
          className="my-6 rounded-lg border border-rose-800/80 bg-[#0E1628] p-6 text-slate-100"
        >
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-rose-800/60 bg-rose-950/60 text-rose-300">
              <AlertTriangle className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="flex-1 space-y-3">
              <div>
                <h2 className="text-lg font-semibold text-slate-100">{strings.title}</h2>
                <p className="mt-1 text-sm text-slate-400">{strings.subtitle}</p>
              </div>

              {this.state.error && (
                <div className="rounded-md border border-[#1E2D4A] bg-[#080D1A] p-3.5">
                  <div className="text-xs font-medium text-slate-400">
                    {strings.technicalDetails}
                  </div>
                  <pre className="mt-1.5 overflow-x-auto font-mono text-xs text-rose-300">
                    {this.state.error.name}: {this.state.error.message}
                  </pre>
                </div>
              )}

              <div className="pt-2">
                <button
                  type="button"
                  onClick={this.handleReset}
                  className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-500"
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{strings.resetButton}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
