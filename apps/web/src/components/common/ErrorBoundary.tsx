import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';
import { Button } from '../ui/button';

interface Props {
  children: ReactNode;
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
    console.error('BaselineGuard UI Error Caught:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <main
          role="alert"
          aria-live="assertive"
          className="min-h-[300px] flex items-center justify-center p-6"
        >
          <div className="max-w-md w-full bg-slate-900 border border-red-900/60 rounded-xl p-6 text-center shadow-xl">
            <div className="w-12 h-12 bg-red-950/80 border border-red-800 rounded-xl flex items-center justify-center mx-auto mb-4 text-red-400">
              <AlertOctagon className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Component Execution Error</h2>
            <p className="text-xs text-slate-400 mb-4 font-mono bg-black/40 p-2.5 rounded border border-slate-800 text-left overflow-auto max-h-28">
              {this.state.error?.message || 'An unexpected rendering error occurred.'}
            </p>
            <Button
              onClick={() => this.setState({ hasError: false, error: null })}
              variant="outline"
              size="sm"
              className="gap-2"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Try Recovering View
            </Button>
          </div>
        </main>
      );
    }

    return this.props.children;
  }
}

