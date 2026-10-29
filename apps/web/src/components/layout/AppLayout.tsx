import React, { useState, useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { MobileNav } from './MobileNav';
import { ErrorBoundary } from '../common/ErrorBoundary';
import { WifiOff } from 'lucide-react';
import { ScreenDataBoundary } from '../common/ScreenDataBoundary';
import { useAuth } from '../../auth/context';
import { useApi } from '../../api/context';
import { DemoApiClient } from '../../api/client';

export const AppLayout: React.FC = () => {
  const { isDemoSession } = useAuth();
  const api = useApi();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  if (!isDemoSession && api instanceof DemoApiClient) return <main><h1>Production data unavailable</h1><p role="alert">UNSUPPORTED: no production adapter is configured. DEMO fallback is disabled.</p></main>;

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col antialiased">
      {/* Offline Alert Banner */}
      {!isOnline && (
        <div
          role="status"
          className="bg-amber-950/90 text-amber-200 border-b border-amber-800 px-4 py-2 text-xs flex items-center justify-center gap-2 select-none sticky top-0 z-50 backdrop-blur-md"
        >
          <WifiOff className="w-4 h-4 text-amber-400" />
          <span>Network disconnected. Requests may fail; no production fallback is enabled.</span>
        </div>
      )}

      <div className="flex-1 flex overflow-hidden">
        {/* Desktop Sidebar */}
        <div className="hidden lg:block shrink-0">
          <Sidebar />
        </div>

        {/* Mobile Navigation Drawer */}
        <MobileNav isOpen={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />

        {/* Main Content Viewport */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Topbar onOpenMobileNav={() => setMobileNavOpen(true)} />

          <main
            id="main-content"
            className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl w-full mx-auto"
          >
            <ErrorBoundary>
              <ScreenDataBoundary><Outlet /></ScreenDataBoundary>
            </ErrorBoundary>
          </main>
        </div>
      </div>
    </div>
  );
};

