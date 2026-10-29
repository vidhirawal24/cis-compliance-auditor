import React, { useState } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  HelpCircle,
  WifiOff,
  Inbox,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { Button } from '../../components/ui/button';
import { EmptyState } from '../../components/common/EmptyState';
import { LoadingSkeleton } from '../../components/common/LoadingSkeleton';

export const SystemStatesShell: React.FC = () => {
  const [selectedState, setSelectedState] = useState<
    'LOADING' | 'EMPTY' | '403' | '404' | '500' | 'OFFLINE' | 'UNSUPPORTED' | 'PARTIAL_SCAN'
  >('LOADING');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-sky-400" />
            System States & Edge Case Gallery (10 Standardized States)
          </h1>
          <p className="text-xs text-slate-400">
            Interactive showcase of error handling, accessibility boundaries, and stateful resiliency.
          </p>
        </div>

        {/* State Toggle Buttons */}
        <div className="flex flex-wrap items-center gap-1.5 bg-slate-900 p-1.5 rounded-lg border border-slate-800 text-xs">
          {(
            ['LOADING', 'EMPTY', '403', '404', '500', 'OFFLINE', 'UNSUPPORTED', 'PARTIAL_SCAN'] as const
          ).map((st) => (
            <button
              key={st}
              onClick={() => setSelectedState(st)}
              className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                selectedState === st
                  ? 'bg-sky-600 text-white font-bold'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* State Renderers */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 min-h-[400px] flex items-center justify-center">
        {selectedState === 'LOADING' && (
          <div className="w-full max-w-2xl space-y-4">
            <div className="text-xs text-slate-400 font-mono mb-2">Skeleton Loading Simulation:</div>
            <LoadingSkeleton type="cards" />
            <LoadingSkeleton type="table" rows={4} />
          </div>
        )}

        {selectedState === 'EMPTY' && (
          <EmptyState
            icon={Inbox}
            title="No Non-Compliant Findings Found"
            description="All automated controls evaluated in the selected baseline passed verification."
            action={{
              label: 'Launch New Scan',
              onClick: () => {},
            }}
          />
        )}

        {selectedState === '403' && (
          <div className="max-w-md w-full bg-slate-900 border border-red-900/60 rounded-xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-red-950/80 border border-red-800 rounded-xl flex items-center justify-center mx-auto mb-4 text-red-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Access Denied (403 Forbidden)</h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              Viewer role does not have authorization to trigger configuration mutations or approve remediation plans.
            </p>
            <Button size="sm" variant="outline">Request Elevated Permissions</Button>
          </div>
        )}

        {selectedState === '404' && (
          <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-slate-800 border border-slate-700 rounded-xl flex items-center justify-center mx-auto mb-4 text-slate-400">
              <HelpCircle className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Resource Not Found (404)</h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              The requested asset identifier or finding reference does not exist in the tenant catalog.
            </p>
            <Button size="sm">Return to Overview</Button>
          </div>
        )}

        {selectedState === '500' && (
          <div className="max-w-md w-full bg-slate-900 border border-red-900/60 rounded-xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-red-950 border border-red-800 rounded-xl flex items-center justify-center mx-auto mb-4 text-red-400">
              <AlertOctagon className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Internal Service Exception (500)</h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              The backend evaluator encountered an unhandled parsing anomaly. A failure trace was isolated.
            </p>
            <Button size="sm" variant="outline" className="gap-2">
              <RotateCcw className="w-3.5 h-3.5" /> Retry Request
            </Button>
          </div>
        )}

        {selectedState === 'OFFLINE' && (
          <div className="max-w-md w-full bg-slate-900 border border-amber-900/60 rounded-xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-amber-950 border border-amber-800 rounded-xl flex items-center justify-center mx-auto mb-4 text-amber-400">
              <WifiOff className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Network Disconnected</h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              You are currently working offline. Cached synthetic demo data remains accessible locally.
            </p>
            <Button size="sm" variant="outline">Check Connectivity</Button>
          </div>
        )}

        {selectedState === 'UNSUPPORTED' && (
          <div className="max-w-md w-full bg-slate-900 border border-purple-900/60 rounded-xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-purple-950 border border-purple-800 rounded-xl flex items-center justify-center mx-auto mb-4 text-purple-400">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Unsupported Appliance Firmware</h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              Target firmware is not supported by the certified CIS evaluator pack. Result marked NOT_ASSESSED.
            </p>
            <Button size="sm" variant="outline">Consult Platform Matrix</Button>
          </div>
        )}

        {selectedState === 'PARTIAL_SCAN' && (
          <div className="max-w-md w-full bg-slate-900 border border-amber-900/60 rounded-xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-amber-950 border border-amber-800 rounded-xl flex items-center justify-center mx-auto mb-4 text-amber-400">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h2 className="text-base font-bold text-white mb-2">Partial Audit Completed</h2>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              1 target host timed out during WinRM collection. Assessed compliance reflects 10 verified hosts.
            </p>
            <Button size="sm" variant="outline">View Error Manifest</Button>
          </div>
        )}
      </div>
    </div>
  );
};

