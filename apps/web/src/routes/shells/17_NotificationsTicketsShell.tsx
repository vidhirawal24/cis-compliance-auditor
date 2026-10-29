import React, { useState } from 'react';
import { Bell, Ticket, AlertTriangle } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';

export const NotificationsTicketsShell: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'ALERTS' | 'WEBHOOKS' | 'TICKETS'>('ALERTS');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Bell className="w-5 h-5 text-sky-400" />
            Alerts & Integration Delivery (E26, E27)
          </h1>
          <p className="text-xs text-slate-400">
            Real-time webhook events, retry policies, and automated ticketing integrations.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('ALERTS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'ALERTS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          System Notifications & Alerts
        </button>
        <button
          onClick={() => setActiveTab('WEBHOOKS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'WEBHOOKS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Webhook Endpoints (E26)
        </button>
        <button
          onClick={() => setActiveTab('TICKETS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'TICKETS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Jira / ServiceNow Sync (E27)
        </button>
      </div>

      {/* Alerts Tab */}
      {activeTab === 'ALERTS' && (
        <div className="space-y-3">
          <Card className="border-slate-800 bg-slate-900/90 p-4 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">Critical Finding: Wildcard ACL Detected on ASA Perimeter</span>
                <span className="text-slate-500 font-mono text-[11px]">10 mins ago</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Control CIS-CISCO-ASA-1.3.4 failed evaluation during automated daily midnight scan.
              </p>
            </div>
          </Card>
        </div>
      )}

      {/* Webhooks Tab */}
      {activeTab === 'WEBHOOKS' && (
        <Card className="border-slate-800 bg-slate-900/90 p-4 space-y-4">
          <CardHeader className="p-0 pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-semibold">Configured Webhook Endpoints</CardTitle>
            <Button size="sm" variant="outline" className="text-xs">Add Webhook</Button>
          </CardHeader>
          <CardContent className="p-0 space-y-3 text-xs font-mono">
            <div className="p-3 bg-black/40 rounded border border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-white font-bold">https://events.acmefinancial.com/secops-webhook</div>
                <div className="text-slate-500 text-[11px]">Events: scan.completed, finding.created, drift.detected</div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="success" className="text-[10px]">HEALTHY (200 OK)</Badge>
                <Button size="sm" variant="ghost" className="h-6 text-[10px]">Test Ping</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tickets Tab */}
      {activeTab === 'TICKETS' && (
        <Card className="border-slate-800 bg-slate-900/90 p-4 space-y-4">
          <CardHeader className="p-0 pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Ticket className="w-4 h-4 text-sky-400" />
              ITSM & Ticket Synchronization (E27)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-3 text-xs">
            <div className="p-3 bg-black/40 rounded border border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-white font-semibold font-mono">Jira Software Cloud (SEC-PROJECT)</div>
                <div className="text-slate-400 text-[11px]">Auto-creates issues for CRITICAL and HIGH severity findings.</div>
              </div>
              <Badge variant="success" className="text-[10px] font-mono">SYNCED</Badge>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

