import React, { useState } from 'react';
import { Settings, Key, ShieldCheck } from 'lucide-react';
import { Card, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { fixtureStore } from '../../api/store';
import { UserRole } from '../../contracts/v1/enums';

export const AdminSecurityShell: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'USERS' | 'VAULT' | 'AUDIT_LOGS'>('USERS');
  const auditLogs = fixtureStore.auditEvents;

  const users = [
    { email: 'apoorva.lead@baselineguard.local', role: UserRole.OWNER, mfa: true },
    { email: 'ciso@acmefinancial.com', role: UserRole.APPROVER, mfa: true },
    { email: 'operator@acmefinancial.com', role: UserRole.OPERATOR, mfa: true },
    { email: 'auditor.external@pwc-audit.local', role: UserRole.AUDITOR, mfa: true },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Settings className="w-5 h-5 text-sky-400" />
            Administration & Security Governance (E15, E16, E17, E19)
          </h1>
          <p className="text-xs text-slate-400">
            Tenant access control, OpenBao vault secret pointers, and immutable application activity trail.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('USERS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'USERS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Users & RBAC (E15, E16)
        </button>
        <button
          onClick={() => setActiveTab('VAULT')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'VAULT'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          OpenBao Vault Pointers (E17)
        </button>
        <button
          onClick={() => setActiveTab('AUDIT_LOGS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors ${
            activeTab === 'AUDIT_LOGS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Application Audit Trail (E19)
        </button>
      </div>

      {/* Users Tab */}
      {activeTab === 'USERS' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>User Email</TableHead>
                <TableHead>Assigned Role (E15)</TableHead>
                <TableHead>MFA Enforced (E16)</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => (
                <TableRow key={u.email}>
                  <TableCell className="font-mono text-white">{u.email}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px] text-sky-300 border-sky-800">
                      {u.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 font-semibold">
                      <ShieldCheck className="w-3.5 h-3.5" /> TOTP ACTIVE
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" className="h-6 text-[10px]">Edit Role</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Vault Pointers Tab */}
      {activeTab === 'VAULT' && (
        <Card className="border-slate-800 bg-slate-900/90 p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-400" />
              OpenBao Credential References (Zero Plaintext Invariant - E17)
            </CardTitle>
            <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-800 font-mono">
              VAULT SEALED & AUTHENTICATED
            </Badge>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            The frontend interface and audit database store only immutable pointer IDs. No plaintext passwords, SSH private keys, or API tokens are transmitted to the browser client.
          </p>
          <div className="space-y-2 text-xs font-mono">
            <div className="p-2.5 bg-black/40 rounded border border-slate-800 flex justify-between">
              <span className="text-slate-300">vault:secret/cisco-asa-ssh</span>
              <span className="text-slate-500">Target: DEMO-ASA5525-VPN (SSH Key ID: #9901)</span>
            </div>
            <div className="p-2.5 bg-black/40 rounded border border-slate-800 flex justify-between">
              <span className="text-slate-300">vault:secret/fortigate-api-token</span>
              <span className="text-slate-500">Target: DEMO-FG100F-PERIMETER (REST Token ID: #9902)</span>
            </div>
          </div>
        </Card>
      )}

      {/* Audit Logs Tab */}
      {activeTab === 'AUDIT_LOGS' && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
          <Table className="table-compact">
            <TableHeader>
              <TableRow>
                <TableHead>Event ID</TableHead>
                <TableHead>Actor Email</TableHead>
                <TableHead>Action Type</TableHead>
                <TableHead>Target Resource</TableHead>
                <TableHead>Timestamp (UTC)</TableHead>
                <TableHead>Integrity Hash</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {auditLogs.map((evt) => (
                <TableRow key={evt.event_id}>
                  <TableCell className="font-mono text-slate-400">{evt.event_id}</TableCell>
                  <TableCell className="font-mono text-white">{evt.actor_email}</TableCell>
                  <TableCell>
                    <span className="font-mono text-[10px] uppercase font-bold text-sky-400">
                      {evt.action_type}
                    </span>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{evt.target_resource_id}</TableCell>
                  <TableCell className="font-mono text-xs text-slate-400">{evt.timestamp}</TableCell>
                  <TableCell className="font-mono text-xs text-slate-500">{evt.sha256_hash}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
};

