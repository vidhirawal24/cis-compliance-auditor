import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Building2, ArrowRight, Plus, Shield, CheckCircle2 } from 'lucide-react';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { useAuth } from '../../auth/context';
import { DEMO_ORG_ID } from '../../fixtures/demoData';

export const OrgSelectShell: React.FC = () => {
  const { currentOrg, switchOrg, role } = useAuth();
  const navigate = useNavigate();

  const orgs = [
    {
      id: DEMO_ORG_ID,
      name: 'Acme Financial SecOps (DEMO)',
      devices: 11,
      compliance: '72.7%',
      coverage: '84.6%',
      isCurrent: currentOrg?.org_id === DEMO_ORG_ID,
    },
    {
      id: 'org-health-staging',
      name: 'Healthcare DMZ Staging',
      devices: 4,
      compliance: '91.2%',
      coverage: '95.0%',
      isCurrent: currentOrg?.org_id === 'org-health-staging',
    },
  ];

  const handleSelectOrg = (id: string) => {
    switchOrg(id);
    navigate(`/orgs/${id}/overview`);
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] flex items-center justify-center p-4">
      <div className="max-w-2xl w-full space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-white">Select Tenant Workspace</h1>
            <p className="text-xs text-slate-400">
              Each tenant workspace enforces isolated Supabase RLS and independent CIS policy baselines.
            </p>
          </div>
          <Badge variant="outline" className="gap-1.5 font-mono text-xs">
            <Shield className="w-3.5 h-3.5 text-sky-400" />
            ROLE: {role}
          </Badge>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {orgs.map((org) => (
            <Card
              key={org.id}
              className={`p-4 cursor-pointer transition-all border ${
                org.isCurrent
                  ? 'border-sky-500/80 bg-sky-950/20'
                  : 'border-slate-800 hover:border-slate-700 bg-slate-900/80'
              }`}
              onClick={() => handleSelectOrg(org.id)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="w-9 h-9 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-sky-400">
                  <Building2 className="w-4 h-4" />
                </div>
                {org.isCurrent && (
                  <Badge variant="success" className="gap-1 text-[10px]">
                    <CheckCircle2 className="w-3 h-3" /> ACTIVE
                  </Badge>
                )}
              </div>

              <h2 className="text-sm font-bold text-white mb-1">{org.name}</h2>
              <p className="text-xs text-slate-400 font-mono mb-4">ID: {org.id.slice(0, 18)}...</p>

              <div className="grid grid-cols-3 gap-2 p-2 rounded bg-black/40 border border-slate-800 text-center font-mono text-[11px] mb-4">
                <div>
                  <div className="text-slate-500 text-[10px]">ASSETS</div>
                  <div className="text-white font-bold">{org.devices}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px]">COMPLIANCE</div>
                  <div className="text-emerald-400 font-bold">{org.compliance}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px]">COVERAGE</div>
                  <div className="text-sky-400 font-bold">{org.coverage}</div>
                </div>
              </div>

              <Button
                size="sm"
                className="w-full gap-2 text-xs"
                variant={org.isCurrent ? 'default' : 'secondary'}
              >
                <span>Enter Workspace</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Button>
            </Card>
          ))}
        </div>

        {/* Empty Workspace Option */}
        <Card className="border-dashed border-slate-800 bg-slate-900/30 p-4 text-center">
          <p className="text-xs text-slate-400 mb-3">Need to audit an isolated client or branch network?</p>
          <Button variant="outline" size="sm" className="gap-2 text-xs">
            <Plus className="w-3.5 h-3.5" />
            Create New Tenant Workspace
          </Button>
        </Card>
      </div>
    </div>
  );
};

