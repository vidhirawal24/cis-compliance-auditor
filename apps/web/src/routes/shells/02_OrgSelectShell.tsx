import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Building2, ArrowRight, Plus, Shield, CheckCircle2, Lock, X } from 'lucide-react';
import { Card } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { useAuth } from '../../auth/context';
import { useApi } from '../../api/context';
import { orgCreateFormSchema } from '../../contracts/v1/schemas';

type OrgCreateFormData = z.infer<typeof orgCreateFormSchema>;

export const OrgSelectShell: React.FC = () => {
  const { currentOrg, switchOrg, role, userOrgs } = useAuth();
  const api = useApi();
  const navigate = useNavigate();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<OrgCreateFormData>({
    resolver: zodResolver(orgCreateFormSchema),
    defaultValues: {
      name: '',
      slug: '',
    },
  });

  const handleSelectOrg = (id: string) => {
    switchOrg(id);
    navigate(`/orgs/${id}/overview`);
  };

  const handleCreateOrg = async (data: OrgCreateFormData) => {
    try {
      setCreateError(null);
      const res = await api.createOrganization({ name: data.name, slug: data.slug });
      setShowCreateModal(false);
      reset();
      handleSelectOrg(res.data.org_id);
    } catch (err: unknown) {
      setCreateError((err as Error)?.message || 'Failed to create workspace.');
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] flex items-center justify-center p-4">
      <div className="max-w-3xl w-full space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Building2 className="w-5 h-5 text-sky-400" />
              Select Tenant Workspace
            </h1>
            <p className="text-xs text-slate-400">
              Multi-tenant architecture enforces isolated Supabase RLS and independent CIS benchmark baselines (M34).
            </p>
          </div>
          <Badge variant="outline" className="gap-1.5 font-mono text-xs w-fit">
            <Shield className="w-3.5 h-3.5 text-sky-400" />
            ROLE: {role}
          </Badge>
        </div>

        {/* Organization Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {userOrgs.map((org) => {
            const isCurrent = currentOrg?.org_id === org.org_id;
            return (
              <Card
                key={org.org_id}
                className={`p-5 transition-all border ${
                  isCurrent
                    ? 'border-sky-500/80 bg-sky-950/20 shadow-lg shadow-sky-950/30'
                    : 'border-slate-800 hover:border-slate-700 bg-slate-900/80'
                }`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-9 h-9 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-sky-400">
                    <Building2 className="w-4 h-4" />
                  </div>
                  {isCurrent && (
                    <Badge variant="success" className="gap-1 text-[10px]">
                      <CheckCircle2 className="w-3 h-3" /> ACTIVE WORKSPACE
                    </Badge>
                  )}
                </div>

                <h2 className="text-sm font-bold text-white mb-1">{org.name}</h2>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mb-4">
                  <span>ID: {org.org_id.slice(0, 16)}...</span>
                  <span>•</span>
                  <span className="capitalize">{org.role}</span>
                </div>

                <div className="grid grid-cols-3 gap-2 p-2 rounded bg-black/40 border border-slate-800 text-center font-mono text-[11px] mb-4">
                  <div>
                    <div className="text-slate-500 text-[10px]">PLATFORMS</div>
                    <div className="text-white font-bold">CIS Network</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[10px]">ISOLATION</div>
                    <div className="text-emerald-400 font-bold">RLS Guarded</div>
                  </div>
                  <div>
                    <div className="text-slate-500 text-[10px]">VAULT</div>
                    <div className="text-sky-400 font-bold">OpenBao</div>
                  </div>
                </div>

                <Button
                  onClick={() => handleSelectOrg(org.org_id)}
                  size="sm"
                  className="w-full gap-2 text-xs"
                  variant={isCurrent ? 'default' : 'secondary'}
                >
                  <span>Enter Workspace</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Button>
              </Card>
            );
          })}
        </div>

        {/* Create Workspace Trigger */}
        <Card className="border-dashed border-slate-800 bg-slate-900/30 p-5 text-center">
          <p className="text-xs text-slate-400 mb-3">
            Need an isolated compliance tenant for another client or data boundary?
          </p>
          <Button
            onClick={() => setShowCreateModal(true)}
            variant="outline"
            size="sm"
            className="gap-2 text-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            Create New Tenant Workspace
          </Button>
        </Card>

        {/* Modal: Create Tenant Workspace */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
            <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl relative">
              <button
                onClick={() => setShowCreateModal(false)}
                className="absolute top-4 right-4 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-2 mb-4">
                <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
                  <Building2 className="w-4 h-4" />
                </div>
                <h3 className="text-base font-bold text-white">New Compliance Workspace</h3>
              </div>

              {createError && (
                <div className="mb-4 p-2.5 bg-red-950/80 border border-red-800 rounded text-xs text-red-300">
                  {createError}
                </div>
              )}

              <form onSubmit={handleSubmit(handleCreateOrg)} className="space-y-4" noValidate>
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Workspace / Organization Name</label>
                  <Input
                    placeholder="e.g. Acme Corp EMEA Infrastructure"
                    {...register('name')}
                    aria-invalid={!!errors.name}
                    className="h-8 text-xs"
                  />
                  {errors.name && (
                    <p className="text-[11px] text-red-400">{errors.name.message}</p>
                  )}
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Tenant Slug (URL Identifier)</label>
                  <Input
                    placeholder="e.g. acme-corp-emea"
                    {...register('slug')}
                    aria-invalid={!!errors.slug}
                    className="h-8 text-xs font-mono"
                  />
                  {errors.slug && (
                    <p className="text-[11px] text-red-400">{errors.slug.message}</p>
                  )}
                  <p className="text-[10px] text-slate-500 font-mono">
                    Must contain only lowercase letters, digits, and hyphens.
                  </p>
                </div>

                <div className="p-3 bg-black/40 border border-slate-800 rounded text-[11px] text-slate-400 space-y-1">
                  <div className="flex items-center gap-1.5 font-semibold text-slate-300">
                    <Lock className="w-3 h-3 text-sky-400" />
                    <span>Tenant Boundary Guarantee (M34)</span>
                  </div>
                  <p>
                    All asset records, audit scans, and configuration archives created inside this workspace are isolated by Supabase Row-Level Security.
                  </p>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowCreateModal(false)}
                    className="text-xs"
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    disabled={isSubmitting}
                    size="sm"
                    className="text-xs gap-1.5"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    {isSubmitting ? 'Provisioning...' : 'Provision Workspace'}
                  </Button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
