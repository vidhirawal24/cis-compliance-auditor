import React from 'react';
import { NavLink, useParams } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Server,
  Radar,
  BookOpen,
  FileCheck2,
  AlertCircle,
  Network,
  Flame,
  ListTree,
  FlaskConical,
  ShieldAlert,
  CheckCheck,
  FileText,
  Bell,
  Settings,
} from 'lucide-react';
import { useAuth } from '../../auth/context';
import { UserRole } from '../../contracts/v1/enums';
import { cn } from '../../lib/utils';

export interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  allowedRoles?: UserRole[];
  badge?: string;
  badgeVariant?: 'critical' | 'warning' | 'info';
}

export const Sidebar: React.FC<{ onCloseMobile?: () => void }> = ({ onCloseMobile }) => {
  const { orgId } = useParams<{ orgId: string }>();
  const { role } = useAuth();
  const currentOrgId = orgId || 'default-org';

  const navItems: NavItem[] = [
    {
      name: 'Overview',
      href: `/orgs/${currentOrgId}/overview`,
      icon: LayoutDashboard,
    },
    {
      name: 'Asset Inventory',
      href: `/orgs/${currentOrgId}/assets`,
      icon: Server,
      badge: '11',
    },
    {
      name: 'Scan Center',
      href: `/orgs/${currentOrgId}/scans`,
      icon: Radar,
    },
    {
      name: 'Policy Library',
      href: `/orgs/${currentOrgId}/policies`,
      icon: BookOpen,
    },
    {
      name: 'Findings Explorer',
      href: `/orgs/${currentOrgId}/findings`,
      icon: AlertCircle,
      badge: '7',
      badgeVariant: 'critical',
    },
    {
      name: 'Exceptions & Reviews',
      href: `/orgs/${currentOrgId}/exceptions`,
      icon: FileCheck2,
    },
    {
      name: 'Security Graph',
      href: `/orgs/${currentOrgId}/graph`,
      icon: Network,
    },
    {
      name: 'Risk Scenarios',
      href: `/orgs/${currentOrgId}/risk-scenarios`,
      icon: Flame,
      badge: '1 High',
      badgeVariant: 'warning',
    },
    {
      name: 'Remediation Planner',
      href: `/orgs/${currentOrgId}/planner`,
      icon: ListTree,
      allowedRoles: [UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER],
    },
    {
      name: 'What-If Simulator',
      href: `/orgs/${currentOrgId}/simulator`,
      icon: FlaskConical,
      allowedRoles: [UserRole.OWNER, UserRole.ADMIN, UserRole.OPERATOR, UserRole.APPROVER],
    },
    {
      name: 'Approvals & Hardening',
      href: `/orgs/${currentOrgId}/approvals`,
      icon: ShieldAlert,
      badge: '1 Pending',
      badgeVariant: 'warning',
      allowedRoles: [UserRole.OWNER, UserRole.ADMIN, UserRole.APPROVER, UserRole.OPERATOR],
    },
    {
      name: 'Verification & Proof',
      href: `/orgs/${currentOrgId}/verifications`,
      icon: CheckCheck,
      allowedRoles: [UserRole.OWNER, UserRole.ADMIN, UserRole.AUDITOR, UserRole.APPROVER],
    },
    {
      name: 'Reports & Drift',
      href: `/orgs/${currentOrgId}/reports`,
      icon: FileText,
    },
    {
      name: 'Notifications',
      href: `/orgs/${currentOrgId}/notifications`,
      icon: Bell,
    },
    {
      name: 'Admin & Security',
      href: `/orgs/${currentOrgId}/admin/users`,
      icon: Settings,
      allowedRoles: [UserRole.OWNER, UserRole.ADMIN],
    },
    { name: 'System States', href: `/orgs/${currentOrgId}/system-states`, icon: Settings, allowedRoles: [UserRole.OWNER, UserRole.ADMIN] },
  ];

  // Filter items based on current active role
  const visibleItems = navItems.filter((item) => {
    if (!item.allowedRoles) return true;
    return item.allowedRoles.includes(role);
  });

  return (
    <aside
      aria-label="Main Navigation"
      className="w-64 h-full bg-[#0e1420] border-r border-slate-800 flex flex-col justify-between shrink-0 select-none"
    >
      {/* Brand Header */}
      <div>
        <div className="h-14 px-4 flex items-center gap-3 border-b border-slate-800">
          <div className="w-8 h-8 rounded-lg bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400">
            <Shield className="w-5 h-5" />
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-bold tracking-wider text-white uppercase font-mono">
              BaselineGuard
            </span>
            <span className="text-[10px] text-slate-400 font-mono">
              v1.0.0-DEMO
            </span>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1 overflow-y-auto max-h-[calc(100vh-140px)]" aria-label="Sidebar Sections">
          {visibleItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.name}
                to={item.href}
                onClick={onCloseMobile}
                className={({ isActive }) =>
                  cn(
                    'flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors group',
                    isActive
                      ? 'bg-sky-950/80 text-sky-300 border border-sky-800/80 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  )
                }
              >
                <div className="flex items-center gap-2.5">
                  <Icon className="w-4 h-4 text-slate-400 group-hover:text-slate-200" />
                  <span>{item.name}</span>
                </div>

                {item.badge && (
                  <span
                    className={cn(
                      'text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold',
                      item.badgeVariant === 'critical' && 'bg-rose-950 text-rose-300 border border-rose-800',
                      item.badgeVariant === 'warning' && 'bg-amber-950 text-amber-300 border border-amber-800',
                      (!item.badgeVariant || item.badgeVariant === 'info') && 'bg-slate-800 text-slate-300'
                    )}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Role Indicator Footer */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/40">
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-500 font-mono text-[11px]">ACTIVE ROLE:</span>
          <span className="font-mono text-[11px] font-bold text-sky-400 uppercase bg-sky-950/60 px-1.5 py-0.5 rounded border border-sky-800/60">
            {role}
          </span>
        </div>
      </div>
    </aside>
  );
};

