import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Building2,
  Search,
  Bell,
  Menu,
  ShieldAlert,
  LogOut,
  ChevronDown,
} from 'lucide-react';
import { useAuth } from '../../auth/context';
import { UserRole } from '../../contracts/v1/enums';
import { Button } from '../ui/button';

export interface TopbarProps {
  onOpenMobileNav: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onOpenMobileNav }) => {
  const { currentOrg, role, setRole, user, logout } = useAuth();
  const navigate = useNavigate();
  const { orgId } = useParams<{ orgId: string }>();

  return (
    <header className="h-14 bg-[#0e1420]/90 backdrop-blur-md border-b border-slate-800 px-4 flex items-center justify-between gap-4 sticky top-0 z-40">
      {/* Left: Mobile Nav Button + Org Context Picker */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobileNav}
          className="lg:hidden p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800"
          aria-label="Open navigation drawer"
        >
          <Menu className="w-5 h-5" />
        </button>

        <button
          onClick={() => navigate('/orgs')}
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs font-medium text-slate-200 transition-colors"
          title="Switch Tenant Organization"
        >
          <Building2 className="w-4 h-4 text-sky-400" />
          <span className="font-semibold">{currentOrg?.name || 'Acme Financial SecOps'}</span>
          <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
        </button>
      </div>

      {/* Center: Global Search Bar (E29) */}
      <div className="hidden md:flex items-center flex-1 max-w-md relative">
        <Search className="w-4 h-4 text-slate-400 absolute left-3 pointer-events-none" />
        <input
          type="search"
          placeholder="Search controls, hostnames, findings, CVEs, or subnets (Ctrl+K)..."
          className="w-full h-8 pl-9 pr-14 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500 transition-all"
        />
        <kbd className="absolute right-2 px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-800 rounded border border-slate-700 pointer-events-none">
          ⌘K
        </kbd>
      </div>

      {/* Right: Role Switcher (DEMO / Testing) + Notifications + User Menu */}
      <div className="flex items-center gap-3">
        {/* Role Selector Dropdown for Role-Aware Testing */}
        <div className="flex items-center gap-1.5 bg-slate-900 px-2 py-1 rounded-md border border-slate-800 text-xs">
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-slate-400 hidden sm:inline text-[11px]">Role:</span>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="bg-transparent text-white font-mono text-xs focus:outline-none cursor-pointer"
            aria-label="Switch Active Role"
          >
            <option value={UserRole.OWNER} className="bg-slate-900 text-white">OWNER</option>
            <option value={UserRole.ADMIN} className="bg-slate-900 text-white">ADMIN</option>
            <option value={UserRole.APPROVER} className="bg-slate-900 text-white">APPROVER</option>
            <option value={UserRole.OPERATOR} className="bg-slate-900 text-white">OPERATOR</option>
            <option value={UserRole.AUDITOR} className="bg-slate-900 text-white">AUDITOR</option>
            <option value={UserRole.VIEWER} className="bg-slate-900 text-white">VIEWER</option>
          </select>
        </div>

        {/* Notifications Icon */}
        <button
          onClick={() => navigate(`/orgs/${orgId || 'default'}/notifications`)}
          className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 relative"
          aria-label="View system alerts"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-sky-500 ring-2 ring-[#0e1420]" />
        </button>

        {/* User Identity & Logout */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-7 h-7 rounded-full bg-sky-950 border border-sky-800 flex items-center justify-center text-sky-400 font-mono text-xs font-bold">
            {user?.email ? user.email.charAt(0).toUpperCase() : 'A'}
          </div>
          <Button
            onClick={() => {
              logout();
              navigate('/auth/login');
            }}
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-slate-400 hover:text-rose-400"
            title="Sign Out"
          >
            <LogOut className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>
    </header>
  );
};

