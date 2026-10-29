import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './context';
import { UserRole } from '../contracts/v1/enums';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

interface AuthGuardProps {
  children: React.ReactNode;
  allowedRoles?: UserRole[];
}

export const AuthGuard: React.FC<AuthGuardProps> = ({ children, allowedRoles }) => {
  const { isAuthenticated, role, currentOrg } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/auth/login" state={{ from: location }} replace />;
  }

  // If role check fails, render 403 Forbidden screen
  if (allowedRoles && !allowedRoles.includes(role)) {
    return (
      <main
        role="main"
        aria-labelledby="forbidden-title"
        className="min-h-screen bg-[#0b0f17] flex items-center justify-center p-6"
      >
        <div className="max-w-md w-full bg-slate-900/90 border border-red-900/50 rounded-xl p-8 text-center shadow-2xl backdrop-blur-md">
          <div className="w-16 h-16 bg-red-500/10 border border-red-500/30 rounded-2xl flex items-center justify-center mx-auto mb-6 text-red-400">
            <ShieldAlert className="w-8 h-8" aria-hidden="true" />
          </div>
          <span className="inline-block px-2.5 py-1 text-xs font-mono font-semibold bg-red-950 text-red-300 border border-red-800 rounded-full mb-3">
            ERROR 403 - FORBIDDEN
          </span>
          <h1 id="forbidden-title" className="text-xl font-bold text-white mb-2">
            Access Denied
          </h1>
          <p className="text-sm text-slate-400 mb-6">
            Your current assigned role (<span className="text-slate-200 font-semibold">{role}</span>) does not have
            authorization to view this resource. Contact your organization administrator to elevate your permissions.
          </p>
          <div className="flex justify-center gap-3">
            <button
              onClick={() => window.history.back()}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors focus:ring-2 focus:ring-sky-500"
            >
              <ArrowLeft className="w-4 h-4" />
              Go Back
            </button>
            <a
              href={`/orgs/${currentOrg?.org_id || 'default'}/overview`}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded-lg transition-colors focus:ring-2 focus:ring-sky-500"
            >
              Overview Dashboard
            </a>
          </div>
        </div>
      </main>
    );
  }

  return <>{children}</>;
};

