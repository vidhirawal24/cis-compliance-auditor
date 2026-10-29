import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserRole } from '../contracts/v1/enums';
import type { Organization } from '../contracts/v1/types';
import { DEMO_ORGANIZATION } from '../fixtures/demoData';
import { supabase } from './supabase';
import { runtimeConfig } from '../api/config';

export interface AuthUser {
  id: string;
  email: string;
  role: UserRole;
  mfaVerified: boolean;
  isDemo?: boolean;
}

export interface AuthContextType {
  user: AuthUser | null;
  currentOrg: Organization | null;
  userOrgs: Organization[];
  role: UserRole;
  isAuthenticated: boolean;
  authMode: 'DEMO' | 'SUPABASE';
  isDemoSession: boolean;
  switchOrg: (orgId: string) => void;
  setRole: (role: UserRole) => void;
  loginDemo: (email: string, role: UserRole) => void;
  loginSupabase: (email: string, password: string) => Promise<{ success: boolean; error?: string; requiresMfa?: boolean }>;
  logout: () => Promise<void>;
  resetPassword: (email: string) => Promise<{ success: boolean; message: string }>;
  enrollMfa: () => Promise<{ qrCode: string; secret: string; factorId: string }>;
  verifyMfa: (code: string) => Promise<{ success: boolean; error?: string }>;
  hasTenantAccess: (orgId: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const DEMO_USER: AuthUser = {
  id: 'usr-apoorva-secops',
  email: 'apoorva.lead@baselineguard.local',
  role: UserRole.OWNER,
  mfaVerified: true,
  isDemo: true,
};

const INITIAL_ORGS: Organization[] = [
  DEMO_ORGANIZATION,
  {
    org_id: 'org-health-staging',
    name: 'Healthcare DMZ Staging',
    slug: 'health-dmz-staging',
    created_at: '2026-02-01T00:00:00Z',
    role: UserRole.VIEWER,
    is_active: true,
  },
];

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const demoAllowed = runtimeConfig().mode === 'demo';
  const [user, setUser] = useState<AuthUser | null>(demoAllowed ? DEMO_USER : null);
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(demoAllowed ? DEMO_ORGANIZATION : null);
  const [userOrgs] = useState<Organization[]>(demoAllowed ? INITIAL_ORGS : []);
  const [role, setRoleState] = useState<UserRole>(demoAllowed ? UserRole.OWNER : UserRole.VIEWER);
  const [authMode, setAuthMode] = useState<'DEMO' | 'SUPABASE'>(demoAllowed ? 'DEMO' : 'SUPABASE');

  useEffect(() => {
    // No fabricated tenant memberships or elevated roles for a real session.
    if (!supabase) return;
    const { data: authListener } = supabase.auth.onAuthStateChange((event, session) => {
      if (session?.user && authMode === 'SUPABASE') {
        setUser({
          id: session.user.id,
          email: session.user.email || 'user@baselineguard.local',
          role: UserRole.VIEWER,
          mfaVerified: false,
          isDemo: false,
        });
      } else if (event === 'SIGNED_OUT' && authMode === 'SUPABASE') {
        setUser(null);
        setCurrentOrg(null);
      }
    });

    return () => {
      authListener.subscription.unsubscribe();
    };
  }, [authMode]);

  const hasTenantAccess = (orgId: string): boolean => {
    return userOrgs.some((org) => org.org_id === orgId);
  };

  const switchOrg = (orgId: string) => {
    const target = userOrgs.find((o) => o.org_id === orgId);
    if (!target) {
      throw new Error(`Access Denied: You do not have authorization to access tenant ${orgId}`);
    }
    setCurrentOrg(target);
    setRoleState(target.role);
  };

  const setRole = (newRole: UserRole) => {
    if (!demoAllowed || authMode !== 'DEMO') return;
    setRoleState(newRole);
    if (user) {
      setUser({ ...user, role: newRole });
    }
  };

  const loginDemo = (email: string, targetRole: UserRole) => {
    if (!demoAllowed) return;
    setAuthMode('DEMO');
    setUser({
      id: `usr-${Date.now()}`,
      email,
      role: targetRole,
      mfaVerified: true,
      isDemo: true,
    });
    setRoleState(targetRole);
    setCurrentOrg(DEMO_ORGANIZATION);
  };

  const loginSupabase = async (email: string, password: string) => {
    try {
      if (!supabase) return { success: false, error: 'Supabase is not configured. No DEMO fallback is enabled.' };
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) {
        return {
          success: false,
          error: error.message || 'Supabase authentication failed. Ensure credentials are valid or use Demo Quick Sign-In.',
        };
      }
      setAuthMode('SUPABASE');
      setUser({
        id: data.user.id,
        email: data.user.email || email,
        role: UserRole.VIEWER,
        mfaVerified: false, // Requires MFA verification
        isDemo: false,
      });
      return { success: true, requiresMfa: true };
    } catch (err: unknown) {
      return {
        success: false,
        error: (err as Error)?.message || 'Failed to connect to Supabase auth service.',
      };
    }
  };

  const logout = async () => {
    if (authMode === 'SUPABASE' && supabase) {
      await supabase.auth.signOut();
    }
    setUser(null);
    setCurrentOrg(null);
  };

  const resetPassword = async (email: string) => {
    if (demoAllowed && authMode === 'DEMO') return { success: true, message: 'DEMO password reset preview; no email was sent.' };
    if (!supabase) return { success: false, message: 'Password reset unavailable: Supabase is not configured.' };
    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: `${window.location.origin}/auth/login` });
      return error ? { success: false, message: 'Password reset request failed.' } : { success: true, message: 'Password reset request accepted. Delivery is not confirmed.' };
    } catch { return { success: false, message: 'Password reset request failed. No delivery is claimed.' }; }
  };

  const enrollMfa = async () => {
    if (!demoAllowed || authMode !== 'DEMO') return { qrCode: '', secret: '', factorId: '' };
    return { qrCode: '', secret: 'JBSWY3DPEHPK3PXP', factorId: 'factor-demo-01' };
  };

  const verifyMfa = async (code: string) => {
    if (!demoAllowed || authMode !== 'DEMO') return { success: false, error: 'MFA verification is unsupported until the live factor/challenge workflow is integrated. No local approval is granted.' };
    if (!/^\d{6}$/.test(code)) return { success: false, error: 'Verification code must be exactly 6 digits.' };
    if (code === '000000') return { success: false, error: 'Invalid or expired TOTP security token.' };
    if (user) setUser({ ...user, mfaVerified: true });
    return { success: true };
  };
  return (
    <AuthContext.Provider
      value={{
        user,
        currentOrg,
        userOrgs,
        role,
        isAuthenticated: !!user,
        authMode,
        isDemoSession: authMode === 'DEMO',
        switchOrg,
        setRole,
        loginDemo,
        loginSupabase,
        logout,
        resetPassword,
        enrollMfa,
        verifyMfa,
        hasTenantAccess,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
