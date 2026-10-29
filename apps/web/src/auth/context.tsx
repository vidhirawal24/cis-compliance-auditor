import React, { createContext, useContext, useState } from 'react';
import { UserRole } from '../contracts/v1/enums';
import type { Organization } from '../contracts/v1/types';
import { DEMO_ORGANIZATION, DEMO_ORG_ID } from '../fixtures/demoData';

interface AuthUser {
  id: string;
  email: string;
  role: UserRole;
  mfaVerified: boolean;
}

interface AuthContextType {
  user: AuthUser | null;
  currentOrg: Organization | null;
  role: UserRole;
  isAuthenticated: boolean;
  switchOrg: (orgId: string) => void;
  setRole: (role: UserRole) => void;
  loginDemo: (email: string, role: UserRole) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const DEMO_USER: AuthUser = {
  id: 'usr-apoorva-secops',
  email: 'apoorva.lead@baselineguard.local',
  role: UserRole.OWNER,
  mfaVerified: true,
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(DEMO_USER);
  const [currentOrg, setCurrentOrg] = useState<Organization | null>(DEMO_ORGANIZATION);
  const [role, setRoleState] = useState<UserRole>(UserRole.OWNER);

  const switchOrg = (orgId: string) => {
    if (orgId === DEMO_ORG_ID) {
      setCurrentOrg(DEMO_ORGANIZATION);
    } else {
      setCurrentOrg({
        org_id: orgId,
        name: `Organization (${orgId})`,
        slug: `org-${orgId}`,
        created_at: new Date().toISOString(),
        role: role,
        is_active: true,
      });
    }
  };

  const setRole = (newRole: UserRole) => {
    setRoleState(newRole);
    if (user) {
      setUser({ ...user, role: newRole });
    }
  };

  const loginDemo = (email: string, targetRole: UserRole) => {
    setUser({
      id: `usr-${Date.now()}`,
      email,
      role: targetRole,
      mfaVerified: true,
    });
    setRoleState(targetRole);
    setCurrentOrg(DEMO_ORGANIZATION);
  };

  const logout = () => {
    setUser(null);
    setCurrentOrg(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        currentOrg,
        role,
        isAuthenticated: !!user,
        switchOrg,
        setRole,
        loginDemo,
        logout,
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

