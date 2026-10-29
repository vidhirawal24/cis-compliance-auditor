import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, KeyRound } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../../components/ui/card';
import { Input } from '../../components/ui/input';
import { Button } from '../../components/ui/button';
import { useAuth } from '../../auth/context';
import { UserRole } from '../../contracts/v1/enums';

export const AuthShell: React.FC = () => {
  const [email, setEmail] = useState('apoorva.lead@baselineguard.local');
  const [password, setPassword] = useState('••••••••••••');
  const [selectedRole, setSelectedRole] = useState<UserRole>(UserRole.OWNER);
  const [step, setStep] = useState<'LOGIN' | 'MFA_CHALLENGE' | 'MFA_SETUP' | 'BLOCKED'>('LOGIN');
  const [mfaCode, setMfaCode] = useState('');
  const { loginDemo } = useAuth();
  const navigate = useNavigate();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate required MFA step for privileged roles
    if (selectedRole === UserRole.OWNER || selectedRole === UserRole.ADMIN || selectedRole === UserRole.APPROVER) {
      setStep('MFA_CHALLENGE');
    } else {
      loginDemo(email, selectedRole);
      navigate('/orgs');
    }
  };

  const handleVerifyMfa = (e: React.FormEvent) => {
    e.preventDefault();
    loginDemo(email, selectedRole);
    navigate('/orgs');
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-6">
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-sky-950 border border-sky-800 rounded-xl flex items-center justify-center mx-auto text-sky-400">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">BaselineGuard</h1>
          <p className="text-xs text-slate-400">
            Audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.
          </p>
        </div>

        {step === 'LOGIN' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl">
            <CardHeader>
              <CardTitle>Sign In to Workspace</CardTitle>
              <CardDescription>
                Authenticate via Supabase Auth with tenant authorization
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Corporate Email</label>
                  <Input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    placeholder="name@company.com"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Password</label>
                  <Input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Session Role (Demo)</label>
                  <select
                    value={selectedRole}
                    onChange={(e) => setSelectedRole(e.target.value as UserRole)}
                    className="w-full h-8 px-2.5 rounded-md border border-slate-700 bg-slate-900 text-xs text-white"
                  >
                    <option value={UserRole.OWNER}>Organization Owner</option>
                    <option value={UserRole.ADMIN}>Security Administrator</option>
                    <option value={UserRole.APPROVER}>Change Approver</option>
                    <option value={UserRole.OPERATOR}>Network/OS Operator</option>
                    <option value={UserRole.AUDITOR}>Auditor / Compliance Officer</option>
                    <option value={UserRole.VIEWER}>Executive / Viewer</option>
                  </select>
                </div>

                <Button type="submit" className="w-full gap-2">
                  <Lock className="w-3.5 h-3.5" />
                  Sign In (DEMO Mode)
                </Button>

                <div className="flex items-center justify-between pt-2 text-[11px] text-slate-400">
                  <button type="button" onClick={() => setStep('MFA_SETUP')} className="hover:underline text-sky-400">
                    Setup TOTP MFA
                  </button>
                  <button type="button" onClick={() => setStep('BLOCKED')} className="hover:underline text-rose-400">
                    Simulate Blocked Tenant
                  </button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {step === 'MFA_CHALLENGE' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl">
            <CardHeader>
              <CardTitle>MFA Security Challenge</CardTitle>
              <CardDescription>
                Role <strong className="text-sky-400">{selectedRole}</strong> requires two-factor authentication
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleVerifyMfa} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-300">Authenticator 6-Digit Code</label>
                  <Input
                    type="text"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value)}
                    placeholder="123456"
                    className="font-mono text-center tracking-widest text-base"
                    required
                    autoFocus
                  />
                </div>
                <Button type="submit" className="w-full gap-2">
                  <KeyRound className="w-3.5 h-3.5" />
                  Verify TOTP & Access Workspace
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setStep('LOGIN')}
                  className="w-full"
                >
                  Back to Sign In
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {step === 'MFA_SETUP' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl">
            <CardHeader>
              <CardTitle>MFA TOTP Enrollment</CardTitle>
              <CardDescription>
                Scan the QR code using Google Authenticator or 1Password
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-center">
              <div className="w-40 h-40 bg-white p-2 rounded-lg mx-auto flex items-center justify-center">
                <div className="w-36 h-36 border-4 border-dashed border-slate-900 flex items-center justify-center text-xs font-mono text-slate-900 font-bold">
                  [DEMO QR CODE]
                </div>
              </div>
              <p className="text-xs text-slate-400 font-mono">Secret: JBSWY3DPEHPK3PXP</p>
              <Button onClick={() => setStep('LOGIN')} className="w-full">
                Complete Enrollment
              </Button>
            </CardContent>
          </Card>
        )}

        {step === 'BLOCKED' && (
          <Card className="border-red-900 bg-slate-900/90 shadow-2xl text-center">
            <CardHeader>
              <div className="w-10 h-10 bg-red-950 border border-red-800 rounded-lg flex items-center justify-center mx-auto text-red-400 mb-2">
                <Shield className="w-5 h-5" />
              </div>
              <CardTitle className="text-red-400">Access Restricted</CardTitle>
              <CardDescription>
                Your tenant workspace has been suspended or restricted by tenant administrator policy.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button onClick={() => setStep('LOGIN')} variant="outline" className="w-full">
                Return to Login
              </Button>
            </CardContent>
          </Card>
        )}

        <div className="text-center text-[11px] text-slate-500 font-mono">
          Deterministic No-AI Execution • Frozen Contract v1.0.0
        </div>
      </div>
    </div>
  );
};

