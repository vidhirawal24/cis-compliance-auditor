import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Shield, Lock, KeyRound, ArrowLeft, Mail, AlertTriangle, CheckCircle2, ShieldCheck } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../../components/ui/card';
import { Input } from '../../components/ui/input';
import { Button } from '../../components/ui/button';
import { useAuth } from '../../auth/context';
import { runtimeConfig } from '../../api/config';
import { UserRole } from '../../contracts/v1/enums';
import { loginFormSchema, passwordResetFormSchema, mfaVerifyFormSchema } from '../../contracts/v1/schemas';

type LoginFormData = z.infer<typeof loginFormSchema>;
type PasswordResetFormData = z.infer<typeof passwordResetFormSchema>;
type MfaVerifyFormData = z.infer<typeof mfaVerifyFormSchema>;

export const AuthShell: React.FC = () => {
  const location = useLocation();
  const [authTab, setAuthTab] = useState<'LOGIN' | 'RECOVER_PASSWORD' | 'MFA_CHALLENGE' | 'MFA_SETUP' | 'BLOCKED'>('LOGIN');
  const [authError, setAuthError] = useState<string | null>(location.state?.logoutUnconfirmed === true ? 'Local session ended; remote sign-out was not confirmed.' : null);
  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [selectedDemoRole, setSelectedDemoRole] = useState<UserRole>(UserRole.OWNER);
  const [demoEmail, setDemoEmail] = useState('apoorva.lead@baselineguard.local');
  const [totpSecret, setTotpSecret] = useState('');

  const { loginDemo, loginSupabase, resetPassword, enrollMfa, verifyMfa } = useAuth();
  const navigate = useNavigate();
  const demoAllowed = runtimeConfig().mode === 'demo';

  // 1. Supabase / Standard Login Form
  const {
    register: registerLogin,
    handleSubmit: handleLoginSubmit,
    formState: { errors: loginErrors, isSubmitting: isLoggingIn },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginFormSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  // 2. Password Recovery Form
  const {
    register: registerReset,
    handleSubmit: handleResetSubmit,
    formState: { errors: resetErrors, isSubmitting: isResetting },
  } = useForm<PasswordResetFormData>({
    resolver: zodResolver(passwordResetFormSchema),
    defaultValues: { email: '' },
  });

  // 3. MFA Verification Form
  const {
    register: registerMfa,
    handleSubmit: handleMfaSubmit,
    formState: { errors: mfaErrors, isSubmitting: isVerifyingMfa },
  } = useForm<MfaVerifyFormData>({
    resolver: zodResolver(mfaVerifyFormSchema),
    defaultValues: { code: '' },
  });

  // Submit standard Supabase login
  const onSupabaseLogin = async (data: LoginFormData) => {
    setAuthError(null);
    setAuthNotice(null);
    const result = await loginSupabase(data.email, data.password);
    if (!result.success) {
      setAuthError(result.error || 'Authentication failed. Please verify credentials or use Demo Quick Sign-In.');
    } else if (result.requiresMfa) {
      setAuthTab('MFA_CHALLENGE');
    } else {
      navigate('/orgs');
    }
  };

  // Submit password reset
  const onResetPassword = async (data: PasswordResetFormData) => {
    setAuthError(null);
    setAuthNotice(null);
    const res = await resetPassword(data.email);
    if (res.success) {
      setAuthNotice(res.message);
    } else {
      setAuthError(res.message);
    }
  };

  // Submit MFA verification
  const onVerifyMfa = async (data: MfaVerifyFormData) => {
    setAuthError(null);
    const res = await verifyMfa(data.code);
    if (res.success) {
      navigate('/orgs');
    } else {
      setAuthError(res.error || 'Invalid TOTP authentication code.');
    }
  };

  // Demo synthetic sign-in
  const handleDemoSignIn = (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    if (!demoAllowed) { setAuthError('DEMO sign-in is disabled for this environment.'); return; }
    loginDemo(demoEmail, selectedDemoRole);
    // Privileged roles require demonstration of the MFA step
    if (selectedDemoRole === UserRole.OWNER || selectedDemoRole === UserRole.ADMIN || selectedDemoRole === UserRole.APPROVER) {
      setAuthTab('MFA_CHALLENGE');
    } else {
      loginDemo(demoEmail, selectedDemoRole);
      navigate('/orgs');
    }
  };

  // Open MFA enrollment
  const handleOpenMfaSetup = async () => {
    const data = await enrollMfa();
    if (!data.factorId) { setAuthError('MFA enrollment is unavailable until live factor integration is complete.'); return; }
    setTotpSecret(data.secret);
    setAuthTab('MFA_SETUP');
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-6">
        {/* Brand Banner */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 bg-sky-950 border border-sky-800 rounded-xl flex items-center justify-center mx-auto text-sky-400 shadow-lg shadow-sky-950/50">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">BaselineGuard</h1>
          <p className="text-xs text-slate-400">
            audit every device against CIS benchmarks. Know what’s wrong, why, and how to fix it.
          </p>
        </div>

        {/* Notices and Errors */}
        {authError && (
          <div role="alert" className="p-3 bg-red-950/80 border border-red-800 rounded-lg text-xs text-red-200 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span>{authError}</span>
          </div>
        )}
        {authNotice && (
          <div role="status" className="p-3 bg-emerald-950/80 border border-emerald-800 rounded-lg text-xs text-emerald-200 flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>{authNotice}</span>
          </div>
        )}

        {/* VIEW 1: Standard / Supabase & Demo Login */}
        {authTab === 'LOGIN' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl backdrop-blur-md">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-bold text-white">Sign In to Workspace</CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Server authorization and tenant membership integration required
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Production Supabase Auth Form */}
              <form onSubmit={handleLoginSubmit(onSupabaseLogin)} className="space-y-3" noValidate>
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Corporate Email</label>
                  <Input
                    type="email"
                    placeholder="operator@acmefinancial.com"
                    {...registerLogin('email')}
                    aria-invalid={!!loginErrors.email}
                    className="h-8 text-xs"
                  />
                  {loginErrors.email && (
                    <p className="text-[11px] text-red-400">{loginErrors.email.message}</p>
                  )}
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between items-center">
                    <label className="text-xs font-medium text-slate-300">Password</label>
                    <button
                      type="button"
                      onClick={() => setAuthTab('RECOVER_PASSWORD')}
                      className="text-[11px] text-sky-400 hover:underline"
                    >
                      Forgot password?
                    </button>
                  </div>
                  <Input
                    type="password"
                    placeholder="••••••••••••"
                    {...registerLogin('password')}
                    aria-invalid={!!loginErrors.password}
                    className="h-8 text-xs"
                  />
                  {loginErrors.password && (
                    <p className="text-[11px] text-red-400">{loginErrors.password.message}</p>
                  )}
                </div>

                <Button type="submit" disabled={isLoggingIn} className="w-full gap-2 text-xs h-8">
                  <Lock className="w-3.5 h-3.5" />
                  {isLoggingIn ? 'Authenticating...' : 'Sign In via Supabase Auth'}
                </Button>
              </form>

              {/* DEMO / SYNTHETIC LAB SECTION (Clearly Demarcated) */}
              <div className="relative pt-3 border-t border-slate-800">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-slate-900 px-2 text-[10px] uppercase font-mono text-slate-500 font-semibold tracking-wider">
                  OR LAB SIMULATION
                </div>

                <div className="p-3 bg-black/40 border border-slate-800 rounded-lg space-y-3 mt-1">
                  <div className="flex items-center gap-1.5 text-[11px] font-mono font-semibold text-amber-400">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>[DEMO MODE: Synthetic Lab Only]</span>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Bypasses live Supabase directory to test RBAC roles with deterministic local fixtures. Never used for production authentication.
                  </p>

                  <div className="space-y-1.5">
                    <label className="text-[11px] font-medium text-slate-300">Demo Persona Email</label>
                    <Input
                      type="email"
                      value={demoEmail}
                      onChange={(e) => setDemoEmail(e.target.value)}
                      className="h-7 text-xs font-mono"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[11px] font-medium text-slate-300">Target Role (RBAC Simulation)</label>
                    <select
                      value={selectedDemoRole}
                      onChange={(e) => setSelectedDemoRole(e.target.value as UserRole)}
                      className="w-full h-7 px-2 rounded border border-slate-700 bg-slate-900 text-xs text-white font-mono"
                    >
                      <option value={UserRole.OWNER}>OWNER (Full Governance)</option>
                      <option value={UserRole.ADMIN}>ADMIN (Security Operations)</option>
                      <option value={UserRole.APPROVER}>APPROVER (Change Board)</option>
                      <option value={UserRole.OPERATOR}>OPERATOR (Remediation & Hardening)</option>
                      <option value={UserRole.AUDITOR}>AUDITOR (Read-Only Compliance)</option>
                      <option value={UserRole.VIEWER}>VIEWER (Executive Dashboard)</option>
                    </select>
                  </div>

                  <Button
                    type="button"
                    onClick={handleDemoSignIn}
                    variant="outline"
                    className="w-full text-xs h-7 border-amber-900/60 hover:bg-amber-950/40 text-amber-300"
                  >
                    Quick Sign-In (DEMO Mode)
                  </Button>
                </div>
              </div>

              {/* Utility Links */}
              <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                <button
                  type="button"
                  onClick={handleOpenMfaSetup}
                  className="hover:underline text-sky-400 flex items-center gap-1"
                >
                  <ShieldCheck className="w-3 h-3" />
                  Enroll TOTP MFA
                </button>
                <button
                  type="button"
                  onClick={() => setAuthTab('BLOCKED')}
                  className="hover:underline text-slate-500"
                >
                  Simulate Blocked Tenant
                </button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* VIEW 2: Password Recovery */}
        {authTab === 'RECOVER_PASSWORD' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                <Mail className="w-4 h-4 text-sky-400" />
                Password Recovery
              </CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Enter your registered corporate address to receive secure reset instructions.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleResetSubmit(onResetPassword)} className="space-y-4" noValidate>
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Corporate Email</label>
                  <Input
                    type="email"
                    placeholder="name@company.com"
                    {...registerReset('email')}
                    aria-invalid={!!resetErrors.email}
                    className="h-8 text-xs"
                  />
                  {resetErrors.email && (
                    <p className="text-[11px] text-red-400">{resetErrors.email.message}</p>
                  )}
                </div>

                <Button type="submit" disabled={isResetting} className="w-full text-xs h-8">
                  {isResetting ? 'Sending...' : 'Send Recovery Link'}
                </Button>

                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setAuthTab('LOGIN')}
                  className="w-full text-xs h-8 gap-1.5"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  Back to Sign In
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* VIEW 3: MFA Challenge (Required for Privileged Personas) */}
        {authTab === 'MFA_CHALLENGE' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-sky-400" />
                MFA Security Challenge
              </CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Privileged access requires two-factor TOTP verification before accessing workspace.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleMfaSubmit(onVerifyMfa)} className="space-y-4" noValidate>
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">6-Digit Authenticator Code</label>
                  <Input
                    type="text"
                    maxLength={6}
                    placeholder="123456"
                    {...registerMfa('code')}
                    aria-invalid={!!mfaErrors.code}
                    className="font-mono text-center tracking-widest text-base h-10"
                    autoFocus
                  />
                  {mfaErrors.code && (
                    <p className="text-[11px] text-red-400 text-center">{mfaErrors.code.message}</p>
                  )}
                </div>

                <Button type="submit" disabled={isVerifyingMfa} className="w-full text-xs h-8 gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  {isVerifyingMfa ? 'Verifying...' : 'Verify Token & Enter Workspace'}
                </Button>

                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setAuthTab('LOGIN')}
                  className="w-full text-xs h-8"
                >
                  Cancel & Return to Login
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        {/* VIEW 4: MFA TOTP Enrollment */}
        {authTab === 'MFA_SETUP' && (
          <Card className="border-slate-800 bg-slate-900/90 shadow-2xl">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                MFA TOTP Enrollment
              </CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Scan using Google Authenticator, 1Password, or Microsoft Authenticator
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-center">
              <div className="w-36 h-36 bg-white p-2 rounded-lg mx-auto flex items-center justify-center">
                <div className="w-32 h-32 border-2 border-dashed border-slate-900 flex flex-col items-center justify-center text-[10px] font-mono text-slate-900 font-bold p-2 text-center">
                  <span>[TOTP QR CODE]</span>
                  <span className="text-[8px] text-slate-600 mt-1">otpauth://totp/BaselineGuard</span>
                </div>
              </div>

              <div className="p-2 bg-black/50 border border-slate-800 rounded font-mono text-xs text-slate-300">
                <div className="text-[10px] text-slate-500 uppercase">Manual Secret Seed:</div>
                <div className="font-bold tracking-wider text-sky-400">{totpSecret}</div>
              </div>

              <Button onClick={() => setAuthTab('LOGIN')} className="w-full text-xs h-8">
                Done & Return to Sign In
              </Button>
            </CardContent>
          </Card>
        )}

        {/* VIEW 5: Tenant Blocked / Suspended State */}
        {authTab === 'BLOCKED' && (
          <Card className="border-red-900/60 bg-slate-900/90 shadow-2xl text-center">
            <CardHeader className="pb-3">
              <div className="w-10 h-10 bg-red-950 border border-red-800 rounded-lg flex items-center justify-center mx-auto text-red-400 mb-2">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <CardTitle className="text-red-400 text-base">Tenant Access Restricted</CardTitle>
              <CardDescription className="text-xs text-slate-400">
                This organization workspace has been suspended or restricted by tenant administrator policy.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button onClick={() => setAuthTab('LOGIN')} variant="outline" className="w-full text-xs h-8">
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
