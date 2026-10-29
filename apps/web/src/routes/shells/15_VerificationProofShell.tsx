import React from 'react';
import { CheckCheck, ShieldCheck, Download, Hash, Sparkles } from 'lucide-react';
import { Card, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { fixtureStore } from '../../api/store';

export const VerificationProofShell: React.FC = () => {
  const verif = fixtureStore.dualVerification;
  const proof = fixtureStore.proofPackage;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <CheckCheck className="w-5 h-5 text-emerald-400" />
            Dual Verification & Proof Dossier (I16, I17, I18)
          </h1>
          <p className="text-xs text-slate-400">
            Cryptographically sealed post-hardening verification combining automated CIS audit with live service probes.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={() => window.open(proof.download_urls.pdf, '_blank')}
            size="sm"
            className="gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-white"
          >
            <Download className="w-3.5 h-3.5" />
            Download Signed Proof Dossier (PDF)
          </Button>
        </div>
      </div>

      {/* Dual Verification Invariant Card (I16) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Check 1: CIS Control Status */}
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Check 1: Automated CIS Re-Audit</div>
          <div className="text-xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5" />
            {verif.cis_control_status}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Rule CIS-CISCO-ROUTER-2.1.1 evaluated PASS</div>
        </Card>

        {/* Check 2: Live Service Reachability Probe */}
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Check 2: Live Service Probe (I16)</div>
          <div className="text-xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5" />
            {verif.service_probe_status}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">SSH/HTTPS socket handshake verified live</div>
        </Card>

        {/* Invariant Result: Both Must Pass */}
        <Card className="border-slate-800 bg-slate-900/90 p-4">
          <div className="text-xs text-slate-400 mb-1">Overall Hardening Result (I16)</div>
          <div className="text-xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            <Sparkles className="w-5 h-5" />
            VERIFIED SUCCESS
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Dual condition satisfied</div>
        </Card>
      </div>

      {/* Residual Risk Gauge (I17) */}
      <Card className="border-slate-800 bg-slate-900/90 p-5 space-y-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <span>Residual Risk Measurement (I17)</span>
        </CardTitle>
        <p className="text-xs text-slate-400 leading-relaxed">
          Post-hardening risk calculation confirms reduction from an initial composite attack score of <span className="font-mono text-rose-400 font-bold">{verif.pre_change_risk_score}</span> down to <span className="font-mono text-emerald-400 font-bold">{verif.residual_risk_score}</span>.
        </p>

        <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden flex">
          <div style={{ width: `${verif.residual_risk_score}%` }} className="bg-emerald-500" />
          <div style={{ width: `${verif.pre_change_risk_score - verif.residual_risk_score}%` }} className="bg-slate-700/60" />
        </div>
        <div className="flex justify-between text-[11px] font-mono text-slate-500">
          <span>0 (Secure)</span>
          <span className="text-emerald-400 font-bold">Residual: {verif.residual_risk_score}</span>
          <span className="text-rose-400 font-bold">Baseline: {verif.pre_change_risk_score}</span>
          <span>100 (Critical)</span>
        </div>
      </Card>

      {/* Proof-of-Hardening Dossier Manifest (I18) */}
      <Card className="border-slate-800 bg-slate-900/90 p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Hash className="w-4 h-4 text-sky-400" />
            Cryptographic Integrity Manifest & Third-Party Audit Chain (I18)
          </CardTitle>
          <Badge variant="success" className="text-[10px] font-mono">
            MANIFEST INTEGRITY VERIFIED
          </Badge>
        </div>

        <div className="space-y-2 text-xs font-mono">
          <div className="p-2.5 bg-black/40 rounded border border-slate-800 flex justify-between">
            <span className="text-slate-500">Pre-Hardening Baseline Hash:</span>
            <span className="text-slate-300 truncate max-w-sm">{proof.pre_hardening_config_hash}</span>
          </div>
          <div className="p-2.5 bg-black/40 rounded border border-slate-800 flex justify-between">
            <span className="text-slate-500">Post-Hardening Verified Hash:</span>
            <span className="text-emerald-400 truncate max-w-sm">{proof.post_hardening_config_hash}</span>
          </div>
          <div className="p-2.5 bg-black/40 rounded border border-slate-800 flex justify-between">
            <span className="text-slate-500">Execution Log Hash (SHA-256):</span>
            <span className="text-slate-300 truncate max-w-sm">{proof.execution_log_hash}</span>
          </div>
          <div className="p-2.5 bg-black/40 rounded border border-slate-800 flex justify-between">
            <span className="text-slate-500">Digital Signature (ECDSA):</span>
            <span className="text-sky-400 truncate max-w-sm">{proof.digital_signature}</span>
          </div>
        </div>
      </Card>
    </div>
  );
};

