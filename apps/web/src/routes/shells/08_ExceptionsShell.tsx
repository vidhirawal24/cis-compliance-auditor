import React, { useState } from 'react';
import {
  FileCheck2,
  Plus,
  Clock,
  UserCheck,
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Lock,
  FileText,
  X,
  ShieldAlert,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../../components/ui/table';
import { useAuth } from '../../auth/context';
import { fixtureStore } from '../../api/store';
import { UserRole } from '../../contracts/v1/enums';
import { toast } from 'sonner';
import type { PolicyExceptionItem, ManualReviewItem, Finding } from '../../contracts/v1/types';

export const ExceptionsShell: React.FC = () => {
  const { role, user } = useAuth();
  const [activeTab, setActiveTab] = useState<'EXCEPTIONS' | 'MANUAL_REVIEWS'>('EXCEPTIONS');

  // Authorization check: Read-only auditors and viewers cannot request exceptions or sign off reviews
  const isAuthorizedApprover = [UserRole.OWNER, UserRole.ADMIN, UserRole.APPROVER].includes(role);

  // Exceptions State (E14)
  const [exceptions, setExceptions] = useState<PolicyExceptionItem[]>([...fixtureStore.policyExceptions]);
  const [exceptionFilter, setExceptionFilter] = useState<'ALL' | 'ACTIVE' | 'EXPIRED'>('ALL');
  const [exceptionSearch, setExceptionSearch] = useState('');
  const [isRequestingException, setIsRequestingException] = useState(false);

  // Exception Form State
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const [exceptionControlId, setExceptionControlId] = useState('');
  const [exceptionAssetId, setExceptionAssetId] = useState('');
  const [exceptionReason, setExceptionReason] = useState('');
  const [exceptionApprover, setExceptionApprover] = useState('ciso@acmefinancial.com');
  const [exceptionExpiresAt, setExceptionExpiresAt] = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() + 60);
    return d.toISOString().split('T')[0];
  });
  const [exceptionFormError, setExceptionFormError] = useState<string | null>(null);

  // Manual Reviews State (E12)
  const [manualReviews, setManualReviews] = useState<ManualReviewItem[]>([...fixtureStore.manualReviews]);
  const [reviewFilter, setReviewFilter] = useState<'ALL' | 'PENDING' | 'ATTESTED_PASS' | 'ATTESTED_FAIL'>('ALL');
  const [selectedReviewForSignoff, setSelectedReviewForSignoff] = useState<ManualReviewItem | null>(null);

  // Review Signoff Form State
  const [signoffVerdict, setSignoffVerdict] = useState<'ATTESTED_PASS' | 'ATTESTED_FAIL'>('ATTESTED_PASS');
  const [signoffReviewerEmail, setSignoffReviewerEmail] = useState(user?.email || 'auditor@acmefinancial.com');
  const [signoffJustification, setSignoffJustification] = useState('');
  const [signoffEvidenceUri, setSignoffEvidenceUri] = useState('');
  const [signoffFormError, setSignoffFormError] = useState<string | null>(null);

  // Candidate findings for exception dropdown (findings that failed and don't already have an active exception)
  const candidateFindings: Finding[] = fixtureStore.findings.filter((f) => f.status === 'FAIL');

  // Handle Finding Selection in Exception Form
  const handleSelectFinding = (findingId: string) => {
    setSelectedFindingId(findingId);
    const found = candidateFindings.find((f) => f.finding_id === findingId);
    if (found) {
      setExceptionControlId(found.control_id);
      setExceptionAssetId(found.asset_id);
    }
  };

  // Calculate remaining days
  const getExpirationStatus = (expiresAt: string, isExpiredFlag: boolean) => {
    const target = new Date(expiresAt).getTime();
    const now = Date.now();
    const diffDays = Math.ceil((target - now) / (1000 * 60 * 60 * 24));
    const expired = isExpiredFlag || diffDays <= 0;

    if (expired) {
      return {
        expired: true,
        label: diffDays <= 0 ? `Expired ${Math.abs(diffDays)}d ago` : 'Expired',
      };
    }
    return {
      expired: false,
      label: `${diffDays} Days remaining`,
    };
  };

  // Filter Exceptions
  const filteredExceptions = exceptions.filter((exc) => {
    const isExpired = exc.is_expired || new Date(exc.expires_at).getTime() < Date.now();
    if (exceptionFilter === 'ACTIVE' && isExpired) return false;
    if (exceptionFilter === 'EXPIRED' && !isExpired) return false;

    if (exceptionSearch.trim()) {
      const q = exceptionSearch.toLowerCase();
      const matchId = exc.exception_id.toLowerCase().includes(q);
      const matchControl = exc.control_id.toLowerCase().includes(q);
      const matchHost = exc.hostname.toLowerCase().includes(q);
      const matchReason = exc.reason.toLowerCase().includes(q);
      return matchId || matchControl || matchHost || matchReason;
    }
    return true;
  });

  // Filter Manual Reviews
  const filteredReviews = manualReviews.filter((rev) => {
    if (reviewFilter === 'ALL') return true;
    return rev.status === reviewFilter;
  });

  // Submit Exception Request
  const handleCreateException = (e: React.FormEvent) => {
    e.preventDefault();
    setExceptionFormError(null);

    if (!isAuthorizedApprover) {
      setExceptionFormError('Permission Denied: Read-only auditors cannot grant or request policy exceptions.');
      return;
    }

    if (!selectedFindingId) {
      setExceptionFormError('Target finding selection is required.');
      return;
    }

    if (!exceptionReason.trim() || exceptionReason.trim().length < 10) {
      setExceptionFormError('Business justification must be at least 10 characters.');
      return;
    }

    if (!exceptionApprover.trim() || !exceptionApprover.includes('@')) {
      setExceptionFormError('Valid approver corporate email is required.');
      return;
    }

    if (!exceptionExpiresAt) {
      setExceptionFormError('Expiration date is required.');
      return;
    }

    const newExc = fixtureStore.createException({
      finding_id: selectedFindingId,
      control_id: exceptionControlId,
      asset_id: exceptionAssetId,
      reason: exceptionReason.trim(),
      approver_email: exceptionApprover.trim(),
      expires_at: `${exceptionExpiresAt}T23:59:59Z`,
    });

    setExceptions([...fixtureStore.policyExceptions]);
    setIsRequestingException(false);
    setSelectedFindingId('');
    setExceptionControlId('');
    setExceptionAssetId('');
    setExceptionReason('');
    toast.success(`Exception ${newExc.exception_id} created as overlay on ${newExc.control_id}`);
  };

  // Submit Manual Review Attestation
  const handleSubmitReviewSignoff = (e: React.FormEvent) => {
    e.preventDefault();
    setSignoffFormError(null);

    if (!isAuthorizedApprover) {
      setSignoffFormError('Permission Denied: Read-only auditors cannot submit review attestations.');
      return;
    }

    if (!selectedReviewForSignoff) return;

    if (!signoffReviewerEmail.trim() || !signoffReviewerEmail.includes('@')) {
      setSignoffFormError('Valid reviewer corporate email is required.');
      return;
    }

    if (!signoffJustification.trim() || signoffJustification.trim().length < 10) {
      setSignoffFormError('Attestation justification / inspection notes must be at least 10 characters.');
      return;
    }

    if (!signoffEvidenceUri.trim()) {
      setSignoffFormError('Attestation evidence artifact URI is mandatory for human sign-off.');
      return;
    }

    const updated = fixtureStore.submitManualReview(
      selectedReviewForSignoff.review_id,
      signoffVerdict,
      signoffReviewerEmail.trim(),
      signoffJustification.trim(),
      signoffEvidenceUri.trim()
    );

    setManualReviews([...fixtureStore.manualReviews]);
    setSelectedReviewForSignoff(null);
    setSignoffJustification('');
    setSignoffEvidenceUri('');
    toast.success(`Manual review ${updated.review_id} attested with verdict ${updated.status}`);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-sky-400" />
            Exceptions & Manual Reviews (E12, E14)
          </h1>
          <p className="text-xs text-slate-400">
            Time-boxed policy exceptions with business justification and human attestation workflow.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isAuthorizedApprover ? (
            <Button
              size="sm"
              onClick={() => setIsRequestingException(true)}
              className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500"
            >
              <Plus className="w-3.5 h-3.5" />
              Request Policy Exception (E14)
            </Button>
          ) : (
            <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-md">
              <Lock className="w-3.5 h-3.5 text-amber-400" />
              <span>Read-Only Auditor Mode</span>
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1 text-xs">
        <button
          onClick={() => setActiveTab('EXCEPTIONS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'EXCEPTIONS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>Time-Boxed Policy Exceptions (E14)</span>
          <Badge variant="outline" className="text-[10px] py-0 px-1.5">
            {exceptions.length}
          </Badge>
        </button>
        <button
          onClick={() => setActiveTab('MANUAL_REVIEWS')}
          className={`px-4 py-2 font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === 'MANUAL_REVIEWS'
              ? 'border-sky-500 text-sky-400 bg-sky-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>Manual Review Queue (E12)</span>
          <Badge variant="outline" className="text-[10px] py-0 px-1.5">
            {manualReviews.length}
          </Badge>
        </button>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Exceptions Tab (E14) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'EXCEPTIONS' && (
        <div className="space-y-4">
          {/* Auditing Invariant Alert Banner */}
          <div className="bg-amber-950/40 border border-amber-800/80 rounded-lg p-3 text-xs text-amber-200 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-semibold text-amber-300">
                Auditing Invariant (E14): Exceptions Provide Operational Tolerance Only
              </div>
              <p className="text-amber-200/90 leading-relaxed">
                Policy exceptions document approved business risks with mandatory expiration dates.
                They <strong>NEVER</strong> turn a failed CIS control into a PASS or delete the underlying
                finding. The finding remains visible across the security graph, reports, and compliance tracking.
              </p>
            </div>
          </div>

          {/* Controls Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            {/* Filter Pills */}
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
              <button
                onClick={() => setExceptionFilter('ALL')}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  exceptionFilter === 'ALL'
                    ? 'bg-sky-600 text-white font-medium'
                    : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
                }`}
              >
                All ({exceptions.length})
              </button>
              <button
                onClick={() => setExceptionFilter('ACTIVE')}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  exceptionFilter === 'ACTIVE'
                    ? 'bg-emerald-600 text-white font-medium'
                    : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
                }`}
              >
                Active ({exceptions.filter((e) => !e.is_expired && new Date(e.expires_at).getTime() >= Date.now()).length})
              </button>
              <button
                onClick={() => setExceptionFilter('EXPIRED')}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  exceptionFilter === 'EXPIRED'
                    ? 'bg-rose-600 text-white font-medium'
                    : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
                }`}
              >
                Expired ({exceptions.filter((e) => e.is_expired || new Date(e.expires_at).getTime() < Date.now()).length})
              </button>
            </div>

            {/* Search Input */}
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
              <Input
                placeholder="Search exceptions..."
                value={exceptionSearch}
                onChange={(e) => setExceptionSearch(e.target.value)}
                className="pl-8 h-8 text-xs bg-slate-900 border-slate-800"
              />
            </div>
          </div>

          {/* Exceptions Table */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
            <Table className="table-compact">
              <TableHeader>
                <TableRow>
                  <TableHead>Exception ID</TableHead>
                  <TableHead>Target Finding / Control</TableHead>
                  <TableHead>Target Host</TableHead>
                  <TableHead>Approver</TableHead>
                  <TableHead>Business Justification</TableHead>
                  <TableHead>Expires In</TableHead>
                  <TableHead className="text-right">Overlay Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredExceptions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-xs text-slate-500">
                      No policy exceptions found matching the current criteria.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredExceptions.map((exc) => {
                    const statusInfo = getExpirationStatus(exc.expires_at, exc.is_expired);
                    return (
                      <TableRow key={exc.exception_id} className="hover:bg-slate-800/40">
                        <TableCell className="font-mono font-bold text-sky-400 text-xs">
                          {exc.exception_id}
                        </TableCell>
                        <TableCell>
                          <div className="font-mono text-xs font-semibold text-white">
                            {exc.control_id}
                          </div>
                          <div className="text-[10px] text-slate-400 font-mono">
                            {exc.finding_id}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-slate-300">
                          {exc.hostname}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-slate-400">
                          {exc.approver_email}
                        </TableCell>
                        <TableCell className="text-slate-300 text-xs max-w-xs">
                          <p className="line-clamp-2" title={exc.reason}>
                            {exc.reason}
                          </p>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {statusInfo.expired ? (
                            <span className="flex items-center gap-1 text-rose-400 font-semibold">
                              <Clock className="w-3 h-3" />
                              {statusInfo.label}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-amber-400">
                              <Clock className="w-3 h-3" />
                              {statusInfo.label}
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          {statusInfo.expired ? (
                            <Badge className="bg-rose-950/60 text-rose-300 border border-rose-800/80 text-[10px]">
                              EXPIRED OVERLAY
                            </Badge>
                          ) : (
                            <Badge className="bg-emerald-950/60 text-emerald-300 border border-emerald-800/80 text-[10px]">
                              ACTIVE OVERLAY
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Manual Reviews Tab (E12) */}
      {/* ------------------------------------------------------------------ */}
      {activeTab === 'MANUAL_REVIEWS' && (
        <div className="space-y-4">
          {/* Information Notice */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-300 flex items-start gap-3">
            <UserCheck className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-semibold text-white">
                Human Attestation Controls & Evidence Verification (E12)
              </div>
              <p className="text-slate-400 leading-relaxed">
                Physical security locks, key ceremony custody, and SOC2 / ISO-27001 external auditor attestations
                cannot be verified through automated command-line probes. Reviewers must inspect physical evidence,
                enter an immutable evidence artifact URI, and sign off the audit finding.
              </p>
            </div>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
            <button
              onClick={() => setReviewFilter('ALL')}
              className={`px-2.5 py-1 rounded text-xs transition-colors ${
                reviewFilter === 'ALL'
                  ? 'bg-sky-600 text-white font-medium'
                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              All ({manualReviews.length})
            </button>
            <button
              onClick={() => setReviewFilter('PENDING')}
              className={`px-2.5 py-1 rounded text-xs transition-colors ${
                reviewFilter === 'PENDING'
                  ? 'bg-amber-600 text-white font-medium'
                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              Pending ({manualReviews.filter((r) => r.status === 'PENDING').length})
            </button>
            <button
              onClick={() => setReviewFilter('ATTESTED_PASS')}
              className={`px-2.5 py-1 rounded text-xs transition-colors ${
                reviewFilter === 'ATTESTED_PASS'
                  ? 'bg-emerald-600 text-white font-medium'
                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              Attested Pass ({manualReviews.filter((r) => r.status === 'ATTESTED_PASS').length})
            </button>
            <button
              onClick={() => setReviewFilter('ATTESTED_FAIL')}
              className={`px-2.5 py-1 rounded text-xs transition-colors ${
                reviewFilter === 'ATTESTED_FAIL'
                  ? 'bg-rose-600 text-white font-medium'
                  : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
              }`}
            >
              Attested Fail ({manualReviews.filter((r) => r.status === 'ATTESTED_FAIL').length})
            </button>
          </div>

          {/* Manual Review Cards / Table */}
          <div className="space-y-3">
            {filteredReviews.length === 0 ? (
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-8 text-center text-xs text-slate-500">
                No manual reviews found in the current filter.
              </div>
            ) : (
              filteredReviews.map((rev) => {
                const targetAsset = fixtureStore.assets.find((a) => a.asset_id === rev.asset_id);
                return (
                  <Card key={rev.review_id} className="border-slate-800 bg-slate-900/80">
                    <CardContent className="p-4 space-y-3">
                      <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-sky-400">
                              {rev.review_id}
                            </span>
                            <span className="text-slate-600">•</span>
                            <span className="font-mono text-xs font-semibold text-white">
                              {rev.control_id}
                            </span>
                            {rev.status === 'PENDING' && (
                              <Badge className="bg-amber-950/50 text-amber-300 border-amber-800 text-[10px]">
                                PENDING ATTESTATION
                              </Badge>
                            )}
                            {rev.status === 'ATTESTED_PASS' && (
                              <Badge className="bg-emerald-950/50 text-emerald-300 border-emerald-800 text-[10px] flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                ATTESTED PASS
                              </Badge>
                            )}
                            {rev.status === 'ATTESTED_FAIL' && (
                              <Badge className="bg-rose-950/50 text-rose-300 border-rose-800 text-[10px] flex items-center gap-1">
                                <XCircle className="w-3 h-3 text-rose-400" />
                                ATTESTED FAIL
                              </Badge>
                            )}
                          </div>
                          <div className="text-xs text-slate-400 flex items-center gap-2">
                            <span>Target Asset:</span>
                            <span className="font-mono text-slate-200">
                              {targetAsset?.hostname || rev.asset_id}
                            </span>
                            <span className="text-slate-600">•</span>
                            <span className="text-slate-400">Platform:</span>
                            <Badge variant="outline" className="text-[10px] uppercase">
                              {targetAsset?.platform || 'Unknown'}
                            </Badge>
                          </div>
                        </div>

                        {/* Action Sign-Off Button */}
                        <div>
                          {isAuthorizedApprover ? (
                            <Button
                              size="sm"
                              variant={rev.status === 'PENDING' ? 'default' : 'outline'}
                              onClick={() => {
                                setSelectedReviewForSignoff(rev);
                                setSignoffVerdict(rev.status === 'ATTESTED_FAIL' ? 'ATTESTED_FAIL' : 'ATTESTED_PASS');
                                setSignoffJustification(rev.justification || '');
                                setSignoffEvidenceUri(rev.attestation_evidence_uri || '');
                                setSignoffFormError(null);
                              }}
                              className="text-xs h-7 gap-1.5"
                            >
                              <FileText className="w-3.5 h-3.5" />
                              {rev.status === 'PENDING' ? 'Attest & Sign Off' : 'Update Attestation'}
                            </Button>
                          ) : (
                            <div className="flex items-center gap-1 text-[11px] text-slate-500">
                              <Lock className="w-3 h-3" />
                              <span>Read-only auditor</span>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Attestation Details & Evidence */}
                      <div className="p-3 bg-black/40 rounded border border-slate-800/80 text-xs space-y-2">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          <div>
                            <span className="text-slate-400 text-[11px] block">Evidence Artifact URI:</span>
                            {rev.attestation_evidence_uri ? (
                              <div className="flex items-center gap-1.5 font-mono text-[11px] text-sky-400 break-all mt-0.5">
                                <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                                <span>{rev.attestation_evidence_uri}</span>
                              </div>
                            ) : (
                              <span className="text-rose-400/90 italic text-[11px] block mt-0.5">
                                No evidence attached (Mandatory artifact required for pass/fail attestation)
                              </span>
                            )}
                          </div>

                          <div>
                            <span className="text-slate-400 text-[11px] block">Reviewer & Timestamp:</span>
                            {rev.reviewer_email ? (
                              <div className="text-[11px] text-slate-300 font-mono mt-0.5">
                                {rev.reviewer_email} • {rev.submitted_at ? new Date(rev.submitted_at).toLocaleString() : 'N/A'}
                              </div>
                            ) : (
                              <span className="text-slate-500 italic text-[11px] block mt-0.5">
                                Awaiting reviewer sign-off
                              </span>
                            )}
                          </div>
                        </div>

                        {rev.justification && (
                          <div className="pt-2 border-t border-slate-800">
                            <span className="text-slate-400 text-[11px] block">Attestation Justification:</span>
                            <p className="text-slate-200 text-xs mt-0.5">{rev.justification}</p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Request Policy Exception Modal (E14) */}
      {/* ------------------------------------------------------------------ */}
      {isRequestingException && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <Card className="w-full max-w-lg border-slate-700 bg-slate-900 shadow-2xl">
            <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-slate-800">
              <CardTitle className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-sky-400" />
                Request Time-Boxed Policy Exception (E14)
              </CardTitle>
              <button
                onClick={() => setIsRequestingException(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </CardHeader>

            <CardContent className="pt-4">
              <form onSubmit={handleCreateException} className="space-y-4 text-xs">
                {exceptionFormError && (
                  <div className="p-2.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">
                    {exceptionFormError}
                  </div>
                )}

                {/* Target Finding Selection */}
                <div className="space-y-1">
                  <label htmlFor="target-finding-select" className="text-slate-300 font-medium">Select Target Finding (Failed Controls)</label>
                  <select
                    id="target-finding-select"
                    aria-label="Select Target Finding"
                    value={selectedFindingId}
                    onChange={(e) => handleSelectFinding(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-sky-500"
                  >
                    <option value="">-- Choose a finding to except --</option>
                    {candidateFindings.map((f) => (
                      <option key={f.finding_id} value={f.finding_id}>
                        [{f.control_id}] {f.title} ({f.asset_id})
                      </option>
                    ))}
                  </select>
                </div>

                {/* Auto-populated details */}
                <div className="grid grid-cols-2 gap-2 p-2.5 bg-black/40 rounded border border-slate-800 font-mono text-[11px]">
                  <div>
                    <span className="text-slate-500 block">Control ID:</span>
                    <span className="text-white font-semibold">{exceptionControlId || 'None'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Asset ID:</span>
                    <span className="text-white font-semibold">{exceptionAssetId || 'None'}</span>
                  </div>
                </div>

                {/* Expiration Date */}
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">Exception Expiration Date</label>
                  <Input
                    type="date"
                    value={exceptionExpiresAt}
                    onChange={(e) => setExceptionExpiresAt(e.target.value)}
                    className="bg-slate-950 border-slate-800 text-white"
                  />
                  <span className="text-[10px] text-slate-500">
                    Policy exceptions automatically expire and require security review renewal.
                  </span>
                </div>

                {/* Approver Email */}
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">Authorized Approver Corporate Email</label>
                  <Input
                    type="email"
                    value={exceptionApprover}
                    onChange={(e) => setExceptionApprover(e.target.value)}
                    className="bg-slate-950 border-slate-800 text-white"
                  />
                </div>

                {/* Business Justification */}
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">
                    Business & Technical Justification (Min 10 characters)
                  </label>
                  <textarea
                    rows={3}
                    value={exceptionReason}
                    onChange={(e) => setExceptionReason(e.target.value)}
                    placeholder="Describe legacy system dependency, compensating security controls, and decommission schedule..."
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-sky-500 text-xs"
                  />
                </div>

                {/* Invariant Note */}
                <div className="p-2.5 rounded bg-amber-950/30 border border-amber-900/60 text-[11px] text-amber-300/90">
                  <strong>Important Invariant:</strong> Creating this exception attaches an operational tolerance overlay
                  to the finding. The underlying finding status remains <span className="font-mono text-rose-400 font-semibold">FAIL</span>.
                </div>

                {/* Buttons */}
                <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setIsRequestingException(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" size="sm" className="bg-sky-600 hover:bg-sky-500">
                    Submit Exception
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Sign-off Attestation Modal (E12) */}
      {/* ------------------------------------------------------------------ */}
      {selectedReviewForSignoff && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <Card className="w-full max-w-lg border-slate-700 bg-slate-900 shadow-2xl">
            <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-slate-800">
              <CardTitle className="text-sm font-bold text-white flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-emerald-400" />
                Human Attestation Sign-Off (E12)
              </CardTitle>
              <button
                onClick={() => setSelectedReviewForSignoff(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </CardHeader>

            <CardContent className="pt-4">
              <form onSubmit={handleSubmitReviewSignoff} className="space-y-4 text-xs">
                {signoffFormError && (
                  <div className="p-2.5 rounded bg-rose-950/80 border border-rose-800 text-rose-300">
                    {signoffFormError}
                  </div>
                )}

                <div className="p-2.5 bg-black/40 rounded border border-slate-800 font-mono text-[11px] space-y-1">
                  <div>
                    <span className="text-slate-500">Review ID: </span>
                    <span className="text-sky-400 font-semibold">{selectedReviewForSignoff.review_id}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Control ID: </span>
                    <span className="text-white font-semibold">{selectedReviewForSignoff.control_id}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Target Asset: </span>
                    <span className="text-slate-300">{selectedReviewForSignoff.asset_id}</span>
                  </div>
                </div>

                {/* Verdict Selector */}
                <div className="space-y-1.5">
                  <label className="text-slate-300 font-medium">Attestation Verdict</label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setSignoffVerdict('ATTESTED_PASS')}
                      className={`p-2 rounded border text-left flex items-center gap-2 transition-colors ${
                        signoffVerdict === 'ATTESTED_PASS'
                          ? 'border-emerald-500 bg-emerald-950/40 text-emerald-300 font-semibold'
                          : 'border-slate-800 bg-slate-950 text-slate-400'
                      }`}
                    >
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>ATTESTED_PASS</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setSignoffVerdict('ATTESTED_FAIL')}
                      className={`p-2 rounded border text-left flex items-center gap-2 transition-colors ${
                        signoffVerdict === 'ATTESTED_FAIL'
                          ? 'border-rose-500 bg-rose-950/40 text-rose-300 font-semibold'
                          : 'border-slate-800 bg-slate-950 text-slate-400'
                      }`}
                    >
                      <XCircle className="w-4 h-4 text-rose-400" />
                      <span>ATTESTED_FAIL</span>
                    </button>
                  </div>
                </div>

                {/* Reviewer Email */}
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">Reviewer Corporate Email</label>
                  <Input
                    type="email"
                    value={signoffReviewerEmail}
                    onChange={(e) => setSignoffReviewerEmail(e.target.value)}
                    className="bg-slate-950 border-slate-800 text-white"
                  />
                </div>

                {/* Attestation Evidence URI (Mandatory) */}
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">
                    Attestation Evidence Artifact URI <span className="text-rose-400">*</span>
                  </label>
                  <Input
                    type="text"
                    value={signoffEvidenceUri}
                    onChange={(e) => setSignoffEvidenceUri(e.target.value)}
                    placeholder="e.g. supabase://manual-evidence/2026/room-b-inspection-photo.jpg"
                    className="bg-slate-950 border-slate-800 text-white font-mono"
                  />
                  <span className="text-[10px] text-slate-500">
                    Mandatory URI pointing to uploaded photo, SOC2 certification, or physical inspection log.
                  </span>
                </div>

                {/* Justification */}
                <div className="space-y-1">
                  <label className="text-slate-300 font-medium">
                    Inspection Notes & Rationale (Min 10 characters) <span className="text-rose-400">*</span>
                  </label>
                  <textarea
                    rows={3}
                    value={signoffJustification}
                    onChange={(e) => setSignoffJustification(e.target.value)}
                    placeholder="Detail physical inspection date, witness badge ID, observed enclosure locks..."
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-sky-500 text-xs"
                  />
                </div>

                {/* Buttons */}
                <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedReviewForSignoff(null)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" size="sm" className="bg-emerald-600 hover:bg-emerald-500">
                    Confirm Attestation
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};
