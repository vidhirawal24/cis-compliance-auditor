import React from 'react';
import { EvaluationStatus } from '../../contracts/v1/enums';
import { cn } from '../../lib/utils';
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, AlertOctagon, MinusCircle, ShieldCheck } from 'lucide-react';

export interface StatusBadgeProps {
  status: EvaluationStatus | string;
  hasException?: boolean;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, hasException, className }) => {
  const norm = status.toUpperCase();

  const config = {
    [EvaluationStatus.PASS]: {
      label: 'PASS',
      icon: CheckCircle2,
      style: 'bg-emerald-950/80 text-emerald-300 border-emerald-800',
    },
    [EvaluationStatus.FAIL]: {
      label: 'FAIL',
      icon: XCircle,
      style: 'bg-rose-950/80 text-rose-300 border-rose-800',
    },
    [EvaluationStatus.NOT_APPLICABLE]: {
      label: 'NOT APPLICABLE',
      icon: MinusCircle,
      style: 'bg-slate-900 text-slate-400 border-slate-700',
    },
    [EvaluationStatus.MANUAL_REVIEW]: {
      label: 'MANUAL REVIEW',
      icon: AlertTriangle,
      style: 'bg-amber-950/80 text-amber-300 border-amber-800',
    },
    [EvaluationStatus.ERROR]: {
      label: 'ERROR',
      icon: AlertOctagon,
      style: 'bg-red-950 text-red-400 border-red-700',
    },
    [EvaluationStatus.NOT_ASSESSED]: {
      label: 'NOT ASSESSED',
      icon: HelpCircle,
      style: 'bg-purple-950/80 text-purple-300 border-purple-800',
    },
  }[norm as EvaluationStatus] || {
    label: norm,
    icon: HelpCircle,
    style: 'bg-slate-900 text-slate-400 border-slate-700',
  };

  const Icon = config.icon;

  return (
    <div className="inline-flex items-center gap-1.5 flex-wrap">
      <span
        className={cn(
          'inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium border select-none',
          config.style,
          className
        )}
      >
        <Icon className="w-3.5 h-3.5" aria-hidden="true" />
        <span>{config.label}</span>
      </span>

      {hasException && (
        <span
          title="Policy-Approved Time-Bound Exception Active (Retains Technical Finding)"
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-sky-950 text-sky-300 border border-sky-800"
        >
          <ShieldCheck className="w-3 h-3 text-sky-400" />
          EXCEPTION
        </span>
      )}
    </div>
  );
};

