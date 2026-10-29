import React from 'react';
import { SeverityLevel } from '../../contracts/v1/enums';
import { cn } from '../../lib/utils';

export interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  count?: number;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, count, className }) => {
  const norm = severity.toUpperCase();

  const styles = {
    [SeverityLevel.CRITICAL]: 'bg-rose-950/80 text-rose-300 border-rose-800/80',
    [SeverityLevel.HIGH]: 'bg-orange-950/80 text-orange-300 border-orange-800/80',
    [SeverityLevel.MEDIUM]: 'bg-yellow-950/80 text-yellow-300 border-yellow-800/80',
    [SeverityLevel.LOW]: 'bg-blue-950/80 text-blue-300 border-blue-800/80',
    [SeverityLevel.INFORMATIONAL]: 'bg-slate-900 text-slate-300 border-slate-700',
  }[norm as SeverityLevel] || 'bg-slate-900 text-slate-300 border-slate-700';

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium border select-none',
        styles,
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
      <span>{norm}</span>
      {count !== undefined && (
        <span className="ml-0.5 px-1 rounded-sm bg-black/40 text-[10px] font-bold">
          {count}
        </span>
      )}
    </span>
  );
};

