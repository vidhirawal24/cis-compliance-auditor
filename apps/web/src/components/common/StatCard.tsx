import React from 'react';
import { LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { Card, CardContent } from '../ui/card';
import { Skeleton } from '../ui/skeleton';
import { cn } from '../../lib/utils';

export interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  change?: {
    value: number;
    trend: 'up' | 'down' | 'neutral';
    period: string;
  };
  badge?: {
    text: string;
    variant: 'success' | 'warning' | 'destructive' | 'outline';
  };
  icon: LucideIcon;
  loading?: boolean;
  className?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  change,
  badge,
  icon: Icon,
  loading = false,
  className,
}) => {
  if (loading) {
    return (
      <Card className={cn('p-4', className)}>
        <div className="flex items-center justify-between pb-2">
          <Skeleton className="h-4 w-28" />
          <Skeleton className="h-8 w-8 rounded-lg" />
        </div>
        <Skeleton className="h-7 w-20 mb-2" />
        <Skeleton className="h-3 w-36" />
      </Card>
    );
  }

  return (
    <Card className={cn('relative overflow-hidden border-slate-800 hover:border-slate-700 transition-colors', className)}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <p className="text-xs font-medium text-slate-400">{title}</p>
          <div className="w-8 h-8 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-sky-400">
            <Icon className="w-4 h-4" aria-hidden="true" />
          </div>
        </div>

        <div className="mt-2 flex items-baseline gap-2">
          <span className="text-2xl font-bold tracking-tight text-white font-mono">{value}</span>
          {badge && (
            <span
              className={cn(
                'text-[10px] font-semibold px-1.5 py-0.5 rounded border',
                badge.variant === 'success' && 'bg-emerald-950 text-emerald-300 border-emerald-800',
                badge.variant === 'destructive' && 'bg-red-950 text-red-300 border-red-800',
                badge.variant === 'warning' && 'bg-amber-950 text-amber-300 border-amber-800',
                badge.variant === 'outline' && 'text-slate-300 border-slate-700'
              )}
            >
              {badge.text}
            </span>
          )}
        </div>

        <div className="mt-1 flex items-center justify-between text-xs text-slate-400">
          {subtitle && <span>{subtitle}</span>}
          {change && (
            <div
              className={cn(
                'flex items-center gap-1 font-mono text-[11px]',
                change.trend === 'up' && 'text-emerald-400',
                change.trend === 'down' && 'text-rose-400',
                change.trend === 'neutral' && 'text-slate-400'
              )}
            >
              {change.trend === 'up' && <TrendingUp className="w-3 h-3" />}
              {change.trend === 'down' && <TrendingDown className="w-3 h-3" />}
              {change.trend === 'neutral' && <Minus className="w-3 h-3" />}
              <span>{change.value > 0 ? `+${change.value}%` : `${change.value}%`}</span>
              <span className="text-slate-500">{change.period}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

