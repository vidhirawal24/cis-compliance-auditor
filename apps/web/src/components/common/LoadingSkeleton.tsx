import React from 'react';
import { Skeleton } from '../ui/skeleton';
import { cn } from '../../lib/utils';

export interface LoadingSkeletonProps {
  type?: 'table' | 'cards' | 'detail';
  rows?: number;
  className?: string;
}

export const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({
  type = 'table',
  rows = 5,
  className,
}) => {
  if (type === 'cards') {
    return (
      <div className={cn('grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4', className)}>
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-8 w-16" />
            <Skeleton className="h-3 w-32" />
          </div>
        ))}
      </div>
    );
  }

  if (type === 'detail') {
    return (
      <div className={cn('space-y-6', className)}>
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-3 w-64" />
          </div>
          <Skeleton className="h-8 w-24" />
        </div>
        <div className="grid grid-cols-3 gap-4">
          <Skeleton className="h-28 rounded-lg" />
          <Skeleton className="h-28 rounded-lg" />
          <Skeleton className="h-28 rounded-lg" />
        </div>
        <Skeleton className="h-64 rounded-lg" />
      </div>
    );
  }

  return (
    <div className={cn('rounded-lg border border-slate-800 overflow-hidden', className)}>
      <div className="h-9 bg-slate-900 border-b border-slate-800 px-4 flex items-center">
        <Skeleton className="h-4 w-48" />
      </div>
      <div className="p-4 space-y-3 bg-slate-900/40">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-4">
            <Skeleton className="h-4 w-1/4" />
            <Skeleton className="h-4 w-1/4" />
            <Skeleton className="h-4 w-1/4" />
            <Skeleton className="h-4 w-1/4" />
          </div>
        ))}
      </div>
    </div>
  );
};

