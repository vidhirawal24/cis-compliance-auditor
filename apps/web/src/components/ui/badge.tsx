import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-sky-900/60 text-sky-200 border border-sky-700/50',
        secondary: 'border-transparent bg-slate-800 text-slate-300 border border-slate-700',
        destructive: 'border-transparent bg-red-950 text-red-300 border border-red-800',
        outline: 'text-slate-300 border-slate-700',
        success: 'border-transparent bg-emerald-950 text-emerald-300 border border-emerald-800',
        warning: 'border-transparent bg-amber-950 text-amber-300 border border-amber-800',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

