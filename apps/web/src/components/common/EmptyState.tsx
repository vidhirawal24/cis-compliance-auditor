import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
    icon?: LucideIcon;
  };
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
}) => {
  const ActionIcon = action?.icon;

  return (
    <div
      role="region"
      aria-label={title}
      className={cn(
        'flex flex-col items-center justify-center p-8 text-center rounded-lg border border-dashed border-slate-800 bg-slate-900/40 my-4',
        className
      )}
    >
      <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-slate-400 mb-4">
        <Icon className="w-6 h-6" aria-hidden="true" />
      </div>
      <h3 className="text-sm font-semibold text-slate-200 mb-1">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mb-6">{description}</p>
      {action && (
        <Button onClick={action.onClick} size="sm" className="gap-2">
          {ActionIcon && <ActionIcon className="w-3.5 h-3.5" />}
          {action.label}
        </Button>
      )}
    </div>
  );
};

