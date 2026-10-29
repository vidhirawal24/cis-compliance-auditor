import React from 'react';
import { cn } from '../../lib/utils';

export interface ConfigDiffProps {
  diffText: string;
  className?: string;
  title?: string;
}

export const ConfigDiff: React.FC<ConfigDiffProps> = ({ diffText, className, title }) => {
  const lines = diffText.split('\n');

  return (
    <div className={cn('rounded-lg border border-slate-800 bg-slate-950 overflow-hidden font-mono text-xs', className)}>
      {title && (
        <div className="px-3 py-2 bg-slate-900 border-b border-slate-800 text-xs font-sans font-medium text-slate-300">
          {title}
        </div>
      )}
      <div className="p-3 overflow-x-auto max-h-64 space-y-0.5">
        {lines.map((line, idx) => {
          const isAddition = line.startsWith('+');
          const isDeletion = line.startsWith('-');
          const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

          return (
            <div
              key={idx}
              className={cn(
                'flex items-center gap-2 px-1.5 py-0.5 rounded-sm select-text',
                isAddition && 'bg-emerald-950/60 text-emerald-300',
                isDeletion && 'bg-rose-950/60 text-rose-300 line-through opacity-80',
                isHeader && 'text-slate-500 font-semibold',
                !isAddition && !isDeletion && !isHeader && 'text-slate-300'
              )}
            >
              <span className="w-6 text-slate-600 text-[10px] select-none text-right shrink-0">
                {idx + 1}
              </span>
              <span className="w-3 select-none shrink-0 font-bold">
                {isAddition ? '+' : isDeletion ? '-' : ' '}
              </span>
              <span className="whitespace-pre">{line.replace(/^[+-]/, '')}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

