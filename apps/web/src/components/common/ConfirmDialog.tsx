import React, { useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';

export interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description: string;
  confirmWord?: string;
  danger?: boolean;
  isLoading?: boolean;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  description,
  confirmWord,
  danger = true,
  isLoading = false,
}) => {
  const [inputVal, setInputVal] = useState('');

  if (!isOpen) return null;

  const isConfirmed = confirmWord ? inputVal.trim() === confirmWord : true;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-dialog-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
    >
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${danger ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-sky-950 text-sky-400 border border-sky-800'}`}>
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h3 id="confirm-dialog-title" className="text-sm font-bold text-white">
              {title}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-md"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">{description}</p>

        {confirmWord && (
          <div className="space-y-1.5 pt-2">
            <label className="text-[11px] font-mono text-slate-400">
              Type <strong className="text-white font-bold">{confirmWord}</strong> to confirm:
            </label>
            <Input
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              placeholder={confirmWord}
              className="font-mono text-xs"
              autoFocus
            />
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
          <Button onClick={onClose} variant="outline" size="sm" disabled={isLoading}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              if (isConfirmed) onConfirm();
            }}
            variant={danger ? 'destructive' : 'default'}
            size="sm"
            disabled={!isConfirmed || isLoading}
          >
            {isLoading ? 'Processing...' : 'Confirm Action'}
          </Button>
        </div>
      </div>
    </div>
  );
};

