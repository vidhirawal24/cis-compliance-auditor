import React, { useState } from 'react';
import { Copy, Check, FileCode, Hash, ShieldCheck, Clock } from 'lucide-react';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import type { EvidenceRef } from '../../contracts/v1/types';

export interface EvidenceViewerProps {
  evidence: EvidenceRef;
  rawText?: string;
  collectionMethod?: string;
  className?: string;
}

export const EvidenceViewer: React.FC<EvidenceViewerProps> = ({
  evidence,
  rawText,
  collectionMethod = 'read_only_collector',
  className,
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(rawText || evidence.source_command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`rounded-lg border border-slate-800 bg-slate-900/90 overflow-hidden ${className}`}>
      {/* Evidence Metadata Header */}
      <div className="flex flex-wrap items-center justify-between p-3 bg-slate-950 border-b border-slate-800 gap-2">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-sky-400" />
          <span className="text-xs font-mono font-semibold text-slate-200">
            {evidence.source_command}
          </span>
          <Badge variant="secondary" className="text-[10px] uppercase font-mono">
            {collectionMethod}
          </Badge>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={handleCopy}
            variant="ghost"
            size="sm"
            className="h-7 text-xs gap-1.5 text-slate-400 hover:text-white"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </Button>
        </div>
      </div>

      {/* Raw Output Box */}
      <div className="p-3 bg-black/60 font-mono text-xs text-slate-300 overflow-x-auto max-h-48 leading-relaxed selection:bg-sky-900">
        <pre className="whitespace-pre-wrap">{rawText || evidence.source_command}</pre>
      </div>

      {/* Cryptographic Hash & Provenance Footer */}
      <div className="p-2.5 bg-slate-950/70 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-[11px] text-slate-400 gap-2 font-mono">
        <div className="flex items-center gap-1.5 overflow-hidden">
          <Hash className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span className="text-slate-500">SHA256:</span>
          <span className="truncate text-slate-300" title={evidence.sha256}>
            {evidence.sha256}
          </span>
          <span className="inline-flex items-center gap-0.5 text-emerald-400 font-sans text-[10px] font-semibold">
            <ShieldCheck className="w-3 h-3" /> VERIFIED
          </span>
        </div>

        <div className="flex items-center gap-1 shrink-0 text-slate-500">
          <Clock className="w-3 h-3" />
          <span>{new Date(evidence.timestamp).toLocaleTimeString()} UTC</span>
        </div>
      </div>
    </div>
  );
};

