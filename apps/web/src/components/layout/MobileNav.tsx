import React from 'react';
import { X } from 'lucide-react';
import { Sidebar } from './Sidebar';

export interface MobileNavProps {
  isOpen: boolean;
  onClose: () => void;
}

export const MobileNav: React.FC<MobileNavProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="lg:hidden fixed inset-0 z-50 flex">
      {/* Dimmed Backdrop */}
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-over Container */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Mobile Navigation"
        className="relative flex-1 flex flex-col max-w-xs w-full bg-[#0e1420] border-r border-slate-800 z-10 animate-in slide-in-from-left duration-200"
      >
        <div className="absolute top-2 right-2 z-20">
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
            aria-label="Close navigation"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <Sidebar onCloseMobile={onClose} />
      </div>
    </div>
  );
};

