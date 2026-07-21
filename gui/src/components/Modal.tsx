// Reusable modal dialog component
import { ReactNode } from 'react';

interface ModalProps {
  title: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
  width?: string;
}

export function Modal({ title, open, onClose, children, width = 'max-w-md' }: ModalProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className={`bg-void-900 border border-void-700 rounded-xl shadow-2xl ${width} w-full mx-4`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-void-700">
          <h3 className="text-sm font-semibold text-accent">{title}</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-100 text-lg leading-none"
          >
            ×
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

// Input field helper
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="mb-3">
      <label className="text-sm text-gray-400 mb-1 block">{label}</label>
      {children}
    </div>
  );
}

export const inputClass = 'w-full bg-void-950 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none';

export const btnPrimary = 'bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors';

export const btnSecondary = 'bg-void-800 hover:bg-void-700 text-gray-300 rounded-lg px-4 py-2 text-sm font-medium transition-colors';