import React, { useState } from 'react';
import { Trash2, AlertTriangle, X, Lock } from 'lucide-react';
import { deleteReport } from '../../services/api';

interface DeleteModalProps {
  publicId: string;
  isOpen: boolean;
  onClose: () => void;
  onDeleted: () => void;
}

export const DeleteModal: React.FC<DeleteModalProps> = ({ publicId, isOpen, onClose, onDeleted }) => {
  const [deletionKey, setDeletionKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleDelete = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!deletionKey.trim()) {
      setError('Please provide the Deletion Key given upon report submission.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await deleteReport(publicId, deletionKey.trim());
      onDeleted();
    } catch (err: any) {
      setError(err.message || 'Failed to delete report. Please verify your deletion key.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl relative space-y-4">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-500 hover:text-slate-200"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-red-950/70 border border-red-800/80 text-red-400">
            <Trash2 className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">Permanently Delete Report</h3>
            <p className="text-xs text-slate-400">Report ID: <span className="font-mono text-emerald-400">{publicId}</span></p>
          </div>
        </div>

        <div className="p-3 bg-amber-950/30 border border-amber-800/50 rounded-lg text-xs text-amber-200 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p>
            Deleting this report will immediately purge all findings, metadata, and raw evidence files from both the database and disk storage. This action cannot be reversed.
          </p>
        </div>

        <form onSubmit={handleDelete} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>Enter Secret Deletion Key:</span>
            </label>
            <input
              type="text"
              placeholder="del_..."
              value={deletionKey}
              onChange={(e) => setDeletionKey(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-red-500"
              autoFocus
            />
            <p className="text-[11px] text-slate-500">
              The 256-bit deletion key returned to the uploader at the time of scan completion.
            </p>
          </div>

          {error && (
            <div className="p-2.5 bg-red-950/50 border border-red-800/60 rounded-lg text-xs text-red-300">
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-medium rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold shadow-sm transition disabled:opacity-50"
            >
              {loading ? 'Deleting...' : 'Confirm Deletion'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
