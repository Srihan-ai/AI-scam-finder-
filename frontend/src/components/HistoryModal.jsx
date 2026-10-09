import React from 'react';
import { X, Trash2, ArrowRight, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function HistoryModal({ isOpen, onClose, history, onSelectScan, onClearHistory }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="w-full max-w-xl max-h-[85vh] flex flex-col rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base sm:text-lg font-bold text-white">Your Scan History</h3>
            <span className="text-xs text-slate-400 font-mono">({history.length})</span>
          </div>
          
          <div className="flex items-center gap-2">
            {history.length > 0 && (
              <button
                onClick={onClearHistory}
                className="flex items-center gap-1 px-2.5 py-1 text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-950/40 rounded-lg transition-colors cursor-pointer"
                title="Clear all scans"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear All</span>
              </button>
            )}
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* List of scans */}
        <div className="overflow-y-auto p-4 space-y-3 flex-1">
          {history.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-xs sm:text-sm">
              No scans recorded yet. Try scanning a suspicious URL or message!
            </div>
          ) : (
            history.map((item) => (
              <div
                key={item.scanId}
                onClick={() => {
                  onSelectScan(item);
                  onClose();
                }}
                className="p-3.5 rounded-xl bg-slate-950/60 hover:bg-slate-850/80 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer flex items-center justify-between gap-3 group"
              >
                <div className="flex items-start gap-3 overflow-hidden">
                  <div className={`p-2 rounded-lg shrink-0 ${
                    item.riskLevel === 'CRITICAL' || item.riskLevel === 'HIGH'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    {item.riskScore >= 60 ? (
                      <AlertTriangle className="w-4 h-4" />
                    ) : (
                      <ShieldCheck className="w-4 h-4" />
                    )}
                  </div>

                  <div className="overflow-hidden">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[11px] font-mono font-bold text-slate-300">
                        {item.detectedType}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 truncate group-hover:text-white transition-colors">
                      {item.inputPreview}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <div className="text-right">
                    <span className={`text-xs font-mono font-bold block ${
                      item.riskScore >= 75 ? 'text-rose-400' : item.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'
                    }`}>
                      {item.riskScore}/100
                    </span>
                    <span className="text-[9px] text-slate-500 uppercase font-mono">{item.riskLevel}</span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
                </div>
              </div>
            ))
          )}
        </div>

      </div>
    </div>
  );
}
