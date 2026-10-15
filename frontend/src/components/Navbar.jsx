import React from 'react';
import { ShieldCheck, History, PhoneCall } from 'lucide-react';

export default function Navbar({ onOpenHistory, historyCount }) {
  return (
    <header className="sticky top-0 z-40 w-full backdrop-blur-md bg-[#07090f]/90 border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between">

        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-11 h-11 rounded-xl bg-gradient-to-tr from-violet-500/20 to-indigo-600/30 border border-violet-500/40 shadow-lg shadow-violet-500/10">
            <ShieldCheck className="w-6 h-6 text-violet-400" />
            <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-400 animate-pulse"></div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-violet-300 bg-clip-text text-transparent">
                ScamGuard{' '}
                <span className="text-violet-400 font-mono text-sm px-1.5 py-0.5 rounded bg-violet-950/80 border border-violet-500/30">
                  AI
                </span>
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">Intelligent Scam &amp; Fraud Interception Platform</p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 sm:gap-4">

          {/* Scan History Button */}
          <button
            onClick={onOpenHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 bg-slate-800/80 border border-slate-700 hover:bg-slate-800 transition-all cursor-pointer"
            title="View Past Scans"
          >
            <History className="w-3.5 h-3.5 text-slate-400" />
            <span>History</span>
            {historyCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full bg-violet-500 text-white font-bold text-[10px]">
                {historyCount}
              </span>
            )}
          </button>

          {/* Emergency Helpline Pill — intentional UX safety feature, kept per spec */}
          <a
            href="tel:1930"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-emerald-300 bg-emerald-950/60 border border-emerald-500/40 hover:bg-emerald-900/40 transition-all"
            title="National Cyber Crime Helpline"
          >
            <PhoneCall className="w-3.5 h-3.5 text-emerald-400 animate-bounce" />
            <span className="hidden sm:inline">Helpline:</span>
            <span className="font-mono text-emerald-400 font-bold">1930</span>
          </a>

        </div>

      </div>
    </header>
  );
}
