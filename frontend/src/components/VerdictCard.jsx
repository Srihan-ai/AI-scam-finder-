import React from 'react';
import { ShieldX, ShieldAlert, ShieldCheck } from 'lucide-react';

// Fallback verdict derivation for history items saved before the backend emitted
// verdict/verdictDescription fields. Thresholds MUST stay in sync with
// backend/analyzers/aiExplainer.js: >=60 → FAKE, >=35 → SUSPICIOUS, <35 → REAL.
function deriveVerdict(riskScore) {
  if (riskScore >= 60) {
    return {
      verdict: 'FAKE',
      verdictDescription: 'This content shows strong indicators of fraud. Do not interact with it.',
    };
  } else if (riskScore >= 35) {
    return {
      verdict: 'SUSPICIOUS',
      verdictDescription: 'This content has warning signs. Proceed with caution and verify through official channels.',
    };
  } else {
    return {
      verdict: 'REAL',
      verdictDescription: 'No significant threat patterns were detected. This content appears legitimate.',
    };
  }
}

const THEMES = {
  FAKE: {
    color: '#ef4444',
    Icon: ShieldX,
    cardClass: 'bg-red-950/40 border-red-500/50 shadow-[0_0_60px_rgba(239,68,68,0.15)]',
    textClass: 'text-[#ef4444]',
    badgeClass: 'bg-red-950/60 border-red-500/30 text-red-300',
  },
  SUSPICIOUS: {
    color: '#f59e0b',
    Icon: ShieldAlert,
    cardClass: 'bg-amber-950/40 border-amber-500/50 shadow-[0_0_60px_rgba(245,158,11,0.15)]',
    textClass: 'text-[#f59e0b]',
    badgeClass: 'bg-amber-950/60 border-amber-500/30 text-amber-300',
  },
  REAL: {
    color: '#22c55e',
    Icon: ShieldCheck,
    cardClass: 'bg-green-950/40 border-green-500/50 shadow-[0_0_60px_rgba(34,197,94,0.15)]',
    textClass: 'text-[#22c55e]',
    badgeClass: 'bg-green-950/60 border-green-500/30 text-green-300',
  },
};

export default function VerdictCard({ verdict, verdictDescription, riskScore, detectedType }) {
  // Fallback for history items without verdict
  let resolvedVerdict = verdict;
  let resolvedDescription = verdictDescription;
  if (!resolvedVerdict) {
    const derived = deriveVerdict(riskScore);
    resolvedVerdict = derived.verdict;
    resolvedDescription = derived.verdictDescription;
  }

  const theme = THEMES[resolvedVerdict] || THEMES.REAL;
  const { Icon, cardClass, textClass, badgeClass } = theme;

  return (
    <div
      className={`rounded-2xl border p-4 sm:p-5 backdrop-blur-xl flex flex-col items-center text-center ${cardClass}`}
    >
      {/* Shield Icon */}
      <Icon className="w-8 h-8 mb-2" style={{ color: theme.color }} />

      {/* Verdict Word */}
      <div className={`text-4xl sm:text-5xl font-black tracking-tighter mb-2 ${textClass}`}>
        {resolvedVerdict}
      </div>

      {/* Description */}
      <p className="text-sm text-slate-300 max-w-xl mb-3 leading-relaxed">
        {resolvedDescription}
      </p>

      {/* Secondary Info Badges */}
      <div className="flex flex-wrap items-center justify-center gap-2">
        {detectedType && (
          <span className={`text-xs font-mono font-semibold px-3 py-1 rounded-full border ${badgeClass}`}>
            {detectedType}
          </span>
        )}
        {riskScore !== undefined && (
          <span className={`text-xs font-mono font-semibold px-3 py-1 rounded-full border ${badgeClass}`}>
            Risk Score: {riskScore}/100
          </span>
        )}
      </div>
    </div>
  );
}
