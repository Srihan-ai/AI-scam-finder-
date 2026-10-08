import React, { useState } from 'react';
import VerdictCard from './VerdictCard';
import {
  AlertOctagon, ShieldCheck, Copy, Check, ExternalLink,
  Brain, Lock, Eye, CornerDownRight,
} from 'lucide-react';

export default function ScanResult({ result, onReset }) {
  const [copied, setCopied] = useState(false);

  if (!result) return null;

  const {
    scanId,
    timestamp,
    inputPreview,
    detectedType,
    riskScore,
    riskLevel,
    flags,
    aiExplanation,
  } = result;

  const handleCopySummary = () => {
    const summaryText = `[ScamGuard AI Safety Report]
Scan ID: ${scanId}
Timestamp: ${new Date(timestamp).toLocaleString()}
Type: ${detectedType}
Verdict: ${aiExplanation.verdict || ''}
Risk Score: ${riskScore}/100 (${riskLevel})
Grade: ${aiExplanation.safetyRatingGrade}

WHY UNSAFE:
${aiExplanation.whyUnsafe}

DETECTED RED FLAGS:
${flags.map(f => `- [${f.severity}] ${f.title}: ${f.detail}`).join('\n')}

SAFETY CHECKLIST:
${aiExplanation.checklist.map((c, i) => `${i + 1}. ${c}`).join('\n')}

Emergency Helpline: Call 1930 (National Cyber Crime Portal)`;

    navigator.clipboard.writeText(summaryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'HIGH':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto mt-8 space-y-6 animate-in fade-in duration-500">

      {/* Top Meta Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 px-2 text-xs text-slate-400 font-mono">
        <div className="flex items-center gap-2">
          <span>SCAN ID: <strong className="text-violet-400">{scanId}</strong></span>
          <span>•</span>
          <span>DETECTED TYPE: <strong className="text-slate-200">{detectedType}</strong></span>
        </div>
        <div>
          <span>{new Date(timestamp).toLocaleTimeString()} ({new Date(timestamp).toLocaleDateString()})</span>
        </div>
      </div>

      {/* 1. Verdict Card */}
      <VerdictCard
        verdict={aiExplanation.verdict}
        verdictDescription={aiExplanation.verdictDescription}
        riskScore={riskScore}
        detectedType={detectedType}
      />

      {/* 2. AI Threat Explanation */}
      <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 sm:p-6 shadow-xl backdrop-blur-xl">
        <div className="flex items-center gap-2.5 mb-3 border-b border-slate-800 pb-3">
          <div className="p-2 rounded-lg bg-violet-500/10 border border-violet-500/20 text-violet-400">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base sm:text-lg font-bold text-white">
              AI Security Analysis: Why This May Be Unsafe
            </h3>
            <p className="text-xs text-slate-400">Transparent breakdown of deception vectors and threat mechanics</p>
          </div>
        </div>

        {/* Primary Explanation Text */}
        <div className="prose prose-invert max-w-none text-slate-300 text-sm sm:text-base leading-relaxed mb-5 bg-slate-950/50 p-4 rounded-xl border border-slate-800/80">
          <p>{aiExplanation.whyUnsafe}</p>
        </div>

        {/* Attack Vector & Psychological Tactics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

          {/* Psychological Tactics */}
          <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/60">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Eye className="w-4 h-4 text-purple-400" />
              <span>Psychological Manipulation Vectors</span>
            </h4>
            <ul className="space-y-2">
              {aiExplanation.psychologicalTactics.map((tactic, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs sm:text-sm text-slate-400">
                  <CornerDownRight className="w-3.5 h-3.5 text-purple-400 mt-0.5 shrink-0" />
                  <span>{tactic}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Technical Anatomy */}
          <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/60">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-rose-400" />
              <span>Technical Anatomy &amp; Exploitation</span>
            </h4>
            <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
              {aiExplanation.technicalImpact}
            </p>
          </div>

        </div>
      </div>

      {/* 3. Flagged Risk Patterns */}
      <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 sm:p-6 shadow-xl backdrop-blur-xl">
        <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-amber-400" />
            <h3 className="text-base sm:text-lg font-bold text-white">
              Flagged Risk Patterns ({flags.length})
            </h3>
          </div>
          <span className="text-xs text-slate-400">Heuristic &amp; Rule Engine Signals</span>
        </div>

        <div className="space-y-3">
          {flags.map((flag, idx) => (
            <div
              key={idx}
              className="p-3.5 sm:p-4 rounded-xl bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition-all"
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-sm font-semibold text-slate-200">
                  {flag.title}
                </span>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${getSeverityBadge(flag.severity)}`}>
                  {flag.severity}
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 leading-normal">
                {flag.detail}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* 4. Safety Checklist */}
      <div className="rounded-2xl bg-gradient-to-br from-violet-950/30 to-indigo-950/30 border border-violet-800/40 p-5 sm:p-6 shadow-xl">
        <h3 className="text-base sm:text-lg font-bold text-white mb-2 flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-violet-400" />
          <span>Recommended Safety Checklist</span>
        </h3>
        <p className="text-xs text-slate-400 mb-4">Immediate protective measures to prevent identity or financial theft:</p>

        <div className="space-y-2.5">
          {aiExplanation.checklist.map((step, idx) => (
            <div key={idx} className="flex items-start gap-3 p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
              <div className="flex items-center justify-center w-5 h-5 rounded-full bg-violet-500/20 text-violet-300 font-mono text-xs font-bold shrink-0 mt-0.5">
                {idx + 1}
              </div>
              <span className="text-xs sm:text-sm text-slate-300 font-medium">
                {step}
              </span>
            </div>
          ))}
        </div>

        {/* Action Button Row */}
        <div className="flex flex-wrap items-center justify-between gap-3 mt-6 pt-4 border-t border-slate-800">
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">

            {/* Copy Report */}
            <button
              onClick={handleCopySummary}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-all cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Report Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Incident Summary</span>
                </>
              )}
            </button>

            {/* Official Report Link */}
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold text-rose-300 bg-rose-950/60 hover:bg-rose-900/60 border border-rose-700/60 transition-all"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Report to CyberCrime.gov.in</span>
            </a>

          </div>

          <button
            onClick={onReset}
            className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            Scan Another Item
          </button>
        </div>

      </div>

    </div>
  );
}
