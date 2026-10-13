import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import ScannerInput from './components/ScannerInput';
import ScanResult from './components/ScanResult';
import HistoryModal from './components/HistoryModal';
import { ShieldCheck, AlertCircle } from 'lucide-react';

export default function App() {
  const [input, setInput] = useState('');
  const [scanType, setScanType] = useState('URL');
  const [result, setResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState('');

  const resultRef = useRef(null);

  // Load history from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('scamguard_history');
      if (saved) {
        setHistory(JSON.parse(saved));
      }
    } catch (e) {
      console.warn('History load error:', e);
    }
  }, []);

  // Save history to localStorage
  const saveToHistory = (scanItem) => {
    try {
      const updated = [scanItem, ...history.filter(h => h.scanId !== scanItem.scanId)].slice(0, 30);
      setHistory(updated);
      localStorage.setItem('scamguard_history', JSON.stringify(updated));
    } catch (e) {
      console.warn('History save error:', e);
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
    localStorage.removeItem('scamguard_history');
  };

  // Perform scan
  const handleScan = async (overrideInput = null, overrideType = null) => {
    const targetInput = (overrideInput !== null ? overrideInput : input).trim();
    // FILE tab maps to AUTO (let backend detect)
    const rawType = overrideType !== null ? overrideType : scanType;
    const targetType = rawType === 'FILE' ? null : rawType;

    if (!targetInput) {
      setError('Please enter or paste a suspicious link, message, or upload a file.');
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      const API_BASE = import.meta.env.VITE_API_URL || '';
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: targetInput, scanType: targetType }),
      });

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || 'Failed to complete analysis');
      }

      const data = await response.json();
      setResult(data);
      saveToHistory(data);

      // Smooth scroll to result
      setTimeout(() => {
        if (resultRef.current) {
          resultRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, 100);

    } catch (err) {
      console.error('Scan error:', err);
      setError(err.message || 'Unable to scan content. Please check connection and try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleClear = () => {
    setInput('');
    setResult(null);
    setError(null);
    setUploadedFileName('');
  };

  return (
    <div className="min-h-screen bg-[#111318] text-slate-100 flex flex-col">

      {/* Navbar */}
      <Navbar
        onOpenHistory={() => setIsHistoryOpen(true)}
        historyCount={history.length}
      />

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12 flex flex-col items-center">

        {/* Hero Section */}
        <div className="text-center max-w-3xl mx-auto mb-8 sm:mb-12">
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-white leading-tight mb-4">
            Check Before You Click {' '}
            <span className="text-[#ef4444]">FAKE</span>
            {' '}or{' '}
            <span className="text-[#22c55e]">REAL</span>.
          </h1>
          <p className="text-slate-400 text-base sm:text-lg leading-relaxed max-w-2xl mx-auto">
            Scam links, messages, screenshots, files — analyzed in seconds.
          </p>
        </div>

        {/* Primary Scanner Input */}
        <ScannerInput
          input={input}
          setInput={setInput}
          scanType={scanType}
          setScanType={setScanType}
          onScan={() => handleScan()}
          isScanning={isScanning}
          onClear={handleClear}
          uploadedFileName={uploadedFileName}
          setUploadedFileName={setUploadedFileName}
        />

        {/* Error Alert */}
        {error && (
          <div className="w-full max-w-4xl mx-auto mt-4 p-4 rounded-xl bg-rose-950/40 border border-rose-500/50 text-rose-300 flex items-center gap-3 text-sm">
            <AlertCircle className="w-5 h-5 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Scan Result Section */}
        <div ref={resultRef} className="w-full">
          {result && (
            <ScanResult
              result={result}
              onReset={handleClear}
            />
          )}
        </div>

      </main>

      {/* Footer */}
      <footer className="w-full border-t border-slate-800 bg-[#121212] py-10 px-4 sm:px-6 lg:px-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">

          <div className="flex flex-col items-center md:items-start gap-1.5">
            <div className="flex items-center gap-2 text-slate-300 font-bold text-sm">
              <ShieldCheck className="w-4 h-4 text-violet-400" />
              <span>Smarter Detection. Safer Decisions.</span>
            </div>
            <p>AI-powered threat detection that helps you understand suspicious digital content.</p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 text-slate-400">
            <a href="tel:1930" className="hover:text-emerald-400 transition-colors font-mono font-semibold">
              1930 Helpline
            </a>
            <span>•</span>
            <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="hover:text-violet-400 transition-colors">
              cybercrime.gov.in
            </a>
          </div>

          <div className="text-center md:text-right text-[11px] text-slate-600">
            <span>© 2026 ScamGuard AI. All scans are ephemeral and strictly private.</span>
          </div>

        </div>
      </footer>

      {/* History Modal */}
      <HistoryModal
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        history={history}
        onSelectScan={(item) => {
          setResult(item);
          setInput(item.inputPreview);
          setIsHistoryOpen(false);
          setTimeout(() => {
            if (resultRef.current) {
              resultRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          }, 100);
        }}
        onClearHistory={handleClearHistory}
      />

    </div>
  );
}