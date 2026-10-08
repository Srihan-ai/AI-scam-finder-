import React, { useRef, useState } from 'react';
import { Link as LinkIcon, MessageSquare, Upload, Clipboard, XCircle, ArrowRight } from 'lucide-react';

export default function ScannerInput({
  input,
  setInput,
  scanType,
  setScanType,
  onScan,
  isScanning,
  onClear,
  uploadedFileName,
  setUploadedFileName,
}) {
  const fileInputRef = useRef(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setInput(text);
    } catch (err) {
      console.warn('Clipboard read failed:', err);
    }
  };

  const handleFile = (file) => {
    if (!file) return;
    const ext = file.name.split('.').pop().toLowerCase();
    if (['png', 'jpg', 'jpeg', 'webp', 'gif'].includes(ext)) {
      setInput(`[Image file: ${file.name}] User uploaded a screenshot for scam analysis.`);
      setUploadedFileName(file.name);
    } else if (ext === 'pdf') {
      // PDFs are binary — never attempt text extraction; use sentinel unconditionally
      setInput(`[PDF file: ${file.name}] User uploaded a PDF document for scam analysis.`);
      setUploadedFileName(file.name);
    } else {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result;
        setInput(text.slice(0, 4000));
      };
      reader.readAsText(file);
      setUploadedFileName(file.name);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => setIsDragOver(false);

  const handleFileInputChange = (e) => {
    const file = e.target.files[0];
    if (file) handleFile(file);
  };

  const handleClearAll = () => {
    setUploadedFileName('');
    if (fileInputRef.current) fileInputRef.current.value = '';
    onClear();
  };

  const tabs = [
    { id: 'URL', label: 'Link', icon: LinkIcon },
    { id: 'MESSAGE', label: 'Message', icon: MessageSquare },
    { id: 'FILE', label: 'File', icon: Upload },
  ];

  const isFileTab = scanType === 'FILE';
  const canScan = isFileTab ? !!input.trim() : !!input.trim();

  return (
    <div className="w-full max-w-4xl mx-auto">
      <div
        className={`relative rounded-2xl bg-slate-900/90 border border-slate-700/80 shadow-2xl shadow-violet-950/20 backdrop-blur-xl overflow-hidden p-4 sm:p-6 transition-all focus-within:border-violet-500/60 focus-within:ring-2 focus-within:ring-violet-500/20`}
      >
        {/* Mode Selector Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-1 sm:gap-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = scanType === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setScanType(tab.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    isActive
                      ? 'bg-violet-600 text-white font-semibold shadow-md shadow-violet-500/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* Quick Paste / Clear */}
          <div className="flex items-center gap-2">
            {!isFileTab && (
              <button
                onClick={handlePaste}
                type="button"
                className="flex items-center gap-1 px-2.5 py-1 text-xs text-slate-400 hover:text-violet-300 bg-slate-800/60 hover:bg-slate-850 rounded-md border border-slate-700/60 transition-all cursor-pointer"
              >
                <Clipboard className="w-3 h-3" />
                <span>Paste</span>
              </button>
            )}
            {(input || uploadedFileName) && (
              <button
                onClick={handleClearAll}
                type="button"
                className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-rose-400 bg-slate-800/60 hover:bg-rose-950/40 rounded-md border border-slate-700/60 transition-all cursor-pointer"
              >
                <XCircle className="w-3 h-3" />
                <span>Clear</span>
              </button>
            )}
          </div>
        </div>

        {/* Text Area (Link / Message tabs) */}
        {!isFileTab && (
          <div className="relative">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                  onScan();
                }
              }}
              rows={4}
              placeholder={
                scanType === 'URL'
                  ? 'Paste suspicious website link or domain (e.g. http://sbi-kyc-update.xyz)...'
                  : 'Paste SMS, WhatsApp, or email message (e.g. "Dear customer electricity will be disconnected tonight...")...'
              }
              className="w-full bg-slate-950/60 text-slate-100 placeholder-slate-500 rounded-xl p-3.5 text-sm sm:text-base border border-slate-800 focus:outline-none focus:border-violet-500/50 resize-y min-h-[110px]"
            />
          </div>
        )}

        {/* File Upload Zone */}
        {isFileTab && (
          <div>
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => fileInputRef.current?.click()}
              className={`flex flex-col items-center justify-center gap-3 rounded-xl border-2 border-dashed p-8 cursor-pointer transition-all min-h-[140px] ${
                isDragOver
                  ? 'border-violet-500/70 bg-violet-950/30'
                  : 'border-slate-700 bg-slate-950/40 hover:border-violet-500/50 hover:bg-violet-950/20'
              }`}
            >
              <Upload className="w-10 h-10 text-slate-500" />
              <div className="text-center">
                <p className="text-sm font-medium text-slate-300">
                  Drag &amp; drop a file here, or{' '}
                  <span className="text-violet-400 underline">browse</span>
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Supports: .txt, .pdf, .png, .jpg, .jpeg, .webp, .gif
                </p>
              </div>
            </div>

            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.pdf,.png,.jpg,.jpeg,.webp,.gif"
              className="hidden"
              onChange={handleFileInputChange}
            />

            {/* Loaded File Chip */}
            {uploadedFileName && (
              <div className="flex items-center gap-2 mt-3 px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-300">
                <span className="text-emerald-400 font-bold">✓</span>
                <span className="font-medium truncate max-w-xs">{uploadedFileName}</span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setUploadedFileName('');
                    setInput('');
                    if (fileInputRef.current) fileInputRef.current.value = '';
                  }}
                  className="ml-auto text-slate-400 hover:text-rose-400 transition-colors cursor-pointer"
                >
                  <XCircle className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}

        {/* Bottom Actions */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 mt-4 pt-3 border-t border-slate-800/80">
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>Zero-Knowledge ephemeral scan: Credentials are never logged.</span>
          </div>

          <button
            onClick={onScan}
            disabled={isScanning || !canScan}
            className={`flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl font-semibold text-sm transition-all cursor-pointer ${
              !canScan || isScanning
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
                : 'bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 text-white font-bold shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40 active:scale-98'
            }`}
          >
            {isScanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                <span>Analyzing Patterns...</span>
              </>
            ) : (
              <>
                <span>Check Now</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
