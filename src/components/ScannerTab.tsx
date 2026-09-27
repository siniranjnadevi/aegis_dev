import React, { useState } from 'react';
import {
  Code2,
  FileCode,
  Eye,
  EyeOff,
  AlertOctagon,
  RefreshCw,
  FolderTree,
  CheckCircle2,
  ArrowRight,
  ShieldAlert,
  Zap,
  Copy,
  Check
} from 'lucide-react';
import { ScannerStatus, Vulnerability } from '../types/soc';

interface ScannerTabProps {
  scannerStatus: ScannerStatus | null;
  onRunScan: () => void;
  isScanning: boolean;
  onNavigateToPatcher: () => void;
}

export const ScannerTab: React.FC<ScannerTabProps> = ({
  scannerStatus,
  onRunScan,
  isScanning,
  onNavigateToPatcher
}) => {
  const [selectedFile, setSelectedFile] = useState<string>('sample_config.js');
  const [unmaskedSecrets, setUnmaskedSecrets] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const vulnerabilities = scannerStatus?.vulnerabilities || [];

  const toggleMask = (id: string) => {
    setUnmaskedSecrets((prev) => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filesInTree = [
    { name: 'sample_config.js', hasVulnerabilities: vulnerabilities.length > 0, size: '248 bytes' },
    { name: 'scan_report.json', hasVulnerabilities: false, size: '612 bytes' },
    { name: 'patch_report.json', hasVulnerabilities: false, size: '380 bytes' },
    { name: 'threat_map_report.json', hasVulnerabilities: false, size: '890 bytes' }
  ];

  const filteredVulnerabilities = vulnerabilities.filter((v) => {
    if (severityFilter === 'ALL') return true;
    return v.severity.toUpperCase() === severityFilter;
  });

  return (
    <div className="space-y-6">
      {/* Top Action & Status Banner */}
      <div className="p-6 rounded-xl bg-[#101726] border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
            Member 1 · Code & Secret Scanner
          </span>
          <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
            Static Application Security Testing (SAST)
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Detects plaintext API keys, cloud tokens, database passwords, and CWE-798 vulnerabilities across source files and repositories.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onRunScan}
            disabled={isScanning}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold shadow-md shadow-cyan-900/30 transition-all flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Scanning Codebase...' : 'Execute Code Scanner'}</span>
          </button>
        </div>
      </div>

      {/* Multi-Column Layout: Left (File Explorer + Vuln Table) | Right (Secret Inspector) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Explorer & Table (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* File Explorer Tree */}
          <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80">
            <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 mb-3">
              <FolderTree className="w-4 h-4 text-cyan-400" /> Target Source Files
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {filesInTree.map((f) => (
                <button
                  key={f.name}
                  onClick={() => setSelectedFile(f.name)}
                  className={`p-2.5 rounded-lg border text-left flex items-center justify-between transition-all ${
                    selectedFile === f.name
                      ? 'bg-slate-800/90 border-cyan-500/50 text-white'
                      : 'bg-slate-900/60 border-slate-800 hover:bg-slate-800/40 text-slate-400'
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span className="text-xs font-mono font-medium truncate">{f.name}</span>
                  </div>
                  {f.hasVulnerabilities ? (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold shrink-0">
                      {vulnerabilities.length} LEAKS
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-slate-500 shrink-0">
                      {f.size}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Vulnerabilities Table */}
          <div className="p-5 rounded-xl bg-[#101726] border border-slate-800/80">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Identified Secret Leaks
                </h3>
                <span className="text-xs text-slate-400">
                  {vulnerabilities.length} active findings in target repository
                </span>
              </div>

              {/* Severity Filter */}
              <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
                {(['ALL', 'CRITICAL', 'HIGH'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-2.5 py-0.5 rounded font-medium transition-colors ${
                      severityFilter === sev
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {filteredVulnerabilities.length === 0 ? (
              <div className="p-8 text-center bg-slate-900/50 rounded-lg border border-slate-800 text-slate-400">
                <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-400 mb-2" />
                <p className="text-xs font-semibold text-slate-200">Zero Plaintext Secrets Found</p>
                <p className="text-[11px] text-slate-500 mt-1">
                  sample_config.js is clean or patched with environment variables.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredVulnerabilities.map((vuln) => {
                  const isUnmasked = unmaskedSecrets[vuln.id] || false;
                  return (
                    <div
                      key={vuln.id}
                      className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all space-y-2.5"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/20">
                            {vuln.id}
                          </span>
                          <span className="text-xs font-bold text-slate-100">
                            {vuln.type}
                          </span>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-rose-500/20 text-rose-400 border border-rose-500/30">
                          {vuln.severity}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300">
                        {vuln.description}
                      </p>

                      {/* Code Snippet with line number */}
                      <div className="p-2.5 bg-slate-950 rounded border border-slate-800/80 font-mono text-[11px] flex items-center justify-between">
                        <div className="flex items-center gap-3 overflow-hidden">
                          <span className="text-slate-500 select-none border-r border-slate-800 pr-2">
                            L{vuln.line}
                          </span>
                          <code className="text-rose-300 truncate">
                            {vuln.snippet}
                          </code>
                        </div>

                        <button
                          onClick={() => copyToClipboard(vuln.snippet, vuln.id)}
                          className="p-1 text-slate-400 hover:text-white shrink-0"
                          title="Copy snippet"
                        >
                          {copiedId === vuln.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>

                      {/* Mask / Unmask Toggle Bar */}
                      <div className="flex items-center justify-between pt-1">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-400 text-[11px]">Secret Value:</span>
                          <span className="font-mono text-xs font-bold text-amber-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                            {isUnmasked ? vuln.secretValue : vuln.maskedValue}
                          </span>
                          <button
                            onClick={() => toggleMask(vuln.id)}
                            className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                            title={isUnmasked ? 'Mask Secret' : 'Unmask Secret'}
                          >
                            {isUnmasked ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                          </button>
                        </div>

                        <span className="text-[11px] font-mono text-slate-400">
                          File: <span className="text-slate-200">{vuln.file}</span>
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Inspector & Code Viewer Panel (5 cols) */}
        <div className="lg:col-span-5 bg-[#101726] rounded-xl border border-slate-800/80 p-5 flex flex-col">
          <div className="border-b border-slate-800 pb-3 mb-4 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-wide">
              Raw File Content Inspector
            </h3>
            <span className="font-mono text-xs text-cyan-400">{selectedFile}</span>
          </div>

          <div className="flex-1 flex flex-col space-y-4">
            <div>
              <span className="text-[11px] text-slate-400 block mb-1 font-semibold">
                Live Disk Buffer ({selectedFile})
              </span>
              <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto max-h-[300px] leading-relaxed">
                {scannerStatus?.rawContent || '// No content read from disk'}
              </pre>
            </div>

            <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-2">
              <span className="text-xs font-bold text-white flex items-center gap-1.5">
                <AlertOctagon className="w-4 h-4 text-rose-400" /> CWE-798 Risk Analysis
              </span>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Hardcoding credentials directly inside source control enables unauthorized API access, database compromise, and automated harvesting by malicious actors.
              </p>
            </div>

            <div className="mt-auto pt-4 border-t border-slate-800">
              <button
                onClick={onNavigateToPatcher}
                className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs shadow-md transition-all flex items-center justify-center gap-2"
              >
                <Zap className="w-4 h-4" />
                <span>Send to Automated Patch Fixer (Tab 4)</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
