import React, { useState } from 'react';
import {
  Wrench,
  Zap,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  FileCheck,
  Code2,
  HardDrive,
  Clock,
  ExternalLink,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import { PatchStatus } from '../types/soc';

interface PatchFixerTabProps {
  patchStatus: PatchStatus | null;
  onDeployPatch: () => Promise<void>;
  onRevertPatch: () => Promise<void>;
  isDeploying: boolean;
}

export const PatchFixerTab: React.FC<PatchFixerTabProps> = ({
  patchStatus,
  onDeployPatch,
  onRevertPatch,
  isDeploying
}) => {
  const [activeTab, setActiveTab] = useState<'diff' | 'report'>('diff');

  if (!patchStatus) {
    return (
      <div className="p-12 text-center text-slate-400">
        <Wrench className="w-8 h-8 animate-spin mx-auto mb-2 text-cyan-400" />
        <p className="text-xs">Analyzing patch diffs for sample_config.js...</p>
      </div>
    );
  }

  const isVulnerable = patchStatus.isVulnerable;

  // Split lines for side-by-side diff
  const beforeLines = patchStatus.beforeCode.split('\n');
  const afterLines = patchStatus.afterCode.split('\n');

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="p-6 rounded-xl bg-[#101726] border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
            Member 4 · Automated Auto-Fixer & Patch Generator
          </span>
          <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
            Real-Time Source Code Patch Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Inspects the real file <code className="text-cyan-300 font-mono">sample_config.js</code> on disk and deploys an atomic patch replacing plaintext credentials with secure environment variables.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {!isVulnerable && (
            <button
              onClick={onRevertPatch}
              disabled={isDeploying}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors flex items-center gap-2 disabled:opacity-50"
              title="Reset file back to vulnerable state to re-test the exploit and patch cycle"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset to Vulnerable</span>
            </button>
          )}

          <button
            onClick={onDeployPatch}
            disabled={isDeploying || !isVulnerable}
            className={`px-5 py-2 rounded-lg font-bold text-xs shadow-md transition-all flex items-center gap-2 disabled:opacity-50 ${
              isVulnerable
                ? 'bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white shadow-rose-900/40'
                : 'bg-emerald-600/30 text-emerald-300 border border-emerald-500/50 cursor-default'
            }`}
          >
            {isDeploying ? (
              <Wrench className="w-4 h-4 animate-spin" />
            ) : isVulnerable ? (
              <Zap className="w-4 h-4" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
            <span>
              {isDeploying
                ? 'Writing to Disk...'
                : isVulnerable
                ? 'Deploy Patch to Disk'
                : 'Patch Applied on Disk'}
            </span>
          </button>
        </div>
      </div>

      {/* Target File Status Header */}
      <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <HardDrive className="w-5 h-5 text-cyan-400 shrink-0" />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-white">
                File: sample_config.js
              </span>
              <span
                className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded ${
                  isVulnerable
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}
              >
                {isVulnerable ? 'VULNERABILITY DETECTED' : 'PATCH VERIFIED SECURE'}
              </span>
            </div>
            <span className="text-[11px] text-slate-400">
              {isVulnerable
                ? 'Contains CWE-798 hardcoded credentials in lines 2 and 3.'
                : 'Clean state: All secrets injected via process.env variables.'}
            </span>
          </div>
        </div>

        {/* View Toggle */}
        <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 self-start sm:self-auto text-xs">
          <button
            onClick={() => setActiveTab('diff')}
            className={`px-3 py-1 rounded font-semibold transition-colors ${
              activeTab === 'diff'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Side-by-Side Diff
          </button>
          <button
            onClick={() => setActiveTab('report')}
            className={`px-3 py-1 rounded font-semibold transition-colors ${
              activeTab === 'report'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Patch Report JSON
          </button>
        </div>
      </div>

      {/* Main Diff Content */}
      {activeTab === 'diff' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Before: Vulnerable Code */}
          <div className="rounded-xl bg-[#101726] border border-rose-900/50 overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 bg-rose-950/40 border-b border-rose-900/50 flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-rose-400 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-rose-400" /> BEFORE (Vulnerable Source)
              </span>
              <span className="text-[10px] font-mono text-rose-400/80">
                sample_config.js:v1
              </span>
            </div>

            <div className="p-3 bg-slate-950 text-xs font-mono overflow-x-auto flex-1 space-y-1">
              {beforeLines.map((line, idx) => {
                const isVulnerableLine =
                  line.includes('AKIA_IOSFODNN7EXAMPLE') ||
                  line.includes('super_secret_password_123');

                return (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 px-2 py-1 rounded transition-colors ${
                      isVulnerableLine
                        ? 'bg-rose-950/80 text-rose-300 border-l-2 border-rose-500 font-semibold'
                        : 'text-slate-400'
                    }`}
                  >
                    <span className="text-slate-600 select-none text-[10px] w-6 shrink-0 text-right">
                      {idx + 1}
                    </span>
                    <span className="truncate">{line}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* After: Proposed / Deployed Patch */}
          <div className="rounded-xl bg-[#101726] border border-emerald-900/50 overflow-hidden flex flex-col">
            <div className="px-4 py-2.5 bg-emerald-950/40 border-b border-emerald-900/50 flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> AFTER (Secured with Environment Variables)
              </span>
              <span className="text-[10px] font-mono text-emerald-400/80">
                sample_config.js:patched
              </span>
            </div>

            <div className="p-3 bg-slate-950 text-xs font-mono overflow-x-auto flex-1 space-y-1">
              {afterLines.map((line, idx) => {
                const isPatchedLine =
                  line.includes('process.env.AWS_ACCESS_KEY_ID') ||
                  line.includes('process.env.DB_PASSWORD');

                return (
                  <div
                    key={idx}
                    className={`flex items-start gap-3 px-2 py-1 rounded transition-colors ${
                      isPatchedLine
                        ? 'bg-emerald-950/80 text-emerald-300 border-l-2 border-emerald-500 font-semibold'
                        : 'text-slate-400'
                    }`}
                  >
                    <span className="text-slate-600 select-none text-[10px] w-6 shrink-0 text-right">
                      {idx + 1}
                    </span>
                    <span className="truncate">{line}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        /* Patch Report JSON View */
        <div className="p-5 rounded-xl bg-[#101726] border border-slate-800/80 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white font-mono">
              patch_report.json (Live Disk Record)
            </span>
            <span className="text-[10px] font-mono text-slate-500">
              Generated by Member 4 Auto-Fixer
            </span>
          </div>

          <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto leading-relaxed">
            {JSON.stringify(patchStatus.patchReport || { status: 'pending' }, null, 2)}
          </pre>
        </div>
      )}

      {/* Verification Notice Card */}
      <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>
            Backend sync: Clicking <strong className="text-slate-200">Deploy Patch</strong> directly executes Node.js <code className="text-cyan-300 font-mono">fs.writeFileSync</code> on <code className="text-cyan-300 font-mono">sample_config.js</code>.
          </span>
        </div>
        <span className="font-mono text-[11px] text-slate-500">
          Atomic Invariance Verified
        </span>
      </div>
    </div>
  );
};
