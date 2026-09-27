import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Terminal,
  Code2,
  FileCheck,
  Network,
  Activity,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Flame,
  Cpu,
  Layers,
  Search,
  Filter,
  ArrowRight
} from 'lucide-react';
import { ModuleTab, TelemetryData, AuditLog } from '../types/soc';

interface OverviewCommandCenterProps {
  telemetry: TelemetryData | null;
  onNavigateTab: (tab: ModuleTab) => void;
  onDeployPatch: () => void;
  onRunScanner: () => void;
  isDeploying: boolean;
  isScanning: boolean;
}

export const OverviewCommandCenter: React.FC<OverviewCommandCenterProps> = ({
  telemetry,
  onNavigateTab,
  onDeployPatch,
  onRunScanner,
  isDeploying,
  isScanning
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  const isPatched = telemetry?.isPatched ?? false;
  const riskScore = telemetry?.riskScore ?? (isPatched ? 18 : 86);

  const filteredLogs = (telemetry?.auditLogs || []).filter((log) => {
    const matchesSev = selectedSeverity === 'ALL' || log.severity === selectedSeverity;
    const matchesQuery =
      searchQuery === '' ||
      log.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.source.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesQuery;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner Alert (when vulnerable) */}
      {!isPatched && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-rose-950/70 via-rose-900/40 to-slate-900 border border-rose-800/80 shadow-lg shadow-rose-950/20 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-rose-500/20 border border-rose-500/30 text-rose-400 shrink-0">
              <Flame className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-white tracking-wide">
                  CRITICAL INCIDENT: Exploitable Credentials in Source Code
                </span>
                <span className="text-[11px] font-mono text-rose-300">
                  CVE-2026-AEGIS · CWE-798
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                Plaintext AWS Key and DB password located in <code className="text-rose-300 font-mono">sample_config.js</code>. Multi-step kill chain is actively exposing database tier.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end md:self-auto shrink-0">
            <button
              onClick={() => onNavigateTab('scanner')}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
            >
              Inspect Leak
            </button>
            <button
              onClick={onDeployPatch}
              disabled={isDeploying}
              className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-md shadow-rose-900/40 transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>{isDeploying ? 'Applying Patch...' : 'Auto-Fix Now'}</span>
            </button>
          </div>
        </div>
      )}

      {/* KPI Stat Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Global Risk Posture */}
        <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Global Threat Score</span>
            <span className={`font-mono text-xs font-bold ${isPatched ? 'text-emerald-400' : 'text-rose-400'}`}>
              {isPatched ? 'SECURE' : 'CRITICAL'}
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-3xl font-extrabold font-mono tabular-nums tracking-tight ${isPatched ? 'text-emerald-400' : 'text-rose-400'}`}>
              {riskScore}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                isPatched ? 'bg-emerald-500 w-[18%]' : 'bg-rose-500 w-[86%]'
              }`}
            />
          </div>
          <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
            <span>{isPatched ? 'Baselines nominal' : '3 critical exposures'}</span>
            <span>Tolerance &lt; 25</span>
          </div>
        </div>

        {/* Card 2: AI Guardrail Throughput */}
        <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>AI Firewall Guardrail</span>
            <span className="font-mono text-xs text-cyan-400 font-bold">ONLINE</span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100 tabular-nums tracking-tight">
              1,842
            </span>
            <span className="text-xs text-emerald-400 font-medium">99.8% blocked</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-3 pt-2 border-t border-slate-800/60">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Avg inspection: <strong className="text-slate-200 font-mono tabular-nums">14ms</strong></span>
          </div>
        </div>

        {/* Card 3: Code Vulnerability Status */}
        <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Code & Secret Vulnerabilities</span>
            <span className={`font-mono text-xs font-bold ${isPatched ? 'text-emerald-400' : 'text-rose-400'}`}>
              {isPatched ? 'RESOLVED' : 'UNPATCHED'}
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-3xl font-extrabold font-mono tabular-nums tracking-tight ${isPatched ? 'text-emerald-400' : 'text-rose-400'}`}>
              {isPatched ? '0' : '2'}
            </span>
            <span className="text-xs text-slate-400">discovered in sample_config.js</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 mt-3 pt-2 border-t border-slate-800/60">
            <span className="truncate">CWE-798: Plaintext AWS/DB</span>
            <button
              onClick={() => onNavigateTab('scanner')}
              className="text-cyan-400 hover:text-cyan-300 text-xs font-medium shrink-0 flex items-center gap-1"
            >
              Scan <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Card 4: Compliance Alignment */}
        <div className="p-4 rounded-xl bg-[#101726] border border-slate-800/80 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>SOC 2 Type II Posture</span>
            <span className={`font-mono text-xs font-bold ${isPatched ? 'text-emerald-400' : 'text-amber-400'}`}>
              {isPatched ? '100% PASS' : '80% REVIEW'}
            </span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-3xl font-extrabold font-mono text-slate-100 tabular-nums tracking-tight">
              {isPatched ? '100%' : '80%'}
            </span>
            <span className="text-xs text-slate-400">{isPatched ? '5/5 controls met' : '4/5 controls met'}</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 mt-3 pt-2 border-t border-slate-800/60">
            <span className="text-[11px] text-slate-400">SOC2-005 Secret Invariance</span>
            <button
              onClick={() => onNavigateTab('compliance')}
              className="text-cyan-400 hover:text-cyan-300 text-xs font-medium shrink-0 flex items-center gap-1"
            >
              Audits <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Microservice Threat Pathway & Defense Matrix */}
      <div className="p-5 rounded-xl bg-[#101726] border border-slate-800/80">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Active Attack Vector Timeline & Defense Matrix
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Multi-step exploit chain mapping microservice interactions and live mitigation hooks.
            </p>
          </div>

          <button
            onClick={() => onNavigateTab('threatmap')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 self-start sm:self-auto"
          >
            Open Interactive Threat Graph <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* 4 Pipeline Microservice Stages */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {/* Stage 1 */}
          <div
            onClick={() => onNavigateTab('scanner')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all hover:border-slate-600 ${
              isPatched
                ? 'bg-emerald-950/20 border-emerald-800/40 text-slate-200'
                : 'bg-rose-950/30 border-rose-800/60 text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-mono text-[10px] text-slate-400 uppercase">Stage 01 · Repo</span>
              <span className={`text-[10px] font-bold font-mono ${isPatched ? 'text-emerald-400' : 'text-rose-400'}`}>
                {isPatched ? 'NEUTRALIZED' : 'VULNERABLE'}
              </span>
            </div>
            <h4 className="text-xs font-semibold text-white">GitHub Source Repo</h4>
            <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
              {isPatched
                ? 'Secrets replaced with environment variables.'
                : 'AWS Key and DB password exposed in sample_config.js.'}
            </p>
            <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>Member 1 Scanner</span>
              <span className="text-cyan-400">Inspect &rarr;</span>
            </div>
          </div>

          {/* Stage 2 */}
          <div
            onClick={() => onNavigateTab('firewall')}
            className="p-3.5 rounded-lg border bg-cyan-950/20 border-cyan-800/40 text-slate-200 cursor-pointer transition-all hover:border-slate-600"
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-mono text-[10px] text-slate-400 uppercase">Stage 02 · Ingress</span>
              <span className="text-[10px] font-bold font-mono text-cyan-400">GUARDRAIL ACTIVE</span>
            </div>
            <h4 className="text-xs font-semibold text-white">AI Gateway & Model API</h4>
            <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
              Inspects incoming prompt payloads for adversarial jailbreaks and role shifts.
            </p>
            <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>Member 2 Firewall</span>
              <span className="text-cyan-400">Launch Sandbox &rarr;</span>
            </div>
          </div>

          {/* Stage 3 */}
          <div
            onClick={() => onNavigateTab('compliance')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all hover:border-slate-600 ${
              isPatched
                ? 'bg-emerald-950/20 border-emerald-800/40 text-slate-200'
                : 'bg-amber-950/20 border-amber-800/40 text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-mono text-[10px] text-slate-400 uppercase">Stage 03 · IAM Bus</span>
              <span className={`text-[10px] font-bold font-mono ${isPatched ? 'text-emerald-400' : 'text-amber-400'}`}>
                {isPatched ? 'ENFORCED' : 'AUDIT PENDING'}
              </span>
            </div>
            <h4 className="text-xs font-semibold text-white">Microservice Auth</h4>
            <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
              Enforces SOC 2 least-privilege tokens and prevents lateral privilege elevation.
            </p>
            <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>Member 3 Compliance</span>
              <span className="text-cyan-400">Review Rules &rarr;</span>
            </div>
          </div>

          {/* Stage 4 */}
          <div
            onClick={() => onNavigateTab('patcher')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all hover:border-slate-600 ${
              isPatched
                ? 'bg-emerald-950/20 border-emerald-800/40 text-slate-200'
                : 'bg-rose-950/30 border-rose-800/60 text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-mono text-[10px] text-slate-400 uppercase">Stage 04 · Data Tier</span>
              <span className={`text-[10px] font-bold font-mono ${isPatched ? 'text-emerald-400' : 'text-rose-400'}`}>
                {isPatched ? 'ISOLATED' : 'TARGET AT RISK'}
              </span>
            </div>
            <h4 className="text-xs font-semibold text-white">Cloud Database & Storage</h4>
            <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
              {isPatched
                ? 'Database protected. Direct password access severed.'
                : 'Direct credential compromise path active.'}
            </p>
            <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] font-mono text-slate-400">
              <span>Member 4 Auto-Fixer</span>
              <span className="text-cyan-400">Deploy Patch &rarr;</span>
            </div>
          </div>
        </div>
      </div>

      {/* Master-Detail Live Alert Stream & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Alerts Table (7 cols) */}
        <div className="lg:col-span-7 bg-[#101726] rounded-xl border border-slate-800/80 p-5 flex flex-col">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Live SOC Audit & Alert Stream
              </h3>
              <p className="text-xs text-slate-400">
                Real-time security events captured across all 5 integrated engines.
              </p>
            </div>

            {/* Filter buttons */}
            <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800 self-start sm:self-auto">
              {(['ALL', 'CRITICAL', 'HIGH', 'INFO'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSelectedSeverity(sev)}
                  className={`px-2.5 py-1 text-[11px] font-semibold rounded transition-colors ${
                    selectedSeverity === sev
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Search Box */}
          <div className="relative mb-3">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search audit events by message, source, or CWE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Alert Stream List */}
          <div className="flex-1 overflow-y-auto max-h-[380px] space-y-2 pr-1">
            {filteredLogs.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">
                No events match current filter criteria.
              </div>
            ) : (
              filteredLogs.map((log) => {
                const isSelected = selectedLog?.id === log.id;
                return (
                  <div
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-slate-800/90 border-cyan-500/50 shadow-md'
                        : 'bg-slate-900/60 border-slate-800/70 hover:bg-slate-800/50'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                            log.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : log.severity === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                          }`}
                        >
                          {log.severity}
                        </span>
                        <span className="text-xs font-semibold text-slate-200">
                          {log.source}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400 tabular-nums">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 leading-snug line-clamp-2">
                      {log.message}
                    </p>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Expansive Event Inspector (5 cols) */}
        <div className="lg:col-span-5 bg-[#101726] rounded-xl border border-slate-800/80 p-5 flex flex-col">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <h3 className="text-sm font-bold text-white tracking-wide">
              Inspector & Action Panel
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              {selectedLog ? selectedLog.id : 'Live Focus'}
            </span>
          </div>

          {selectedLog ? (
            <div className="space-y-4 text-xs">
              <div>
                <span className="text-[11px] text-slate-400 block mb-0.5">Event Source</span>
                <span className="font-semibold text-white">{selectedLog.source}</span>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block mb-0.5">Severity Level</span>
                <span
                  className={`inline-block font-mono text-xs font-bold px-2 py-0.5 rounded ${
                    selectedLog.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-400'
                      : selectedLog.severity === 'HIGH'
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-cyan-500/20 text-cyan-400'
                  }`}
                >
                  {selectedLog.severity}
                </span>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block mb-0.5">Timestamp (UTC)</span>
                <span className="font-mono text-slate-300">{selectedLog.timestamp}</span>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block mb-0.5">Incident Description</span>
                <p className="text-slate-200 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] leading-relaxed">
                  {selectedLog.message}
                </p>
              </div>

              <div>
                <span className="text-[11px] text-slate-400 block mb-0.5">Forensic Telemetry</span>
                <p className="text-slate-300 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 font-mono text-[11px] leading-relaxed">
                  {selectedLog.details}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center gap-2">
                <button
                  onClick={() => {
                    if (selectedLog.source.includes('Scanner')) onNavigateTab('scanner');
                    else if (selectedLog.source.includes('Firewall')) onNavigateTab('firewall');
                    else if (selectedLog.source.includes('Fixer')) onNavigateTab('patcher');
                    else if (selectedLog.source.includes('Compliance')) onNavigateTab('compliance');
                    else onNavigateTab('threatmap');
                  }}
                  className="w-full py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-1.5"
                >
                  <span>Investigate in Module</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-6 text-slate-400">
              <Activity className="w-10 h-10 text-slate-600 mb-3" />
              <p className="text-xs font-semibold text-slate-300">No Alert Selected</p>
              <p className="text-[11px] text-slate-500 mt-1 max-w-xs">
                Select any log row on the left to inspect raw payloads, telemetry headers, and execute targeted remediations.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
