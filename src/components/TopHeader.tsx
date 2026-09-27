import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Zap,
  Download,
  Clock,
  Radio,
  FileCheck
} from 'lucide-react';
import { ModuleTab, TelemetryData } from '../types/soc';

interface TopHeaderProps {
  currentTab: ModuleTab;
  telemetry: TelemetryData | null;
  onRunGlobalScan: () => void;
  onDeployPatch: () => void;
  onRefresh: () => void;
  isScanning: boolean;
  isDeploying: boolean;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  currentTab,
  telemetry,
  onRunGlobalScan,
  onDeployPatch,
  onRefresh,
  isScanning,
  isDeploying
}) => {
  const isVulnerable = telemetry ? !telemetry.isPatched : true;

  const tabLabels: Record<ModuleTab, { title: string; subtitle: string }> = {
    overview: {
      title: 'Command Center',
      subtitle: 'Global Cyber Threat Posture & Live Telemetry'
    },
    compliance: {
      title: 'Compliance Checker',
      subtitle: 'SOC2 Type II, OWASP LLM01, GDPR Art 32 & NIST CSF'
    },
    scanner: {
      title: 'Code & Secret Scanner',
      subtitle: 'CWE-798 Hardcoded Credential Detector & File Explorer'
    },
    firewall: {
      title: 'AI Firewall Sandbox',
      subtitle: 'Real-Time Prompt Injection & Jailbreak Guardrail Simulator'
    },
    patcher: {
      title: 'Automated Patch Fixer',
      subtitle: 'Side-by-Side Code Diff & Backend File System Writer'
    },
    threatmap: {
      title: 'AI Copilot & Threat Mapper',
      subtitle: 'Multi-Step Kill-Chain Graph & SecOps Remediation Assistant'
    }
  };

  const handleExportIncidentReport = () => {
    const reportData = {
      exportedAt: new Date().toISOString(),
      cluster: 'us-east-aegis-01',
      telemetry,
      status: isVulnerable ? 'VULNERABILITIES_ACTIVE' : 'SECURITY_BASELINE_COMPLIANT',
      recommendations: [
        'Enforce Member 2 AI Firewall on all inference APIs',
        'Verify zero hardcoded credentials in sample_config.js',
        'Maintain SOC 2 audit logs for 365 days'
      ]
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AEGIS-SOC-INCIDENT-REPORT-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <header className="h-16 px-6 bg-[#0b101a]/95 backdrop-blur-md border-b border-slate-800/80 flex items-center justify-between sticky top-0 z-30">
      {/* Zone 1: Breadcrumb Trail */}
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="text-slate-300 font-semibold tracking-wider">AEGIS</span>
          <span>/</span>
          <span className="text-slate-400">CLUSTER-01</span>
          <span>/</span>
          <span className="text-cyan-400 font-medium">{tabLabels[currentTab].title}</span>
        </div>
        <span className="hidden lg:inline-block w-px h-4 bg-slate-800" />
        <span className="hidden lg:inline-block text-xs text-slate-400 truncate max-w-xs">
          {tabLabels[currentTab].subtitle}
        </span>
      </div>

      {/* Zone 2: Risk Meter & Status Indicator */}
      <div className="flex items-center gap-4">
        {/* Dynamic Global Risk Indicator */}
        <div
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium ${
            isVulnerable
              ? 'bg-rose-950/40 border-rose-800/60 text-rose-300'
              : 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
          }`}
        >
          {isVulnerable ? (
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          ) : (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          )}
          <span className="font-semibold">
            {isVulnerable ? 'Global Risk: CRITICAL (86/100)' : 'Global Risk: NOMINAL (18/100)'}
          </span>
        </div>

        {/* Zone 3: Quick Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={onRunGlobalScan}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors border border-slate-700/80 disabled:opacity-50"
            title="Execute Code Scanner on sample_config.js"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isScanning ? 'animate-spin' : ''}`} />
            <span className="hidden sm:inline">{isScanning ? 'Scanning...' : 'Run Scanner'}</span>
          </button>

          {isVulnerable ? (
            <button
              onClick={onDeployPatch}
              disabled={isDeploying}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white text-xs font-semibold shadow-md shadow-rose-900/30 transition-all disabled:opacity-50"
              title="Deploy Automated Security Patch directly to sample_config.js"
            >
              <Zap className="w-3.5 h-3.5 text-white" />
              <span>{isDeploying ? 'Deploying...' : 'Deploy Auto-Patch'}</span>
            </button>
          ) : (
            <button
              onClick={onDeployPatch}
              disabled={isDeploying}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold transition-all disabled:opacity-50"
              title="Patch already applied to sample_config.js"
            >
              <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Patched Securely</span>
            </button>
          )}

          <button
            onClick={handleExportIncidentReport}
            className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-medium border border-slate-800 transition-colors"
            title="Download Full Forensic JSON Report"
          >
            <Download className="w-3.5 h-3.5 text-slate-400" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={onRefresh}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors"
            title="Refresh All SOC Feeds"
            aria-label="Refresh All SOC Feeds"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
