import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Code2,
  Terminal,
  Wrench,
  Network,
  Activity,
  ChevronLeft,
  ChevronRight,
  Server,
  Cpu,
  Lock
} from 'lucide-react';
import { ModuleTab, TelemetryData } from '../types/soc';

interface SidebarProps {
  currentTab: ModuleTab;
  onSelectTab: (tab: ModuleTab) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  telemetry: TelemetryData | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  collapsed,
  onToggleCollapse,
  telemetry
}) => {
  const isVulnerable = telemetry ? !telemetry.isPatched : true;

  const navItems: Array<{
    id: ModuleTab;
    label: string;
    sublabel: string;
    icon: React.ComponentType<{ className?: string }>;
    alertCount?: number;
    alertVariant?: 'danger' | 'warning' | 'info';
  }> = [
    {
      id: 'overview',
      label: 'Command Center',
      sublabel: 'Global Telemetry & Streams',
      icon: Activity,
    },
    {
      id: 'compliance',
      label: 'Compliance Checker',
      sublabel: 'SOC2 · OWASP · GDPR · NIST',
      icon: ShieldCheck,
      alertCount: isVulnerable ? 1 : 0,
      alertVariant: 'warning'
    },
    {
      id: 'scanner',
      label: 'Code Scanner',
      sublabel: 'Secrets & CWE-798 Audits',
      icon: Code2,
      alertCount: isVulnerable ? 2 : 0,
      alertVariant: 'danger'
    },
    {
      id: 'firewall',
      label: 'AI Firewall Sandbox',
      sublabel: 'Guardrail & Prompt Shield',
      icon: Terminal,
    },
    {
      id: 'patcher',
      label: 'Automated Patch Fixer',
      sublabel: 'Live File Writes & Diff View',
      icon: Wrench,
      alertCount: isVulnerable ? 1 : 0,
      alertVariant: 'danger'
    },
    {
      id: 'threatmap',
      label: 'Threat Mapper & Copilot',
      sublabel: 'Kill-Chain & AI Mitigations',
      icon: Network,
      alertCount: isVulnerable ? 4 : 1,
      alertVariant: isVulnerable ? 'danger' : 'info'
    },
  ];

  return (
    <aside
      className={`fixed top-0 bottom-0 left-0 z-40 bg-[#0d131f] border-r border-slate-800/80 flex flex-col transition-all duration-300 ${
        collapsed ? 'w-18' : 'w-72'
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 px-4 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shrink-0 shadow-lg shadow-cyan-500/20">
            <Lock className="w-5 h-5 text-white" />
          </div>
          {!collapsed && (
            <div className="flex flex-col min-w-0">
              <span className="text-sm font-bold tracking-tight text-white uppercase whitespace-nowrap">
                AEGIS DEV
              </span>
              <span className="text-[11px] text-slate-400 font-mono tracking-wider whitespace-nowrap">
                ENTERPRISE SOC v3.4
              </span>
            </div>
          )}
        </div>

        <button
          onClick={onToggleCollapse}
          className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          aria-label={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Live System Health Badge */}
      <div className="p-3 border-b border-slate-800/60 bg-slate-900/40">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5 shrink-0">
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isVulnerable ? 'bg-amber-400' : 'bg-emerald-400'
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                isVulnerable ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
            />
          </span>

          {!collapsed && (
            <div className="flex flex-col min-w-0">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-300 truncate">
                {isVulnerable ? 'Active Threats Detected' : 'Perimeter Secured'}
              </span>
              <span className="text-[10px] font-mono text-slate-400 truncate">
                Cluster: us-east-aegis-01
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
              }`}
              title={collapsed ? `${item.label} (${item.sublabel})` : undefined}
            >
              <Icon className={`w-5 h-5 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />

              {!collapsed && (
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold tracking-wide text-slate-100 truncate">
                      {item.label}
                    </span>
                    {typeof item.alertCount === 'number' && item.alertCount > 0 && (
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                          item.alertVariant === 'danger'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : item.alertVariant === 'warning'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        }`}
                      >
                        {item.alertCount}
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-slate-400 truncate block mt-0.5">
                    {item.sublabel}
                  </span>
                </div>
              )}
            </button>
          );
        })}
      </nav>

      {/* Live Hardware & Telemetry Gauges */}
      {!collapsed && (
        <div className="p-3 mx-2 mb-3 rounded-lg bg-[#080d16] border border-slate-800/70 text-xs">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-cyan-400" /> Live Throughput
            </span>
            <span className="font-mono text-[11px] text-cyan-400 tabular-nums font-bold">
              {telemetry ? telemetry.throughputMbps : '142.4'} MB/s
            </span>
          </div>

          <div className="space-y-1.5 text-[10px] font-mono text-slate-400">
            <div className="flex justify-between">
              <span>Packets/Sec</span>
              <span className="text-slate-200 tabular-nums">
                {telemetry ? telemetry.packetRate.toLocaleString() : '48,500'} pps
              </span>
            </div>
            <div className="flex justify-between">
              <span>Heap Allocation</span>
              <span className="text-slate-200 tabular-nums">
                {telemetry ? telemetry.memoryUsageMB : '38.4'} MB
              </span>
            </div>
            <div className="flex justify-between">
              <span>Active Sockets</span>
              <span className="text-slate-200 tabular-nums">
                {telemetry ? telemetry.activeSockets : '342'} conn
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Operator Session Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-[#090e18] flex items-center gap-3">
        <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 text-xs font-mono font-bold text-cyan-400">
          OP
        </div>
        {!collapsed && (
          <div className="flex flex-col min-w-0">
            <span className="text-xs font-semibold text-slate-200 truncate">
              SecOps Lead Operator
            </span>
            <span className="text-[10px] font-mono text-slate-400 truncate">
              ID: OP-8375 · Clearance L4
            </span>
          </div>
        )}
      </div>
    </aside>
  );
};
