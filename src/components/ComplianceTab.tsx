import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Code2,
  Search,
  SlidersHorizontal,
  ChevronRight,
  X,
  ExternalLink,
  Layers,
  ArrowRight,
  Zap
} from 'lucide-react';
import { ComplianceReport, ComplianceRule } from '../types/soc';

interface ComplianceTabProps {
  complianceReport: ComplianceReport | null;
  onSelectFramework: (framework: 'SOC2' | 'OWASP' | 'GDPR' | 'NIST') => void;
  onToggleRule: (ruleId: string, passed: boolean) => void;
  onNavigateToPatcher: () => void;
}

export const ComplianceTab: React.FC<ComplianceTabProps> = ({
  complianceReport,
  onSelectFramework,
  onToggleRule,
  onNavigateToPatcher
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PASS' | 'FAIL'>('ALL');
  const [selectedRule, setSelectedRule] = useState<ComplianceRule | null>(null);

  if (!complianceReport) {
    return (
      <div className="p-12 text-center text-slate-400">
        <ShieldCheck className="w-8 h-8 animate-spin mx-auto mb-2 text-cyan-400" />
        <p className="text-xs">Loading compliance frameworks...</p>
      </div>
    );
  }

  const frameworks: Array<{ id: 'SOC2' | 'OWASP' | 'GDPR' | 'NIST'; label: string; tag: string }> = [
    { id: 'SOC2', label: 'SOC 2 Type II', tag: 'AICPA Trust' },
    { id: 'OWASP', label: 'OWASP Top 10', tag: 'LLM & API' },
    { id: 'GDPR', label: 'GDPR / ISO 27001', tag: 'EU Privacy' },
    { id: 'NIST', label: 'NIST CSF 2.0', tag: 'Fed Standard' }
  ];

  const rules = complianceReport.rules || [];

  const filteredRules = rules.filter((rule) => {
    const matchesSearch =
      rule.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.category.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'PASS' && rule.passed) ||
      (statusFilter === 'FAIL' && !rule.passed);

    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Top Framework Selector & Metrics Bar */}
      <div className="p-6 rounded-xl bg-[#101726] border border-slate-800/80">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
              Regulatory Framework Inspector
            </span>
            <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
              {complianceReport.name}
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              {complianceReport.description}
            </p>
          </div>

          {/* Interactive Framework Segmented Selector */}
          <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-900/90 rounded-lg border border-slate-800">
            {frameworks.map((fw) => (
              <button
                key={fw.id}
                onClick={() => onSelectFramework(fw.id)}
                className={`px-3 py-1.5 rounded text-xs font-semibold transition-all whitespace-nowrap ${
                  complianceReport.framework === fw.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {fw.label}
              </button>
            ))}
          </div>
        </div>

        {/* Score & Control Counters */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-6">
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800/70 flex items-center justify-between">
            <div>
              <span className="text-xs text-slate-400">Compliance Posture Score</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span
                  className={`text-2xl font-extrabold font-mono tabular-nums ${
                    complianceReport.score === 100
                      ? 'text-emerald-400'
                      : complianceReport.score >= 70
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {complianceReport.score}%
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  {complianceReport.status}
                </span>
              </div>
            </div>
            <div
              className={`w-10 h-10 rounded-full flex items-center justify-center font-mono text-xs font-bold ${
                complianceReport.score === 100
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
              }`}
            >
              {complianceReport.score}%
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800/70">
            <span className="text-xs text-slate-400">Controls Met</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-extrabold font-mono text-emerald-400 tabular-nums">
                {complianceReport.passedCount}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                / {complianceReport.totalCount} active controls
              </span>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800/70">
            <span className="text-xs text-slate-400">Action Required</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span
                className={`text-2xl font-extrabold font-mono tabular-nums ${
                  complianceReport.totalCount - complianceReport.passedCount > 0
                    ? 'text-rose-400'
                    : 'text-emerald-400'
                }`}
              >
                {complianceReport.totalCount - complianceReport.passedCount}
              </span>
              <span className="text-xs text-slate-400">
                {complianceReport.totalCount - complianceReport.passedCount > 0
                  ? 'failing controls need patch'
                  : 'all controls validated'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Rules Breakdown Table & Drawer Container */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Rules Table (8 or 12 cols) */}
        <div className={`${selectedRule ? 'lg:col-span-7' : 'lg:col-span-12'} bg-[#101726] rounded-xl border border-slate-800/80 p-5 transition-all`}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Regulatory Control Invariants
              </h3>
              <p className="text-xs text-slate-400">
                Click any control to open remediation instructions and live configuration toggles.
              </p>
            </div>

            <div className="flex items-center gap-2">
              {/* Filter Tabs */}
              <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs">
                {(['ALL', 'PASS', 'FAIL'] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setStatusFilter(filter)}
                    className={`px-2.5 py-1 rounded font-medium transition-colors ${
                      statusFilter === filter
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Search Field */}
          <div className="relative mb-3">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search rule ID, category, or title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2.5 px-3">Rule ID</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Control Name</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredRules.map((rule) => {
                  const isSelected = selectedRule?.id === rule.id;
                  return (
                    <tr
                      key={rule.id}
                      onClick={() => setSelectedRule(rule)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-950/30 text-white'
                          : 'hover:bg-slate-800/40 text-slate-300'
                      }`}
                    >
                      <td className="py-3 px-3 font-mono font-bold text-cyan-400">
                        {rule.id}
                      </td>
                      <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                        {rule.category}
                      </td>
                      <td className="py-3 px-3 font-semibold text-slate-200">
                        {rule.name}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            rule.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : rule.severity === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                          }`}
                        >
                          {rule.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        {rule.passed ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-mono font-semibold text-[11px]">
                            <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-400 font-mono font-semibold text-[11px]">
                            <XCircle className="w-3.5 h-3.5" /> FAIL
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detailed Remediation Drawer (5 cols) */}
        {selectedRule && (
          <div className="lg:col-span-5 bg-[#101726] rounded-xl border border-slate-800/80 p-5 flex flex-col relative animate-in fade-in slide-in-from-right-2 duration-200">
            <button
              onClick={() => setSelectedRule(null)}
              className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              title="Close Remediation Drawer"
              aria-label="Close Remediation Drawer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="border-b border-slate-800 pb-3 mb-4">
              <span className="text-[11px] font-mono text-cyan-400 font-bold block">
                {selectedRule.id} · {selectedRule.category}
              </span>
              <h3 className="text-sm font-bold text-white mt-1">
                {selectedRule.name}
              </h3>
            </div>

            <div className="space-y-4 text-xs flex-1">
              <div>
                <span className="text-slate-400 text-[11px] block mb-1 font-semibold">
                  Invariant Description
                </span>
                <p className="text-slate-300 bg-slate-900/90 p-3 rounded-lg border border-slate-800 leading-relaxed">
                  {selectedRule.description}
                </p>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] block mb-1 font-semibold">
                  Required Remediation Step
                </span>
                <p className="text-cyan-200 bg-cyan-950/30 p-3 rounded-lg border border-cyan-800/50 leading-relaxed">
                  {selectedRule.remediation}
                </p>
              </div>

              {selectedRule.codeSnippet && (
                <div>
                  <span className="text-slate-400 text-[11px] block mb-1 font-semibold flex items-center gap-1">
                    <Code2 className="w-3.5 h-3.5 text-cyan-400" /> Reference Implementation
                  </span>
                  <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto">
                    {selectedRule.codeSnippet}
                  </pre>
                </div>
              )}

              {/* Live Rule Status Override Toggle */}
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold text-slate-200 block">
                    Simulate Control Invariant
                  </span>
                  <span className="text-[11px] text-slate-400">
                    Toggle state to test recalculation of compliance posture
                  </span>
                </div>

                <button
                  onClick={() => onToggleRule(selectedRule.id, !selectedRule.passed)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition-colors ${
                    selectedRule.passed
                      ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-600/30'
                      : 'bg-rose-600/20 text-rose-300 border border-rose-500/40 hover:bg-rose-600/30'
                  }`}
                >
                  {selectedRule.passed ? 'SET TO FAIL' : 'SET TO PASS'}
                </button>
              </div>

              {!selectedRule.passed && (
                <div className="pt-2">
                  <button
                    onClick={onNavigateToPatcher}
                    className="w-full py-2 px-3 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-bold text-xs shadow-md transition-all flex items-center justify-center gap-1.5"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Trigger Auto-Fix in Tab 4</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
