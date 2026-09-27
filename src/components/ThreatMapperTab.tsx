import React, { useState } from 'react';
import {
  Network,
  Bot,
  ShieldAlert,
  ShieldCheck,
  Send,
  Zap,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Layers,
  ChevronRight,
  Terminal,
  Cpu,
  RefreshCw
} from 'lucide-react';
import { ThreatMapReport, KillChainStep } from '../types/soc';

interface ThreatMapperTabProps {
  threatMap: ThreatMapReport | null;
  onDeployPatch: () => void;
  onAskCopilot: (question: string) => Promise<{ answer: string; source: string }>;
  isDeploying: boolean;
}

export const ThreatMapperTab: React.FC<ThreatMapperTabProps> = ({
  threatMap,
  onDeployPatch,
  onAskCopilot,
  isDeploying
}) => {
  const [selectedStep, setSelectedStep] = useState<KillChainStep | null>(
    threatMap?.killChainSteps[0] || null
  );
  const [copilotQuestion, setCopilotQuestion] = useState<string>('');
  const [copilotHistory, setCopilotHistory] = useState<
    Array<{ sender: 'user' | 'assistant'; text: string; source?: string }>
  >([
    {
      sender: 'assistant',
      text:
        'Hello Operator. I am the AEGIS SecOps Threat Copilot. I have mapped the multi-step exploit chain targeting our database cluster. You can ask me how to break the kill-chain or query any node for immediate isolation steps.',
      source: 'AEGIS Enterprise Intelligence'
    }
  ]);
  const [isAsking, setIsAsking] = useState<boolean>(false);

  if (!threatMap) {
    return (
      <div className="p-12 text-center text-slate-400">
        <Network className="w-8 h-8 animate-spin mx-auto mb-2 text-cyan-400" />
        <p className="text-xs">Computing threat pathway graph across microservices...</p>
      </div>
    );
  }

  const isMitigated = threatMap.status === 'mitigated';

  const handleAsk = async (questionText?: string) => {
    const q = (questionText || copilotQuestion).trim();
    if (!q || isAsking) return;

    setCopilotHistory((prev) => [...prev, { sender: 'user', text: q }]);
    setCopilotQuestion('');
    setIsAsking(true);

    try {
      const response = await onAskCopilot(q);
      setCopilotHistory((prev) => [
        ...prev,
        { sender: 'assistant', text: response.answer, source: response.source }
      ]);
    } catch (err: any) {
      setCopilotHistory((prev) => [
        ...prev,
        {
          sender: 'assistant',
          text: `Error contacting SecOps Copilot engine: ${err?.message || 'Server timeout'}`
        }
      ]);
    } finally {
      setIsAsking(false);
    }
  };

  const sampleQuestions = [
    'How does patching sample_config.js break this exploit chain?',
    'What egress firewall rule isolates the database tier?',
    'Explain the AI Firewall protection at Step 2'
  ];

  return (
    <div className="space-y-6">
      {/* Top Threat Posture Summary */}
      <div className="p-6 rounded-xl bg-[#101726] border border-slate-800/80">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400">
                Member 5 · Threat Mapper & SecOps Copilot
              </span>
              <span
                className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded ${
                  isMitigated
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    : 'bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse'
                }`}
              >
                {isMitigated ? 'KILL-CHAIN SEVERED' : 'ACTIVE EXPLOIT CHAIN DETECTED'}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white tracking-tight mt-1">
              Multi-Step Microservice Attack Pathway Graph
            </h2>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl leading-relaxed">
              {threatMap.summary}
            </p>
          </div>

          {!isMitigated && (
            <button
              onClick={onDeployPatch}
              disabled={isDeploying}
              className="px-4 py-2 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white text-xs font-bold shadow-md shadow-rose-900/30 transition-all flex items-center gap-2 self-start md:self-auto shrink-0 disabled:opacity-50"
            >
              <Zap className="w-4 h-4" />
              <span>{isDeploying ? 'Deploying...' : 'Break Chain via Auto-Fixer'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Visual Threat-Pathway Timeline */}
      <div className="p-6 rounded-xl bg-[#101726] border border-slate-800/80">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            Attack Progression Pathway across Microservices
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            Click any node below to inspect targeted mitigation steps
          </span>
        </div>

        {/* Nodes Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
          {threatMap.killChainSteps.map((step, idx) => {
            const isSelected = selectedStep?.id === step.id;
            const isStepVulnerable = step.status.includes('Vulnerable') || step.status.includes('Exposed');

            return (
              <div
                key={step.id}
                onClick={() => setSelectedStep(step)}
                className={`p-4 rounded-xl border cursor-pointer transition-all relative ${
                  isSelected
                    ? 'bg-slate-800/90 border-cyan-400 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-400/30'
                    : isStepVulnerable
                    ? 'bg-rose-950/20 border-rose-900/50 hover:border-slate-600'
                    : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                {/* Step Pill */}
                <div className="flex items-center justify-between text-xs mb-2">
                  <span className="font-mono text-[10px] text-cyan-400 font-bold">
                    STEP 0{step.step}
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                      isStepVulnerable
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}
                  >
                    {step.status}
                  </span>
                </div>

                <h4 className="text-xs font-bold text-white leading-snug">
                  {step.node}
                </h4>
                <span className="text-[11px] text-slate-400 font-mono block mt-0.5">
                  Target: {step.target}
                </span>

                <p className="text-[11px] text-slate-300 mt-2 line-clamp-3 leading-relaxed">
                  {step.action}
                </p>

                <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                  <span className="text-slate-500 font-mono">Risk: {step.riskLevel}</span>
                  <span className="text-cyan-400 font-semibold flex items-center gap-1">
                    Inspect <ChevronRight className="w-3 h-3" />
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Two-Column Master Detail: Selected Node Remediation | Interactive AI Copilot Chat */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Selected Pathway Node Details (5 cols) */}
        <div className="lg:col-span-5 bg-[#101726] rounded-xl border border-slate-800/80 p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <h3 className="text-sm font-bold text-white tracking-wide">
              Selected Pathway Node Forensics
            </h3>
            <span className="text-xs font-mono text-cyan-400">
              {selectedStep ? `Step 0${selectedStep.step}` : 'Select Node'}
            </span>
          </div>

          {selectedStep ? (
            <div className="space-y-3.5 text-xs">
              <div>
                <span className="text-slate-400 text-[11px] block font-semibold mb-0.5">
                  Microservice / Architecture Tier
                </span>
                <span className="text-white font-bold text-xs">{selectedStep.node}</span>
                <span className="text-slate-400 font-mono block text-[11px] mt-0.5">
                  Component: {selectedStep.microservice}
                </span>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] block font-semibold mb-0.5">
                  Adversary Vector Action
                </span>
                <p className="text-slate-200 bg-slate-900/90 p-3 rounded-lg border border-slate-800 leading-relaxed font-mono text-[11px]">
                  {selectedStep.action}
                </p>
              </div>

              <div>
                <span className="text-slate-400 text-[11px] block font-semibold mb-0.5">
                  AI Prescribed Remediation Step
                </span>
                <div className="p-3 bg-cyan-950/30 rounded-lg border border-cyan-800/50 text-cyan-200 leading-relaxed">
                  {selectedStep.mitigation}
                </div>
              </div>

              {selectedStep.step === 1 && !isMitigated && (
                <div className="pt-2">
                  <button
                    onClick={onDeployPatch}
                    disabled={isDeploying}
                    className="w-full py-2.5 px-3 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-md transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    <Zap className="w-4 h-4" />
                    <span>Apply Member 4 Auto-Fix Now</span>
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs">
              Click any step in the pathway above to view full forensics and mitigation scripts.
            </div>
          )}
        </div>

        {/* Right: Interactive AI SecOps Copilot Chat (7 cols) */}
        <div className="lg:col-span-7 bg-[#101726] rounded-xl border border-slate-800/80 p-5 flex flex-col">
          <div className="border-b border-slate-800 pb-3 mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                <Bot className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white tracking-wide">
                  AEGIS SecOps AI Copilot
                </h3>
                <span className="text-[10px] text-slate-400 font-mono">
                  Autonomous Threat Reasoning & Advisory
                </span>
              </div>
            </div>

            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              ACTIVE AGENT
            </span>
          </div>

          {/* Quick Prompts */}
          <div className="flex flex-wrap gap-1.5 mb-3">
            {sampleQuestions.map((q, idx) => (
              <button
                key={idx}
                onClick={() => handleAsk(q)}
                disabled={isAsking}
                className="text-[11px] px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 transition-colors text-left disabled:opacity-50"
              >
                {q}
              </button>
            ))}
          </div>

          {/* Chat Messages */}
          <div className="flex-1 overflow-y-auto max-h-[320px] space-y-3 p-3 bg-slate-950 rounded-lg border border-slate-800/80 mb-3">
            {copilotHistory.map((msg, idx) => (
              <div
                key={idx}
                className={`flex flex-col ${
                  msg.sender === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div
                  className={`max-w-[90%] p-3 rounded-xl text-xs leading-relaxed ${
                    msg.sender === 'user'
                      ? 'bg-cyan-600 text-white font-medium rounded-tr-none'
                      : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-none font-mono text-[11px]'
                  }`}
                >
                  <div className="whitespace-pre-wrap">{msg.text}</div>
                  {msg.source && (
                    <span className="block mt-1 text-[9px] text-slate-500 font-mono">
                      Source: {msg.source}
                    </span>
                  )}
                </div>
              </div>
            ))}
            {isAsking && (
              <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono p-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Copilot synthesizing threat intelligence...</span>
              </div>
            )}
          </div>

          {/* Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAsk();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={copilotQuestion}
              onChange={(e) => setCopilotQuestion(e.target.value)}
              placeholder="Ask Copilot about kill-chain mitigation, firewall rules, or patch impact..."
              disabled={isAsking}
              className="flex-1 px-3 py-2 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
            />
            <button
              type="submit"
              disabled={isAsking || !copilotQuestion.trim()}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Ask</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
