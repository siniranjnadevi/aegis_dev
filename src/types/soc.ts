export type ModuleTab = 'overview' | 'compliance' | 'scanner' | 'firewall' | 'patcher' | 'threatmap';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface AuditLog {
  id: string;
  timestamp: string;
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  message: string;
  details: string;
}

export interface TelemetryData {
  riskScore: number;
  status: 'HIGH_RISK' | 'NOMINAL';
  throughputMbps: string;
  packetRate: number;
  activeSockets: number;
  memoryUsageMB: string;
  isPatched: boolean;
  activeThreatsCount: number;
  auditLogs: AuditLog[];
}

export interface ComplianceRule {
  id: string;
  name: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  passed: boolean;
  description: string;
  remediation: string;
  codeSnippet?: string;
}

export interface ComplianceReport {
  framework: 'SOC2' | 'OWASP' | 'GDPR' | 'NIST';
  name: string;
  description: string;
  score: number;
  passedCount: number;
  totalCount: number;
  status: 'COMPLIANT' | 'NEEDS_REVIEW' | 'NON_COMPLIANT';
  rules: ComplianceRule[];
}

export interface Vulnerability {
  id: string;
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  file: string;
  line: number;
  snippet: string;
  secretValue: string;
  maskedValue: string;
  description: string;
}

export interface ScannerStatus {
  module: string;
  status: string;
  fileScanned: string;
  rawContent: string;
  vulnerabilitiesCount: number;
  vulnerabilities: Vulnerability[];
  lastScanned: string;
}

export interface FirewallInspectResult {
  safe: boolean;
  status: 'BLOCKED' | 'PASSED';
  error?: string;
  message?: string;
  matchedRule?: string;
  matchedPatterns?: string[];
  severity?: string;
  tokensAnalyzed: number;
  latencyMs: number;
  riskScore: number;
  aiEvaluation?: string;
  sanitizationNotice?: string;
  rawPayload: {
    prompt: string;
    timestamp: string;
    defenseHeaders: Record<string, string>;
  };
}

export interface PatchStatus {
  file: string;
  status: 'VULNERABLE' | 'PATCHED_SECURELY';
  isVulnerable: boolean;
  currentContent: string;
  beforeCode: string;
  afterCode: string;
  patchReport?: {
    status: string;
    file: string;
    action: string;
    timestamp: string;
    patchedItems?: Array<{ secret: string; replacedWith: string }>;
  } | null;
}

export interface KillChainStep {
  step: number;
  id: string;
  node: string;
  microservice: string;
  target: string;
  action: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Minimal';
  status: string;
  mitigation: string;
}

export interface ThreatMapReport {
  module: string;
  status: 'mitigated' | 'active_killchain';
  assistantName: string;
  totalAlertsAnalyzed: number;
  summary: string;
  killChainSteps: KillChainStep[];
  recommendedAction: string;
  timestamp: string;
}
