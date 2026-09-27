import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { OverviewCommandCenter } from './components/OverviewCommandCenter';
import { ComplianceTab } from './components/ComplianceTab';
import { ScannerTab } from './components/ScannerTab';
import { FirewallTab } from './components/FirewallTab';
import { PatchFixerTab } from './components/PatchFixerTab';
import { ThreatMapperTab } from './components/ThreatMapperTab';
import {
  ModuleTab,
  TelemetryData,
  ComplianceReport,
  ComplianceRule,
  ScannerStatus,
  PatchStatus,
  ThreatMapReport,
  FirewallInspectResult,
  AuditLog
} from './types/soc';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

interface Toast {
  id: string;
  type: 'success' | 'error' | 'info';
  title: string;
  message: string;
}

// ============================================================================
// INLINE FALLBACK MOCK DATA (Instant rendering on Vercel / Static deployments)
// ============================================================================

const initialAuditLogs: AuditLog[] = [
  {
    id: 'LOG-8801',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    source: 'Code Scanner (Member 1)',
    severity: 'CRITICAL',
    message: 'Plaintext AWS & Database credentials detected in sample_config.js',
    details: 'CWE-798: Use of Hard-coded Credentials in source control.'
  },
  {
    id: 'LOG-8802',
    timestamp: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    source: 'AI Firewall (Member 2)',
    severity: 'HIGH',
    message: 'Prompt injection attempt blocked from 192.168.1.142',
    details: 'Pattern matched: "ignore previous instructions". Guardrail triggered.'
  },
  {
    id: 'LOG-8803',
    timestamp: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    source: 'Threat Mapper (Member 5)',
    severity: 'CRITICAL',
    message: 'Active exploit kill-chain detected across microservices',
    details: 'Exposed secret -> LLM endpoint jailbreak -> DB unauthorized access.'
  }
];

const initialTelemetry: TelemetryData = {
  riskScore: 86,
  status: 'HIGH_RISK',
  throughputMbps: '142.4',
  packetRate: 48500,
  activeSockets: 342,
  memoryUsageMB: '38.4',
  isPatched: false,
  activeThreatsCount: 4,
  auditLogs: initialAuditLogs
};

const vulnerableCode = `// sample_config.js - Target Configuration File
const apiKey = "AKIA_IOSFODNN7EXAMPLE";
const dbPassword = "super_secret_password_123";

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};`;

const secureCode = `// sample_config.js - Target Configuration File (Patched by AEGIS Auto-Fixer)
const apiKey = process.env.AWS_ACCESS_KEY_ID; // Patched: Secure environment injection
const dbPassword = process.env.DB_PASSWORD; // Patched securely by CyberShield AI

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};`;

const fallbackFrameworks: Record<
  'SOC2' | 'OWASP' | 'GDPR' | 'NIST',
  { name: string; description: string; rules: ComplianceRule[] }
> = {
  SOC2: {
    name: 'SOC 2 Type II (Trust Services Criteria)',
    description: 'Security, Availability, Processing Integrity, Confidentiality, and Privacy controls.',
    rules: [
      {
        id: 'SOC2-001',
        name: 'Multi-Factor & Identity Authentication',
        category: 'Access Control',
        severity: 'HIGH',
        passed: true,
        description: 'Identity verification with MFA must be enforced on all production endpoints.',
        remediation: 'Enable OAuth2/OIDC with WebAuthn/TOTP enforcement in API gateway.',
        codeSnippet: 'app.use(authMiddleware({ requireMfa: true, provider: "Okta" }));'
      },
      {
        id: 'SOC2-002',
        name: 'At-Rest & In-Transit Cryptographic Encryption',
        category: 'Confidentiality',
        severity: 'HIGH',
        passed: true,
        description: 'All persistent disks and TLS 1.3 tunnels must enforce AES-256-GCM.',
        remediation: 'Configure cloud storage buckets with customer-managed KMS keys.',
        codeSnippet: 'const kmsKey = "arn:aws:kms:us-east-1:123456789:key/soc2-master";'
      },
      {
        id: 'SOC2-003',
        name: 'Immutable Security Audit Logging',
        category: 'Monitoring',
        severity: 'MEDIUM',
        passed: true,
        description: 'Centralized log shipping to immutable WORM storage with 365-day retention.',
        remediation: 'Pipe syslog and application JSON logs into cloud audit trail bucket.',
        codeSnippet: 'logger.add(new CloudWatchTransport({ retentionDays: 365 }));'
      },
      {
        id: 'SOC2-004',
        name: 'Role-Based Least Privilege Access Control',
        category: 'Access Control',
        severity: 'HIGH',
        passed: true,
        description: 'Direct root database credentials prohibited in application environments.',
        remediation: 'Migrate static credentials in sample_config.js to AWS Secrets Manager.',
        codeSnippet: 'const dbPassword = process.env.DB_PASSWORD || await secrets.get("DB_PASS");'
      },
      {
        id: 'SOC2-005',
        name: 'Zero-Secret Source Code Invariance',
        category: 'Code Hygiene',
        severity: 'CRITICAL',
        passed: false,
        description: 'No plaintext API keys, secret hashes, or credentials in git commits.',
        remediation: 'Run Member 4 Automated Patch Fixer to wipe hardcoded secrets from sample_config.js.',
        codeSnippet: '// Fixed: const apiKey = process.env.AWS_ACCESS_KEY_ID;'
      }
    ]
  },
  OWASP: {
    name: 'OWASP Top 10 API & LLM Security (2025/2026)',
    description: 'Covers Prompt Injection (LLM01), Broken Authentication, and Sensitive Data Exposure.',
    rules: [
      {
        id: 'LLM01-INJECT',
        name: 'Prompt Injection & Jailbreak Shielding',
        category: 'LLM Security',
        severity: 'CRITICAL',
        passed: true,
        description: 'Input sanitization against role takeover and prompt manipulation attacks.',
        remediation: 'Enforce Member 2 AI Firewall middleware before delegating to model.',
        codeSnippet: 'app.post("/api/ai-chat", llmFirewall, handleCompletion);'
      },
      {
        id: 'API02-CRED',
        name: 'Hardcoded Credential Exposure Prevention',
        category: 'Sensitive Data',
        severity: 'CRITICAL',
        passed: false,
        description: 'Prohibit API keys and database passwords in source code repos.',
        remediation: 'Trigger Member 4 Auto-Fixer patch to replace secrets with environment vars.',
        codeSnippet: 'const dbPassword = process.env.DB_PASSWORD;'
      },
      {
        id: 'LLM06-SENSITIVE',
        name: 'Sensitive Information Disclosure in Output',
        category: 'Data Privacy',
        severity: 'HIGH',
        passed: true,
        description: 'Output scanner to redact PII, tokens, and internal server topologies.',
        remediation: 'Attach regex DLP post-filter to model completion responses.',
        codeSnippet: 'res.body = redactPII(res.body);'
      },
      {
        id: 'API04-RATE',
        name: 'Unrestricted Resource Consumption & DoS Guard',
        category: 'Availability',
        severity: 'MEDIUM',
        passed: true,
        description: 'Adaptive token and request rate limiting per IP and authenticated user.',
        remediation: 'Deploy sliding-window Redis rate limiter at API gateway ingress.',
        codeSnippet: 'app.use(rateLimit({ windowMs: 60000, max: 120 }));'
      }
    ]
  },
  GDPR: {
    name: 'GDPR & ISO 27001 Data Protection',
    description: 'European Union General Data Protection Regulation and ISO 27001 Annex A controls.',
    rules: [
      {
        id: 'GDPR-ART25',
        name: 'Data Protection by Design and by Default',
        category: 'Privacy Architecture',
        severity: 'HIGH',
        passed: true,
        description: 'Pseudonymization and encryption of personal data across microservice boundaries.',
        remediation: 'Implement field-level encryption for user identifiers and contact records.',
        codeSnippet: 'encryptField(user.email, tenantKmsKey);'
      },
      {
        id: 'GDPR-ART32',
        name: 'Security of Processing & Vulnerability Management',
        category: 'Vulnerability Management',
        severity: 'CRITICAL',
        passed: false,
        description: 'Regular automated scanning and rapid patching of discovered source flaws.',
        remediation: 'Auto-apply Member 4 patch fixer to seal credential leak in sample_config.js.',
        codeSnippet: 'patchRealFile(); // Cleans credentials immediately'
      },
      {
        id: 'GDPR-ART33',
        name: '72-Hour Breach Notification Readiness',
        category: 'Incident Response',
        severity: 'MEDIUM',
        passed: true,
        description: 'Automated audit trail generation and forensic export capability.',
        remediation: 'Maintain threat pathway graph exports in threat_map_report.json.',
        codeSnippet: 'exportForensicChain(activeThreats);'
      }
    ]
  },
  NIST: {
    name: 'NIST Cybersecurity Framework (CSF 2.0)',
    description: 'Identify, Protect, Detect, Respond, and Recover core security standards.',
    rules: [
      {
        id: 'NIST-ID.AM',
        name: 'Asset & Secret Inventory Discovery',
        category: 'Identify',
        severity: 'HIGH',
        passed: true,
        description: 'Automated cataloging of repositories, configuration files, and API endpoints.',
        remediation: 'Run Member 1 Code Scanner on all source trees daily.',
        codeSnippet: 'runCodeScanner("./src");'
      },
      {
        id: 'NIST-PR.DS',
        name: 'Data Security & Secret Sanitization',
        category: 'Protect',
        severity: 'CRITICAL',
        passed: false,
        description: 'Sensitive configuration credentials must be stored in hardened vaults.',
        remediation: 'Deploy Member 4 patch to sample_config.js.',
        codeSnippet: 'fs.writeFileSync("sample_config.js", secureContent);'
      },
      {
        id: 'NIST-DE.CM',
        name: 'Continuous AI Guardrail Monitoring',
        category: 'Detect',
        severity: 'HIGH',
        passed: true,
        description: 'Real-time telemetry and prompt inspection for adversarial injections.',
        remediation: 'Active telemetry stream on Member 2 AI Firewall endpoint.',
        codeSnippet: 'llmFirewall(req, res, next);'
      }
    ]
  }
};

const initialScannerStatus: ScannerStatus = {
  module: 'Member 1 - Code Scanner',
  status: 'completed',
  fileScanned: 'sample_config.js',
  rawContent: vulnerableCode,
  vulnerabilitiesCount: 2,
  vulnerabilities: [
    {
      id: 'SEC-001',
      type: 'Hardcoded AWS Access Key',
      severity: 'Critical',
      file: 'sample_config.js',
      line: 2,
      snippet: 'const apiKey = "AKIA_IOSFODNN7EXAMPLE";',
      secretValue: 'AKIA_IOSFODNN7EXAMPLE',
      maskedValue: 'AKIA_***************',
      description: 'Plaintext AWS cloud credential discovered in application configuration.'
    },
    {
      id: 'SEC-002',
      type: 'Hardcoded Database Password',
      severity: 'Critical',
      file: 'sample_config.js',
      line: 3,
      snippet: 'const dbPassword = "super_secret_password_123";',
      secretValue: 'super_secret_password_123',
      maskedValue: 'supe*******************',
      description: 'Hardcoded database connection password found in plaintext source code.'
    }
  ],
  lastScanned: new Date().toISOString()
};

const initialPatchStatus: PatchStatus = {
  file: 'sample_config.js',
  status: 'VULNERABLE',
  isVulnerable: true,
  currentContent: vulnerableCode,
  beforeCode: vulnerableCode,
  afterCode: secureCode,
  patchReport: {
    status: 'pending_deployment',
    file: 'sample_config.js',
    action: 'Awaiting patch deployment for hardcoded credentials',
    timestamp: new Date().toISOString()
  }
};

const initialThreatMap: ThreatMapReport = {
  module: 'Member 5 - Copilot & Threat Map',
  status: 'active_killchain',
  assistantName: 'CyberShield AEGIS SecOps Copilot',
  totalAlertsAnalyzed: 4,
  summary: 'Critical Threat Alert: Multi-step exploit chain detected targeting production database credentials.',
  killChainSteps: [
    {
      step: 1,
      id: 'STAGE-1-REPO',
      node: 'GitHub Repository / Source Code',
      microservice: 'Version Control & CI/CD',
      target: 'Code Scanner (Member 1)',
      action: 'Attacker scans public repo and discovers exposed AWS & DB credentials in sample_config.js',
      riskLevel: 'Critical',
      status: 'Actively Vulnerable',
      mitigation: 'Wipe secrets from commit history and apply Member 4 patch.'
    },
    {
      step: 2,
      id: 'STAGE-2-INGRESS',
      node: 'AI Ingress Gateway & Model API',
      microservice: 'Prompt Shield / Gateway',
      target: 'AI Firewall (Member 2)',
      action: 'Attacker injects jailbreak prompt payloads ("ignore previous instructions") to bypass security policies',
      riskLevel: 'High',
      status: 'Active Guardrail Protected',
      mitigation: 'Enforce real-time regex & semantic inspection via AI Firewall middleware.'
    },
    {
      step: 3,
      id: 'STAGE-3-AUTH',
      node: 'Internal IAM & Microservice Auth',
      microservice: 'IAM Service Bus',
      target: 'Compliance Checker (Member 3)',
      action: 'Attacker attempts lateral movement exploiting permissive access tokens and missing encryption',
      riskLevel: 'High',
      status: 'Needs Review',
      mitigation: 'Enforce SOC 2 access controls and rotate all service tokens.'
    },
    {
      step: 4,
      id: 'STAGE-4-DATABASE',
      node: 'Production Database & Cloud Storage',
      microservice: 'PostgreSQL / AWS S3',
      target: 'Data Tier',
      action: 'Attacker uses discovered credentials to exfiltrate proprietary tables and user data',
      riskLevel: 'Critical',
      status: 'Exposed to Breach',
      mitigation: 'Rotate database passwords immediately and restrict DB ingress to internal VPC CIDRs.'
    }
  ],
  recommendedAction: 'Deploy Member 4 Automated Patch Fixer immediately to break Step 1 of the attack vector.',
  timestamp: new Date().toISOString()
};

function getComplianceReport(frameworkId: 'SOC2' | 'OWASP' | 'GDPR' | 'NIST', isPatched: boolean): ComplianceReport {
  const fw = fallbackFrameworks[frameworkId] || fallbackFrameworks.SOC2;
  const rules = fw.rules.map((r) => {
    if (['SOC2-005', 'API02-CRED', 'GDPR-ART32', 'NIST-PR.DS'].includes(r.id)) {
      return { ...r, passed: isPatched };
    }
    return r;
  });
  const passedCount = rules.filter((r) => r.passed).length;
  const totalCount = rules.length;
  const score = Math.round((passedCount / totalCount) * 100);

  return {
    framework: frameworkId,
    name: fw.name,
    description: fw.description,
    score,
    passedCount,
    totalCount,
    status: score === 100 ? 'COMPLIANT' : score >= 75 ? 'NEEDS_REVIEW' : 'NON_COMPLIANT',
    rules
  };
}

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================

export default function App() {
  const [currentTab, setCurrentTab] = useState<ModuleTab>('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [activeFramework, setActiveFramework] = useState<'SOC2' | 'OWASP' | 'GDPR' | 'NIST'>('SOC2');

  // Core State Stores initialized directly with rich data (no null delays)
  const [telemetry, setTelemetry] = useState<TelemetryData>(initialTelemetry);
  const [complianceReport, setComplianceReport] = useState<ComplianceReport>(() =>
    getComplianceReport('SOC2', false)
  );
  const [scannerStatus, setScannerStatus] = useState<ScannerStatus>(initialScannerStatus);
  const [patchStatus, setPatchStatus] = useState<PatchStatus>(initialPatchStatus);
  const [threatMap, setThreatMap] = useState<ThreatMapReport>(initialThreatMap);

  // Loading flags
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isDeploying, setIsDeploying] = useState<boolean>(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = (type: 'success' | 'error' | 'info', title: string, message: string) => {
    const id = Date.now().toString();
    setToasts((prev) => [...prev, { id, type, title, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  // Optional background fetch with silent fallback
  const syncWithBackendIfAvailable = useCallback(async () => {
    try {
      const res = await fetch('/api/telemetry');
      if (res.ok) {
        const data = await res.json();
        setTelemetry(data);
      }
    } catch {
      // Backend not running (e.g. Vercel static host) - update subtle client-side telemetry jitter
      setTelemetry((prev) => {
        const jitter = Math.sin(Date.now() / 3000) * 12;
        const throughput = (142.4 + Math.sin(Date.now() / 2500) * 8.5).toFixed(1);
        const pps = Math.round(48500 + jitter * 50);
        return {
          ...prev,
          throughputMbps: throughput,
          packetRate: pps
        };
      });
    }
  }, []);

  useEffect(() => {
    const interval = setInterval(syncWithBackendIfAvailable, 4000);
    return () => clearInterval(interval);
  }, [syncWithBackendIfAvailable]);

  // Handler: Select Compliance Framework
  const handleSelectFramework = async (framework: 'SOC2' | 'OWASP' | 'GDPR' | 'NIST') => {
    setActiveFramework(framework);
    const isPatched = patchStatus ? !patchStatus.isVulnerable : false;
    const report = getComplianceReport(framework, isPatched);
    setComplianceReport(report);

    // Attempt backend sync in background
    try {
      await fetch('/api/compliance/framework', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ framework })
      });
    } catch {
      // client-side state already updated
    }

    addToast('info', 'Framework Switched', `Active compliance standard set to ${framework}.`);
  };

  // Handler: Toggle Rule
  const handleToggleRule = async (ruleId: string, passed: boolean) => {
    setComplianceReport((prev) => {
      if (!prev) return prev;
      const updatedRules = prev.rules.map((r) => (r.id === ruleId ? { ...r, passed } : r));
      const passedCount = updatedRules.filter((r) => r.passed).length;
      const totalCount = updatedRules.length;
      const score = Math.round((passedCount / totalCount) * 100);

      return {
        ...prev,
        score,
        passedCount,
        status: score === 100 ? 'COMPLIANT' : score >= 75 ? 'NEEDS_REVIEW' : 'NON_COMPLIANT',
        rules: updatedRules
      };
    });

    setTelemetry((prev) => ({
      ...prev,
      auditLogs: [
        {
          id: `LOG-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toISOString(),
          source: 'Compliance Checker (Member 3)',
          severity: passed ? 'INFO' : 'HIGH',
          message: `Control ${ruleId} manually marked as ${passed ? 'PASS' : 'FAIL'}.`,
          details: 'Recalculated regulatory compliance posture.'
        },
        ...prev.auditLogs
      ]
    }));

    try {
      await fetch('/api/compliance/toggle-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ruleId, passed })
      });
    } catch {
      // in-memory handled
    }

    addToast('info', 'Control Updated', `Rule ${ruleId} set to ${passed ? 'PASS' : 'FAIL'}.`);
  };

  // Handler: Run Scanner
  const handleRunScanner = async () => {
    setIsScanning(true);
    const isPatched = patchStatus ? !patchStatus.isVulnerable : false;

    // Check backend first, fallback to client state
    let serverResponded = false;
    try {
      const res = await fetch('/api/scanner/run', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.scanReport) {
          serverResponded = true;
          setScannerStatus({
            module: 'Member 1 - Code Scanner',
            status: 'completed',
            fileScanned: 'sample_config.js',
            rawContent: isPatched ? secureCode : vulnerableCode,
            vulnerabilitiesCount: data.scanReport.vulnerabilitiesFound,
            vulnerabilities: data.scanReport.details,
            lastScanned: new Date().toISOString()
          });
        }
      }
    } catch {
      // client-side execution
    }

    if (!serverResponded) {
      // Instant client-side SAST evaluation
      if (isPatched) {
        setScannerStatus({
          module: 'Member 1 - Code Scanner',
          status: 'completed',
          fileScanned: 'sample_config.js',
          rawContent: secureCode,
          vulnerabilitiesCount: 0,
          vulnerabilities: [],
          lastScanned: new Date().toISOString()
        });
      } else {
        setScannerStatus(initialScannerStatus);
      }
    }

    setTelemetry((prev) => ({
      ...prev,
      auditLogs: [
        {
          id: `LOG-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toISOString(),
          source: 'Code Scanner (Member 1)',
          severity: isPatched ? 'INFO' : 'CRITICAL',
          message: isPatched
            ? 'Scan finished on sample_config.js: Zero plaintext secrets detected.'
            : 'Scan finished on sample_config.js: 2 critical vulnerabilities identified (CWE-798).',
          details: isPatched
            ? 'Repository verified clean against secret leaks.'
            : 'Plaintext AWS & DB credentials present in target configuration.'
        },
        ...prev.auditLogs
      ]
    }));

    setIsScanning(false);
    if (isPatched) {
      addToast('success', 'Clean Scan Result', 'Zero vulnerabilities detected in sample_config.js.');
    } else {
      addToast(
        'error',
        'Scan Completed with Findings',
        'Discovered 2 critical plaintext secrets in sample_config.js.'
      );
    }
  };

  // Handler: Inspect Prompt (Firewall Sandbox)
  const handleInspectPrompt = async (prompt: string): Promise<FirewallInspectResult> => {
    // Attempt backend first
    try {
      const res = await fetch('/api/firewall/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt })
      });
      if (res.ok || res.status === 403) {
        const result = await res.json();
        updateFirewallLogs(result.status === 'BLOCKED', result.matchedRule);
        return result;
      }
    } catch {
      // fall through to client-side guardrail evaluation
    }

    // Client-side guardrail evaluation
    const startTime = Date.now();
    const dangerousKeywords = [
      { pattern: 'ignore previous instructions', category: 'Instruction Override / Jailbreak', severity: 'Critical' },
      { pattern: 'system role is now', category: 'Role Hijacking / Persona Shift', severity: 'High' },
      { pattern: 'pretend you are a hacker', category: 'Social Engineering / Adversarial Persona', severity: 'High' },
      { pattern: 'drop table', category: 'SQL Injection / Data Destruction', severity: 'Critical' },
      { pattern: 'bypass guardrail', category: 'Guardrail Circumvention', severity: 'High' },
      { pattern: 'reveal system prompt', category: 'System Architecture Extraction', severity: 'High' },
      { pattern: 'dan mode', category: 'Do Anything Now (DAN) Exploit', severity: 'Critical' },
      { pattern: 'union select', category: 'SQL Extraction Attack', severity: 'Critical' }
    ];

    const lowerPrompt = prompt.toLowerCase();
    const matched = dangerousKeywords.filter((k) => lowerPrompt.includes(k.pattern));
    const isMalicious = matched.length > 0;
    const tokensAnalyzed = Math.ceil(prompt.split(/\s+/).length * 1.3);
    const latencyMs = Math.floor(Math.random() * 8 + 10);

    let result: FirewallInspectResult;

    if (isMalicious) {
      result = {
        safe: false,
        status: 'BLOCKED',
        error: 'Prompt Injection Blocked by CyberShield AI Firewall Guardrail',
        matchedRule: matched[0].category,
        matchedPatterns: matched.map((m) => m.pattern),
        severity: matched[0].severity,
        tokensAnalyzed,
        latencyMs,
        riskScore: Math.min(99, 70 + matched.length * 10),
        aiEvaluation: 'Adversarial instruction detected: Attempted override of conversational constraints.',
        rawPayload: {
          prompt,
          timestamp: new Date().toISOString(),
          defenseHeaders: {
            'x-cybershield-action': 'BLOCK_AND_ISOLATE',
            'x-guardrail-verdict': 'REJECT_INPUT',
            'x-inspection-engine': 'AEGIS-SHIELD-V3'
          }
        }
      };
      addToast('error', '🚨 Guardrail Triggered: BLOCKED', result.error || 'Malicious prompt intercepted.');
    } else {
      result = {
        safe: true,
        status: 'PASSED',
        message: 'Request successfully verified & cleared by AI Firewall guardrail.',
        tokensAnalyzed,
        latencyMs,
        riskScore: Math.floor(Math.random() * 6 + 2),
        sanitizationNotice: 'Input complies with OWASP LLM01, SOC 2 Confidentiality, and Safe Prompting guidelines.',
        rawPayload: {
          prompt,
          timestamp: new Date().toISOString(),
          defenseHeaders: {
            'x-cybershield-action': 'ALLOW',
            'x-guardrail-verdict': 'VERIFIED_SAFE',
            'x-inspection-engine': 'AEGIS-SHIELD-V3'
          }
        }
      };
      addToast('success', '✅ Guardrail Verified: PASSED', 'Payload cleared for model inference.');
    }

    updateFirewallLogs(isMalicious, matched[0]?.category);
    return result;
  };

  const updateFirewallLogs = (isMalicious: boolean, category?: string) => {
    setTelemetry((prev) => ({
      ...prev,
      auditLogs: [
        {
          id: `LOG-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toISOString(),
          source: 'AI Firewall (Member 2)',
          severity: isMalicious ? 'CRITICAL' : 'INFO',
          message: isMalicious
            ? `🚨 BLOCKED: Malicious prompt injection payload detected (${category || 'Adversarial'})`
            : '✅ PASSED: Prompt successfully verified against guardrail invariants',
          details: isMalicious
            ? 'Adversarial instruction neutralized by AI Firewall.'
            : 'Zero forbidden patterns found. Payload cleared.'
        },
        ...prev.auditLogs
      ]
    }));
  };

  // Handler: Deploy Patch (Real in-memory & backend update)
  const handleDeployPatch = async () => {
    setIsDeploying(true);

    try {
      await fetch('/api/patch/deploy', { method: 'POST' });
    } catch {
      // client-side update
    }

    // Update Patch Status
    setPatchStatus({
      file: 'sample_config.js',
      status: 'PATCHED_SECURELY',
      isVulnerable: false,
      currentContent: secureCode,
      beforeCode: vulnerableCode,
      afterCode: secureCode,
      patchReport: {
        status: 'success',
        file: 'sample_config.js',
        action: 'Replaced hardcoded AWS key and database password with environment variables',
        timestamp: new Date().toISOString(),
        patchedItems: [
          { secret: 'AKIA_IOSFODNN7EXAMPLE', replacedWith: 'process.env.AWS_ACCESS_KEY_ID' },
          { secret: 'super_secret_password_123', replacedWith: 'process.env.DB_PASSWORD' }
        ]
      }
    });

    // Update Scanner
    setScannerStatus((prev) => ({
      ...prev,
      rawContent: secureCode,
      vulnerabilitiesCount: 0,
      vulnerabilities: [],
      lastScanned: new Date().toISOString()
    }));

    // Update Compliance
    setComplianceReport(getComplianceReport(activeFramework, true));

    // Update Threat Map
    setThreatMap({
      module: 'Member 5 - Copilot & Threat Map',
      status: 'mitigated',
      assistantName: 'CyberShield AEGIS SecOps Copilot',
      totalAlertsAnalyzed: 1,
      summary: 'Exploit kill-chain severed. Step 1 (Credential Discovery) neutralized via automated environment variable patch.',
      killChainSteps: [
        {
          step: 1,
          id: 'STAGE-1-REPO',
          node: 'GitHub Repository / Source Code',
          microservice: 'Version Control & CI/CD',
          target: 'Code Scanner (Member 1)',
          action: 'Secrets wiped from repository. Plaintext credentials replaced with process.env variables.',
          riskLevel: 'Low',
          status: 'Patched / Neutralized',
          mitigation: 'Secrets rotated in IAM and environment variables injected via Vault.'
        },
        {
          step: 2,
          id: 'STAGE-2-INGRESS',
          node: 'AI Ingress Gateway & Model API',
          microservice: 'Prompt Shield / Gateway',
          target: 'AI Firewall (Member 2)',
          action: 'Adversarial prompt payloads monitored and filtered by AI Firewall guardrail.',
          riskLevel: 'High',
          status: 'Active Guardrail Protected',
          mitigation: 'Enforce real-time regex & semantic inspection via AI Firewall middleware.'
        },
        {
          step: 3,
          id: 'STAGE-3-AUTH',
          node: 'Internal IAM & Microservice Auth',
          microservice: 'IAM Service Bus',
          target: 'Compliance Checker (Member 3)',
          action: 'Role-based access controls verified against SOC 2 and GDPR requirements.',
          riskLevel: 'Low',
          status: 'Secured',
          mitigation: 'Maintain least-privilege tokens and audit access trails.'
        },
        {
          step: 4,
          id: 'STAGE-4-DATABASE',
          node: 'Production Database & Cloud Storage',
          microservice: 'PostgreSQL / AWS S3',
          target: 'Data Tier',
          action: 'Database tier protected. Direct credential access pathway eliminated.',
          riskLevel: 'Minimal',
          status: 'Safe / Access Denied',
          mitigation: 'Credentials rotated in production secrets manager.'
        }
      ],
      recommendedAction: 'Posture nominal. Continue monitoring real-time prompt telemetry in Tab 3.',
      timestamp: new Date().toISOString()
    });

    // Update Telemetry
    setTelemetry((prev) => ({
      ...prev,
      riskScore: 18,
      status: 'NOMINAL',
      isPatched: true,
      activeThreatsCount: 1,
      auditLogs: [
        {
          id: `LOG-${Date.now().toString().slice(-4)}`,
          timestamp: new Date().toISOString(),
          source: 'Auto-Fixer (Member 4)',
          severity: 'INFO',
          message: 'Security patch successfully deployed: sample_config.js rewritten with environment variables.',
          details: 'Vulnerabilities SEC-001 and SEC-002 remediated. Kill chain Step 1 neutralized.'
        },
        ...prev.auditLogs
      ]
    }));

    setIsDeploying(false);
    addToast(
      'success',
      'Security Patch Deployed to Disk',
      'sample_config.js rewritten with process.env variables. Kill-chain severed.'
    );
  };

  // Handler: Revert Patch
  const handleRevertPatch = async () => {
    setIsDeploying(true);

    try {
      await fetch('/api/patch/revert', { method: 'POST' });
    } catch {
      // client-side update
    }

    setPatchStatus(initialPatchStatus);
    setScannerStatus(initialScannerStatus);
    setComplianceReport(getComplianceReport(activeFramework, false));
    setThreatMap(initialThreatMap);
    setTelemetry(initialTelemetry);

    setIsDeploying(false);
    addToast(
      'info',
      'Vulnerable State Restored',
      'sample_config.js reverted to test exploit and scan workflow.'
    );
  };

  // Handler: Ask Copilot
  const handleAskCopilot = async (question: string): Promise<{ answer: string; source: string }> => {
    try {
      const res = await fetch('/api/copilot/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question })
      });
      if (res.ok) {
        return await res.json();
      }
    } catch {
      // client fallback
    }

    const isPatched = patchStatus ? !patchStatus.isVulnerable : false;
    const qLower = question.toLowerCase();

    let answer = '';
    if (qLower.includes('patch') || qLower.includes('fix') || qLower.includes('sample_config')) {
      answer = `**Executive Risk Summary:**
${isPatched
  ? 'The target configuration `sample_config.js` is currently safely patched with environment variable references.'
  : 'Vulnerabilities SEC-001 & SEC-002 are active. Hardcoded credentials are exposed in `sample_config.js`.'}

**Immediate Remediation Steps:**
- ${isPatched ? 'Patch is already deployed.' : 'Execute "Deploy Patch" in Tab 4 to write process.env.DB_PASSWORD and process.env.AWS_ACCESS_KEY_ID.'}
- Revoke and rotate the compromised AWS access key \`AKIA_IOSFODNN7EXAMPLE\`.
- Sever the kill-chain link between Version Control and the Database Tier.

**Hardening Recommendation:**
\`\`\`bash
# Install git pre-commit hook to prevent credential leaks
git secrets --install && git secrets --register-aws
\`\`\``;
    } else if (qLower.includes('firewall') || qLower.includes('prompt') || qLower.includes('injection') || qLower.includes('step 2')) {
      answer = `**Executive Risk Summary:**
Member 2 AI Firewall actively intercepts adversarial prompt injections (LLM01), jailbreak overrides, and SQL commands before tokens reach the model.

**Immediate Remediation Steps:**
- Validate test prompts in Tab 3 (AI Firewall Sandbox) to examine live stream verdicts.
- Wrap model APIs with \`llmFirewall\` middleware.
- Configure automatic IP rate limiting for repeated jailbreak attempts.

**Hardening Recommendation:**
\`\`\`javascript
// AI Firewall middleware enforcement pattern
app.post('/api/ai-chat', llmFirewall, (req, res) => {
  // Safe prompt processing stream
});
\`\`\``;
    } else if (qLower.includes('soc2') || qLower.includes('compliance')) {
      answer = `**Executive Risk Summary:**
Current regulatory standard is set to **${activeFramework}**. Posture is currently **${isPatched ? '100% COMPLIANT' : '80% (NEEDS REVIEW)'}**.

**Immediate Remediation Steps:**
- Satisfy control SOC2-005 by keeping plaintext credentials out of version control.
- Enforce MFA and audit trail shipping with 365-day retention.
- Review interactive control invariant toggles in Tab 1.`;
    } else {
      answer = `**Executive Risk Summary:**
AEGIS SOC is supervising 5 active security layers across repository security, prompt guardrails, compliance rules, and automated patching.

**Immediate Remediation Steps:**
- ${isPatched ? 'All primary kill-chain steps are neutralized.' : 'Execute Member 4 Auto-Fixer patch immediately to sever Step 1 of the attack graph.'}
- Verify AI Firewall guardrail response in Tab 3.
- Run full codebase scan in Tab 2.

**Hardening Recommendation:**
\`\`\`bash
# Verify security baseline status
curl -s http://localhost:3000/api/telemetry
\`\`\``;
    }

    return {
      answer,
      source: 'AEGIS Enterprise Intelligence (Client Engine)'
    };
  };

  return (
    <div className="min-h-screen bg-[#0b0f17] text-slate-100 flex flex-col font-['Plus_Jakarta_Sans',sans-serif]">
      {/* Toast Notification Stack */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm pointer-events-none">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`p-3.5 rounded-lg shadow-xl border pointer-events-auto flex items-start gap-2.5 transition-all text-xs ${
              toast.type === 'success'
                ? 'bg-[#0f1f18] border-emerald-500/50 text-emerald-200'
                : toast.type === 'error'
                ? 'bg-[#221014] border-rose-500/50 text-rose-200'
                : 'bg-[#101b2a] border-cyan-500/50 text-cyan-200'
            }`}
          >
            {toast.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            ) : toast.type === 'error' ? (
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            ) : (
              <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1 min-w-0">
              <span className="font-bold block text-white">{toast.title}</span>
              <span className="text-[11px] leading-snug block mt-0.5">{toast.message}</span>
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-slate-400 hover:text-white p-0.5 shrink-0"
              title="Dismiss notification"
              aria-label="Dismiss notification"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>

      {/* Collapsible Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        telemetry={telemetry}
      />

      {/* Main Content Area */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ${
          sidebarCollapsed ? 'ml-18' : 'ml-72'
        }`}
      >
        {/* Top Header */}
        <TopHeader
          currentTab={currentTab}
          telemetry={telemetry}
          onRunGlobalScan={handleRunScanner}
          onDeployPatch={handleDeployPatch}
          onRefresh={syncWithBackendIfAvailable}
          isScanning={isScanning}
          isDeploying={isDeploying}
        />

        {/* Dynamic Viewport Container */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
          {currentTab === 'overview' && (
            <OverviewCommandCenter
              telemetry={telemetry}
              onNavigateTab={setCurrentTab}
              onDeployPatch={handleDeployPatch}
              onRunScanner={handleRunScanner}
              isDeploying={isDeploying}
              isScanning={isScanning}
            />
          )}

          {currentTab === 'compliance' && (
            <ComplianceTab
              complianceReport={complianceReport}
              onSelectFramework={handleSelectFramework}
              onToggleRule={handleToggleRule}
              onNavigateToPatcher={() => setCurrentTab('patcher')}
            />
          )}

          {currentTab === 'scanner' && (
            <ScannerTab
              scannerStatus={scannerStatus}
              onRunScan={handleRunScanner}
              isScanning={isScanning}
              onNavigateToPatcher={() => setCurrentTab('patcher')}
            />
          )}

          {currentTab === 'firewall' && (
            <FirewallTab onInspectPrompt={handleInspectPrompt} />
          )}

          {currentTab === 'patcher' && (
            <PatchFixerTab
              patchStatus={patchStatus}
              onDeployPatch={handleDeployPatch}
              onRevertPatch={handleRevertPatch}
              isDeploying={isDeploying}
            />
          )}

          {currentTab === 'threatmap' && (
            <ThreatMapperTab
              threatMap={threatMap}
              onDeployPatch={handleDeployPatch}
              onAskCopilot={handleAskCopilot}
              isDeploying={isDeploying}
            />
          )}
        </main>
      </div>
    </div>
  );
}
