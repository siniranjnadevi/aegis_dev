import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());

// Initialize Gemini if API key is present
const geminiApiKey = process.env.GEMINI_API_KEY || '';
let genAI: GoogleGenAI | null = null;
if (geminiApiKey && geminiApiKey !== 'MY_GEMINI_API_KEY') {
  try {
    genAI = new GoogleGenAI({ apiKey: geminiApiKey });
  } catch (err) {
    console.error('[AEGIS DEV] Failed to initialize Gemini API client:', err);
  }
}

// In-memory runtime telemetry & log streams
interface AuditLog {
  id: string;
  timestamp: string;
  source: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  message: string;
  details: string;
}

let auditLogs: AuditLog[] = [
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

// Target sample config file path
const targetConfigPath = path.resolve(__dirname, 'sample_config.js');
const scanReportPath = path.resolve(__dirname, 'scan_report.json');
const patchReportPath = path.resolve(__dirname, 'patch_report.json');
const threatMapReportPath = path.resolve(__dirname, 'threat_map_report.json');

// Ensure sample_config.js exists
function ensureSampleConfigFile() {
  if (!fs.existsSync(targetConfigPath)) {
    const defaultContent = `// sample_config.js - Target Configuration File
const apiKey = "AKIA_IOSFODNN7EXAMPLE";
const dbPassword = "super_secret_password_123";

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};
`;
    fs.writeFileSync(targetConfigPath, defaultContent, 'utf8');
  }
}
ensureSampleConfigFile();

// Compliance State Store
type ComplianceFrameworkId = 'SOC2' | 'OWASP' | 'GDPR' | 'NIST';

interface ComplianceRule {
  id: string;
  name: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  passed: boolean;
  description: string;
  remediation: string;
  codeSnippet?: string;
}

const complianceFrameworks: Record<ComplianceFrameworkId, { name: string; description: string; rules: ComplianceRule[] }> = {
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

let currentFramework: ComplianceFrameworkId = 'SOC2';

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// 1. Health & Server Info
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'HEALTHY',
    system: 'AEGIS DEV Enterprise SOC Engine',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    version: '3.4.1-ENTERPRISE'
  });
});

// 2. Real-time Telemetry Counters & Audit Stream
app.get('/api/telemetry', (req: Request, res: Response) => {
  // Check if sample_config is patched
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  // Dynamic risk score calculation
  const baseRisk = isPatched ? 18 : 86;
  const jitter = Math.sin(Date.now() / 4000) * 3;
  const currentRisk = Math.max(5, Math.min(99, Math.round(baseRisk + jitter)));

  // Simulated live network throughput in MB/s with realistic fluctuation
  const throughputMbps = (142.4 + Math.sin(Date.now() / 3000) * 18.2).toFixed(1);
  const packetRate = Math.round(48500 + Math.sin(Date.now() / 2000) * 3200);
  const activeSockets = 342;
  const memoryUsageMB = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1);

  res.json({
    riskScore: currentRisk,
    status: currentRisk > 60 ? 'HIGH_RISK' : 'NOMINAL',
    throughputMbps,
    packetRate,
    activeSockets,
    memoryUsageMB,
    isPatched,
    activeThreatsCount: isPatched ? 1 : 4,
    auditLogs: auditLogs.slice(0, 20)
  });
});

// 3. Compliance Frameworks & Rules
app.get('/api/compliance', (req: Request, res: Response) => {
  // Sync SOC2-005 / API02-CRED / GDPR-ART32 / NIST-PR.DS with actual file state
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  const frameworkData = complianceFrameworks[currentFramework];
  const rules = frameworkData.rules.map(rule => {
    if (['SOC2-005', 'API02-CRED', 'GDPR-ART32', 'NIST-PR.DS'].includes(rule.id)) {
      return { ...rule, passed: isPatched };
    }
    return rule;
  });

  const passedCount = rules.filter(r => r.passed).length;
  const totalCount = rules.length;
  const score = Math.round((passedCount / totalCount) * 100);

  res.json({
    framework: currentFramework,
    name: frameworkData.name,
    description: frameworkData.description,
    score,
    passedCount,
    totalCount,
    status: score === 100 ? 'COMPLIANT' : score >= 75 ? 'NEEDS_REVIEW' : 'NON_COMPLIANT',
    rules
  });
});

app.post('/api/compliance/framework', (req: Request, res: Response) => {
  const { framework } = req.body;
  if (framework && complianceFrameworks[framework as ComplianceFrameworkId]) {
    currentFramework = framework as ComplianceFrameworkId;
  }
  res.json({ success: true, currentFramework });
});

app.post('/api/compliance/toggle-rule', (req: Request, res: Response) => {
  const { ruleId, passed } = req.body;
  const frameworkData = complianceFrameworks[currentFramework];
  const targetRule = frameworkData.rules.find(r => r.id === ruleId);
  if (targetRule) {
    targetRule.passed = Boolean(passed);
    auditLogs.unshift({
      id: `LOG-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      source: 'Compliance Checker (Member 3)',
      severity: passed ? 'INFO' : 'HIGH',
      message: `Rule ${ruleId} (${targetRule.name}) manual override set to ${passed ? 'PASS' : 'FAIL'}.`,
      details: 'Administrator manually recalculated posture compliance controls.'
    });
    return res.json({ success: true, rule: targetRule });
  }
  res.status(404).json({ error: 'Rule not found' });
});

// 4. Code & Secret Scanner (Member 1)
app.get('/api/scanner/status', (req: Request, res: Response) => {
  ensureSampleConfigFile();
  const fileContent = fs.readFileSync(targetConfigPath, 'utf8');
  const hasPlaintextPassword = fileContent.includes('super_secret_password_123');
  const hasPlaintextApiKey = fileContent.includes('AKIA_IOSFODNN7EXAMPLE');

  const vulnerabilities = [];
  if (hasPlaintextApiKey) {
    vulnerabilities.push({
      id: 'SEC-001',
      type: 'Hardcoded AWS Access Key',
      severity: 'Critical',
      file: 'sample_config.js',
      line: 2,
      snippet: 'const apiKey = "AKIA_IOSFODNN7EXAMPLE";',
      secretValue: 'AKIA_IOSFODNN7EXAMPLE',
      maskedValue: 'AKIA_***************',
      description: 'Plaintext AWS cloud credential discovered in application configuration.'
    });
  }

  if (hasPlaintextPassword) {
    vulnerabilities.push({
      id: 'SEC-002',
      type: 'Hardcoded Database Password',
      severity: 'Critical',
      file: 'sample_config.js',
      line: 3,
      snippet: 'const dbPassword = "super_secret_password_123";',
      secretValue: 'super_secret_password_123',
      maskedValue: 'supe*******************',
      description: 'Hardcoded database connection password found in plaintext source code.'
    });
  }

  res.json({
    module: 'Member 1 - Code Scanner',
    status: 'completed',
    fileScanned: 'sample_config.js',
    rawContent: fileContent,
    vulnerabilitiesCount: vulnerabilities.length,
    vulnerabilities,
    lastScanned: new Date().toISOString()
  });
});

app.post('/api/scanner/run', (req: Request, res: Response) => {
  ensureSampleConfigFile();
  const fileContent = fs.readFileSync(targetConfigPath, 'utf8');
  const hasPlaintextPassword = fileContent.includes('super_secret_password_123');
  const hasPlaintextApiKey = fileContent.includes('AKIA_IOSFODNN7EXAMPLE');

  const vulnerabilities = [];
  if (hasPlaintextApiKey) {
    vulnerabilities.push({
      id: 'SEC-001',
      type: 'Hardcoded AWS Access Key',
      severity: 'Critical',
      file: 'sample_config.js',
      line: 2,
      snippet: 'const apiKey = "AKIA_IOSFODNN7EXAMPLE";',
      secretValue: 'AKIA_IOSFODNN7EXAMPLE',
      maskedValue: 'AKIA_***************',
      description: 'Plaintext AWS cloud credential discovered in application configuration.'
    });
  }

  if (hasPlaintextPassword) {
    vulnerabilities.push({
      id: 'SEC-002',
      type: 'Hardcoded Database Password',
      severity: 'Critical',
      file: 'sample_config.js',
      line: 3,
      snippet: 'const dbPassword = "super_secret_password_123";',
      secretValue: 'super_secret_password_123',
      maskedValue: 'supe*******************',
      description: 'Hardcoded database connection password found in plaintext source code.'
    });
  }

  const scanReport = {
    module: 'Member 1 - Code Scanner',
    status: 'completed',
    filesScanned: 1,
    vulnerabilitiesFound: vulnerabilities.length,
    details: vulnerabilities,
    timestamp: new Date().toISOString()
  };

  fs.writeFileSync(scanReportPath, JSON.stringify(scanReport, null, 2), 'utf8');

  auditLogs.unshift({
    id: `LOG-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString(),
    source: 'Code Scanner (Member 1)',
    severity: vulnerabilities.length > 0 ? 'CRITICAL' : 'INFO',
    message: `Scan finished on sample_config.js: ${vulnerabilities.length} vulnerabilities detected.`,
    details: vulnerabilities.length > 0 ? 'CWE-798 Hardcoded Secrets present in codebase.' : 'Clean state: zero secrets found.'
  });

  res.json({
    success: true,
    scanReport
  });
});

// 5. AI Firewall & Prompt Shield Sandbox (Member 2)
app.post('/api/firewall/inspect', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const userPrompt = (req.body.prompt || '').trim();

  if (!userPrompt) {
    return res.status(400).json({ safe: false, error: 'Prompt payload is empty' });
  }

  const dangerousKeywords = [
    { pattern: 'ignore previous instructions', category: 'Instruction Override / Jailbreak', severity: 'Critical' },
    { pattern: 'system role is now', category: 'Role Hijacking / Persona Shift', severity: 'High' },
    { pattern: 'pretend you are a hacker', category: 'Social Engineering / Adversarial Persona', severity: 'High' },
    { pattern: 'drop table', category: 'SQL Injection / Data Destruction', severity: 'Critical' },
    { pattern: 'bypass guardrail', category: 'Guardrail Circumvention', severity: 'High' },
    { pattern: 'reveal system prompt', category: 'System Architecture Extraction', severity: 'High' },
    { pattern: 'dan mode', category: 'Do Anything Now (DAN) Exploit', severity: 'Critical' },
    { pattern: 'union select', category: 'SQL Extraction Attack', severity: 'Critical' },
    { pattern: '<script>', category: 'Stored / Reflected Cross-Site Scripting', severity: 'Medium' }
  ];

  const matchedKeywords: Array<{ pattern: string; category: string; severity: string }> = [];
  const lowerPrompt = userPrompt.toLowerCase();

  for (const item of dangerousKeywords) {
    if (lowerPrompt.includes(item.pattern.toLowerCase())) {
      matchedKeywords.push(item);
    }
  }

  const isMalicious = matchedKeywords.length > 0;
  const tokenEstimate = Math.ceil(userPrompt.split(/\s+/).length * 1.3);
  const latencyMs = Date.now() - startTime + Math.floor(Math.random() * 8 + 6);

  // If Gemini API is available and prompt is borderline, we can also perform LLM Guardrail evaluation
  let aiEvaluation: string | null = null;
  if (genAI && isMalicious) {
    try {
      const response = await genAI.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are an elite enterprise AI Firewall security engine. Classify why this prompt is dangerous in 1 concise sentence: "${userPrompt.slice(0, 300)}"`
      });
      aiEvaluation = response.text?.trim() || null;
    } catch (e) {
      // Non-blocking fallback
    }
  }

  const logEntry: AuditLog = {
    id: `LOG-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString(),
    source: 'AI Firewall (Member 2)',
    severity: isMalicious ? 'CRITICAL' : 'INFO',
    message: isMalicious
      ? `🚨 BLOCKED: Malicious prompt injection payload detected (${matchedKeywords[0]?.category || 'Violation'})`
      : '✅ PASSED: Prompt successfully verified against guardrail invariants',
    details: isMalicious
      ? `Triggered rules: ${matchedKeywords.map(m => `"${m.pattern}"`).join(', ')}`
      : 'Zero forbidden patterns found. Payload cleared for model inference.'
  };
  auditLogs.unshift(logEntry);

  if (isMalicious) {
    return res.status(403).json({
      safe: false,
      status: 'BLOCKED',
      error: 'Prompt Injection Blocked by CyberShield AI Firewall Guardrail',
      matchedRule: matchedKeywords[0].category,
      matchedPatterns: matchedKeywords.map(k => k.pattern),
      severity: matchedKeywords[0].severity,
      tokensAnalyzed: tokenEstimate,
      latencyMs,
      riskScore: Math.min(99, 70 + matchedKeywords.length * 10),
      aiEvaluation: aiEvaluation || 'Adversarial instruction detected: Attempted override of conversational constraints.',
      rawPayload: {
        prompt: userPrompt,
        timestamp: new Date().toISOString(),
        defenseHeaders: {
          'x-cybershield-action': 'BLOCK_AND_ISOLATE',
          'x-guardrail-verdict': 'REJECT_INPUT',
          'x-inspection-engine': 'AEGIS-SHIELD-V3'
        }
      }
    });
  }

  return res.json({
    safe: true,
    status: 'PASSED',
    message: 'Request successfully verified & cleared by AI Firewall guardrail.',
    tokensAnalyzed: tokenEstimate,
    latencyMs,
    riskScore: Math.floor(Math.random() * 8 + 2),
    sanitizationNotice: 'Input complies with OWASP LLM01, SOC 2 Confidentiality, and Safe Prompting guidelines.',
    rawPayload: {
      prompt: userPrompt,
      timestamp: new Date().toISOString(),
      defenseHeaders: {
        'x-cybershield-action': 'ALLOW',
        'x-guardrail-verdict': 'VERIFIED_SAFE',
        'x-inspection-engine': 'AEGIS-SHIELD-V3'
      }
    }
  });
});

// 6. Automated Patch Fixer (Member 4)
app.get('/api/patch/status', (req: Request, res: Response) => {
  ensureSampleConfigFile();
  const currentContent = fs.readFileSync(targetConfigPath, 'utf8');
  const isVulnerable = currentContent.includes('super_secret_password_123') || currentContent.includes('AKIA_IOSFODNN7EXAMPLE');

  const vulnerableVersion = `// sample_config.js - Target Configuration File
const apiKey = "AKIA_IOSFODNN7EXAMPLE";
const dbPassword = "super_secret_password_123";

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};`;

  const secureVersion = `// sample_config.js - Target Configuration File (Patched by AEGIS Auto-Fixer)
const apiKey = process.env.AWS_ACCESS_KEY_ID; // Patched: Secure environment injection
const dbPassword = process.env.DB_PASSWORD; // Patched securely by CyberShield AI

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};`;

  res.json({
    file: 'sample_config.js',
    status: isVulnerable ? 'VULNERABLE' : 'PATCHED_SECURELY',
    isVulnerable,
    currentContent,
    beforeCode: vulnerableVersion,
    afterCode: secureVersion,
    patchReport: fs.existsSync(patchReportPath) ? JSON.parse(fs.readFileSync(patchReportPath, 'utf8')) : null
  });
});

app.post('/api/patch/deploy', (req: Request, res: Response) => {
  ensureSampleConfigFile();
  const secureVersion = `// sample_config.js - Target Configuration File (Patched by AEGIS Auto-Fixer)
const apiKey = process.env.AWS_ACCESS_KEY_ID; // Patched: Secure environment injection
const dbPassword = process.env.DB_PASSWORD; // Patched securely by CyberShield AI

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};
`;

  // Write directly to disk
  fs.writeFileSync(targetConfigPath, secureVersion, 'utf8');

  const patchReport = {
    status: 'success',
    file: 'sample_config.js',
    action: 'Replaced hardcoded AWS key and database password with environment variables',
    patchedItems: [
      { secret: 'AKIA_IOSFODNN7EXAMPLE', replacedWith: 'process.env.AWS_ACCESS_KEY_ID' },
      { secret: 'super_secret_password_123', replacedWith: 'process.env.DB_PASSWORD' }
    ],
    timestamp: new Date().toISOString()
  };

  fs.writeFileSync(patchReportPath, JSON.stringify(patchReport, null, 2), 'utf8');

  auditLogs.unshift({
    id: `LOG-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString(),
    source: 'Auto-Fixer (Member 4)',
    severity: 'INFO',
    message: 'Security patch successfully written directly to sample_config.js',
    details: 'Vulnerabilities SEC-001 and SEC-002 remediated. Patch report updated.'
  });

  res.json({
    success: true,
    status: 'PATCHED_SECURELY',
    patchReport
  });
});

app.post('/api/patch/revert', (req: Request, res: Response) => {
  const vulnerableVersion = `// sample_config.js - Target Configuration File
const apiKey = "AKIA_IOSFODNN7EXAMPLE";
const dbPassword = "super_secret_password_123";

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};
`;
  fs.writeFileSync(targetConfigPath, vulnerableVersion, 'utf8');

  const patchReport = {
    status: 'pending_deployment',
    file: 'sample_config.js',
    action: 'Reverted to vulnerable state for security testing simulation',
    timestamp: new Date().toISOString()
  };
  fs.writeFileSync(patchReportPath, JSON.stringify(patchReport, null, 2), 'utf8');

  auditLogs.unshift({
    id: `LOG-${Date.now().toString().slice(-4)}`,
    timestamp: new Date().toISOString(),
    source: 'Auto-Fixer (Member 4)',
    severity: 'HIGH',
    message: 'sample_config.js reset to vulnerable state for exploit demonstration.',
    details: 'Hardcoded secrets restored to allow live testing.'
  });

  res.json({
    success: true,
    status: 'VULNERABLE',
    patchReport
  });
});

// 7. AI Copilot & Threat Mapper (Member 5)
app.get('/api/threat-map', (req: Request, res: Response) => {
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  const threatMap = {
    module: 'Member 5 - Copilot & Threat Map',
    status: isPatched ? 'mitigated' : 'active_killchain',
    assistantName: 'CyberShield AEGIS SecOps Copilot',
    totalAlertsAnalyzed: isPatched ? 1 : 4,
    summary: isPatched
      ? 'Exploit kill-chain severed. Step 1 (Credential Discovery) neutralized via automated environment variable patch.'
      : 'Critical Threat Alert: Multi-step exploit chain detected targeting production database credentials.',
    killChainSteps: [
      {
        step: 1,
        id: 'STAGE-1-REPO',
        node: 'GitHub Repository / Source Code',
        microservice: 'Version Control & CI/CD',
        target: 'Code Scanner (Member 1)',
        action: 'Attacker scans public repo and discovers exposed AWS & DB credentials in sample_config.js',
        riskLevel: isPatched ? 'Low' : 'Critical',
        status: isPatched ? 'Patched / Neutralized' : 'Actively Vulnerable',
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
        riskLevel: isPatched ? 'Low' : 'High',
        status: isPatched ? 'Secured' : 'Needs Review',
        mitigation: 'Enforce SOC 2 access control controls and rotate all service tokens.'
      },
      {
        step: 4,
        id: 'STAGE-4-DATABASE',
        node: 'Production Database & Cloud Storage',
        microservice: 'PostgreSQL / AWS S3',
        target: 'Data Tier',
        action: 'Attacker uses discovered credentials to exfiltrate proprietary tables and user data',
        riskLevel: isPatched ? 'Minimal' : 'Critical',
        status: isPatched ? 'Safe / Access Denied' : 'Exposed to Breach',
        mitigation: 'Rotate database passwords immediately and restrict DB ingress to internal VPC CIDRs.'
      }
    ],
    recommendedAction: isPatched
      ? 'Posture nominal. Continue monitoring real-time prompt telemetry in Tab 3.'
      : 'Deploy Member 4 Automated Patch Fixer immediately to break Step 1 of the attack vector.',
    timestamp: new Date().toISOString()
  };

  res.json(threatMap);
});

// Interactive AI Copilot Query
app.post('/api/copilot/ask', async (req: Request, res: Response) => {
  const { question } = req.body;
  if (!question) {
    return res.status(400).json({ error: 'Question is required' });
  }

  // Get current system context
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  if (genAI) {
    try {
      const prompt = `You are the AEGIS DEV Elite Enterprise SOC Copilot & Threat Intelligence Architect.
Current SOC State:
- Patch status of sample_config.js: ${isPatched ? 'PATCHED (Secure)' : 'VULNERABLE (Hardcoded credentials found: AWS Key, DB Password)'}
- Active Framework: ${currentFramework}
- AI Firewall Guardrail: Operational (protects against prompt injection, role shifts, SQL drops)
- Active Kill-Chain Stage: ${isPatched ? 'Broken / Remediated' : 'Step 1 actively vulnerable'}

User Analyst Query: "${question}"

Provide a senior enterprise SOC response structured with:
1. Executive Risk Summary (2 sentences)
2. Immediate Remediation Steps (Bullet points)
3. Hardening Recommendation (1 actionable code or CLI pattern)`;

      const response = await genAI.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt
      });

      return res.json({
        answer: response.text,
        source: 'Gemini 2.5 Flash SecOps Intelligence',
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      console.error('[AEGIS Copilot] Gemini API error, falling back to deterministic heuristics:', err);
    }
  }

  // Expert heuristic fallback
  let answer = '';
  const qLower = question.toLowerCase();
  if (qLower.includes('patch') || qLower.includes('fix') || qLower.includes('sample_config')) {
    answer = `**Executive Risk Summary:**
${isPatched
  ? 'The target configuration `sample_config.js` is currently safely patched with environment variable references.'
  : 'Vulnerability SEC-001 & SEC-002 are active. Hardcoded credentials are fully exposed in `sample_config.js`.'}

**Immediate Remediation Steps:**
- Navigate to Tab 4 (Automated Patch Fixer) and execute "Deploy Patch".
- The patcher rewrites the file to use \`process.env.DB_PASSWORD\` and \`process.env.AWS_ACCESS_KEY_ID\`.
- Invalidate the compromised AWS key \`AKIA_IOSFODNN7EXAMPLE\` via AWS IAM console.

**Hardening Recommendation:**
\`\`\`bash
# Add git pre-commit hook to block secret leaks
git secrets --install && git secrets --register-aws
\`\`\``;
  } else if (qLower.includes('firewall') || qLower.includes('prompt') || qLower.includes('injection')) {
    answer = `**Executive Risk Summary:**
The Member 2 AI Firewall actively filters adversarial input vectors including prompt jailbreaks ("ignore previous instructions") and privilege escalations.

**Immediate Remediation Steps:**
- Test inputs in Tab 3 (AI Firewall Sandbox) to simulate adversarial and benign payloads.
- Ensure the \`llmFirewall\` middleware wraps all LLM inference endpoints before token processing.
- Log flagged payloads to SIEM for automated IP throttling.

**Hardening Recommendation:**
\`\`\`javascript
// Middleware protection pattern
app.post('/api/ai-chat', llmFirewall, async (req, res) => {
  // Safe prompt processing
});
\`\`\``;
  } else if (qLower.includes('soc2') || qLower.includes('compliance')) {
    answer = `**Executive Risk Summary:**
Current compliance framework is set to **${currentFramework}**. Compliance posture is currently ${isPatched ? 'at 100% compliant' : 'under review due to secret exposure'}.

**Immediate Remediation Steps:**
- Satisfy control SOC2-005 by removing plaintext secrets from git tracking.
- Retain audit logs for 365 days in an immutable WORM bucket.
- Review the interactive rule breakdown in Tab 1.`;
  } else {
    answer = `**Executive Risk Summary:**
AEGIS SOC is monitoring 5 integrated defense layers across version control, ingress firewalls, microservice authentication, and automated patching.

**Immediate Remediation Steps:**
- ${isPatched ? 'All primary kill-chain steps are neutralized.' : 'Execute Member 4 Auto-Fixer patch immediately to neutralize Step 1 of the attack graph.'}
- Verify AI Firewall guardrail response in Tab 3.
- Run full codebase scan in Tab 2.

**Hardening Recommendation:**
\`\`\`bash
# Run automated compliance & patch check
curl -X POST http://localhost:3000/api/scanner/run
\`\`\``;
  }

  res.json({
    answer,
    source: 'AEGIS Enterprise Rule Engine',
    timestamp: new Date().toISOString()
  });
});

// ----------------------------------------------------
// Static / Vite Middleware Integration
// ----------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (req: Request, res: Response) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  } else {
    // Mount Vite in middleware mode for hot dev server
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AEGIS DEV Enterprise SOC] Listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('[AEGIS DEV Enterprise SOC] Server startup failed:', err);
  process.exit(1);
});
