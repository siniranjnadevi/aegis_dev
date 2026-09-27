/**
 * AEGIS DEV - Enterprise SOC Backend Server
 * Modules:
 *  - Member 1: Code & Secret Scanner (CWE-798 detector)
 *  - Member 2: AI Firewall & Prompt Shield (OWASP LLM01 Guardrail)
 *  - Member 3: Compliance Invariant Checker (SOC2, OWASP, GDPR, NIST)
 *  - Member 4: Auto-Fixer & Patch Generator (Atomic file writer)
 *  - Member 5: Copilot & Multi-Step Threat Mapper (Kill-chain graph)
 */

import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());

// Target configuration & report paths
const targetConfigPath = path.resolve(__dirname, 'sample_config.js');
const scanReportPath = path.resolve(__dirname, 'scan_report.json');
const patchReportPath = path.resolve(__dirname, 'patch_report.json');
const threatMapReportPath = path.resolve(__dirname, 'threat_map_report.json');

// Ensure sample_config.js exists with realistic credentials
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

// Audit log in-memory telemetry
const auditLogs = [
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

// Compliance Framework State
const complianceFrameworks = {
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
        codeSnippet: 'app.use(authMiddleware({ requireMfa: true }));'
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
    name: 'OWASP Top 10 API & LLM Security',
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
      }
    ]
  },
  GDPR: {
    name: 'GDPR / ISO 27001 Data Privacy',
    description: 'European Union General Data Protection Regulation and ISO 27001 Annex A controls.',
    rules: [
      {
        id: 'GDPR-ART25',
        name: 'Data Protection by Design',
        category: 'Privacy Architecture',
        severity: 'HIGH',
        passed: true,
        description: 'Pseudonymization and encryption of personal data across microservice boundaries.',
        remediation: 'Implement field-level encryption for user identifiers.',
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
        codeSnippet: 'patchRealFile();'
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
      }
    ]
  }
};

let currentFramework = 'SOC2';

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// Telemetry & Risk Score
app.get('/api/telemetry', (req, res) => {
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  const baseRisk = isPatched ? 18 : 86;
  const jitter = Math.sin(Date.now() / 4000) * 3;
  const currentRisk = Math.max(5, Math.min(99, Math.round(baseRisk + jitter)));

  res.json({
    riskScore: currentRisk,
    status: currentRisk > 60 ? 'HIGH_RISK' : 'NOMINAL',
    throughputMbps: (142.4 + Math.sin(Date.now() / 3000) * 18.2).toFixed(1),
    packetRate: Math.round(48500 + Math.sin(Date.now() / 2000) * 3200),
    activeSockets: 342,
    memoryUsageMB: (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(1),
    isPatched,
    activeThreatsCount: isPatched ? 1 : 4,
    auditLogs: auditLogs.slice(0, 20)
  });
});

// Compliance Endpoints
app.get('/api/compliance', (req, res) => {
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  const frameworkData = complianceFrameworks[currentFramework] || complianceFrameworks.SOC2;
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

app.post('/api/compliance/framework', (req, res) => {
  const { framework } = req.body;
  if (framework && complianceFrameworks[framework]) {
    currentFramework = framework;
  }
  res.json({ success: true, currentFramework });
});

app.post('/api/compliance/toggle-rule', (req, res) => {
  const { ruleId, passed } = req.body;
  const frameworkData = complianceFrameworks[currentFramework];
  const targetRule = frameworkData.rules.find(r => r.id === ruleId);
  if (targetRule) {
    targetRule.passed = Boolean(passed);
    return res.json({ success: true, rule: targetRule });
  }
  res.status(404).json({ error: 'Rule not found' });
});

// Member 1: Code Scanner
app.get('/api/scanner/status', (req, res) => {
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

app.post('/api/scanner/run', (req, res) => {
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
  res.json({ success: true, scanReport });
});

// Member 2: AI Firewall Sandbox
app.post('/api/firewall/inspect', (req, res) => {
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
    { pattern: 'dan mode', category: 'Do Anything Now (DAN) Exploit', severity: 'Critical' }
  ];

  const matched = dangerousKeywords.filter(k => userPrompt.toLowerCase().includes(k.pattern.toLowerCase()));
  const isMalicious = matched.length > 0;
  const tokenEstimate = Math.ceil(userPrompt.split(/\s+/).length * 1.3);
  const latencyMs = Date.now() - startTime + Math.floor(Math.random() * 8 + 6);

  if (isMalicious) {
    return res.status(403).json({
      safe: false,
      status: 'BLOCKED',
      error: 'Prompt Injection Blocked by CyberShield AI Firewall Guardrail',
      matchedRule: matched[0].category,
      matchedPatterns: matched.map(m => m.pattern),
      severity: matched[0].severity,
      tokensAnalyzed: tokenEstimate,
      latencyMs,
      riskScore: Math.min(99, 70 + matched.length * 10),
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

// Member 4: Auto-Fixer & Patch Generator
app.get('/api/patch/status', (req, res) => {
  ensureSampleConfigFile();
  const currentContent = fs.readFileSync(targetConfigPath, 'utf8');
  const isVulnerable = currentContent.includes('super_secret_password_123') || currentContent.includes('AKIA_IOSFODNN7EXAMPLE');

  res.json({
    file: 'sample_config.js',
    status: isVulnerable ? 'VULNERABLE' : 'PATCHED_SECURELY',
    isVulnerable,
    currentContent,
    beforeCode: `// sample_config.js - Target Configuration File
const apiKey = "AKIA_IOSFODNN7EXAMPLE";
const dbPassword = "super_secret_password_123";

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};`,
    afterCode: `// sample_config.js - Target Configuration File (Patched by AEGIS Auto-Fixer)
const apiKey = process.env.AWS_ACCESS_KEY_ID; // Patched: Secure environment injection
const dbPassword = process.env.DB_PASSWORD; // Patched securely by CyberShield AI

console.log("Connected to database with credentials.");
module.exports = {
  apiKey,
  dbPassword,
  port: 8080,
  env: "production"
};`,
    patchReport: fs.existsSync(patchReportPath) ? JSON.parse(fs.readFileSync(patchReportPath, 'utf8')) : null
  });
});

app.post('/api/patch/deploy', (req, res) => {
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

  res.json({ success: true, status: 'PATCHED_SECURELY', patchReport });
});

app.post('/api/patch/revert', (req, res) => {
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
  res.json({ success: true, status: 'VULNERABLE' });
});

// Member 5: Copilot & Threat Mapper
app.get('/api/threat-map', (req, res) => {
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  res.json({
    module: 'Member 5 - Copilot & Threat Map',
    status: isPatched ? 'mitigated' : 'active_killchain',
    assistantName: 'CyberShield AEGIS SecOps Copilot',
    totalAlertsAnalyzed: isPatched ? 1 : 4,
    summary: isPatched
      ? 'Exploit kill-chain severed. Step 1 neutralized via automated environment variable patch.'
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
        action: 'Attacker injects jailbreak prompt payloads ("ignore previous instructions")',
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
        action: 'Attacker attempts lateral movement exploiting permissive access tokens',
        riskLevel: isPatched ? 'Low' : 'High',
        status: isPatched ? 'Secured' : 'Needs Review',
        mitigation: 'Enforce SOC 2 access controls and rotate all service tokens.'
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
  });
});

app.post('/api/copilot/ask', (req, res) => {
  const { question } = req.body;
  let isPatched = false;
  if (fs.existsSync(targetConfigPath)) {
    const content = fs.readFileSync(targetConfigPath, 'utf8');
    isPatched = content.includes('process.env.DB_PASSWORD') && !content.includes('super_secret_password_123');
  }

  const answer = `**Executive Risk Summary:**
AEGIS Threat Copilot has analyzed your query: "${question}".
System state is currently **${isPatched ? 'PATCHED / NOMINAL' : 'VULNERABLE (Secrets Exposed)'}**.

**Immediate Remediation Steps:**
- ${isPatched ? 'Maintain real-time prompt guardrail monitoring in Tab 3.' : 'Deploy Member 4 Automated Patch Fixer in Tab 4 to sever Step 1 of the kill chain.'}
- Verify AI Firewall inspection latency and token metrics.
- Ensure SOC 2 compliance rule SOC2-005 is met.`;

  res.json({
    answer,
    source: 'AEGIS Enterprise Rule Engine',
    timestamp: new Date().toISOString()
  });
});

// Serve frontend if built
const distPath = path.resolve(__dirname, 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res) => {
    res.sendFile(path.resolve(distPath, 'index.html'));
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[AEGIS DEV Enterprise SOC] Listening on http://0.0.0.0:${PORT}`);
});
