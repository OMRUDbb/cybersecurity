import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 5000;
const API_KEY = process.env.API_KEY || 'dev-key-12345';

// Middleware
app.use(express.json());
app.use(cors());

// API Key Validation Middleware
const validateApiKey = (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'API key is required. Pass it in the x-api-key header.',
      example: 'curl -H "x-api-key: YOUR_API_KEY" http://localhost:5000/api/security-tips',
    });
  }

  if (apiKey !== API_KEY) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Invalid API key',
    });
  }

  next();
};

// Public endpoint (no API key needed)
app.get('/', (req: Request, res: Response) => {
  res.json({
    message: 'Cybersecurity API is running',
    version: '1.0.0',
    note: 'Most endpoints require an API key. Pass it in the x-api-key header.',
    endpoints: {
      public: [
        'GET / (this endpoint)'
      ],
      protected: [
        'POST /api/password-strength',
        'POST /api/phishing-check',
        'POST /api/vulnerability-scan',
        'GET /api/security-tips',
        'GET /api/threat-types',
        'POST /api/threat-analysis',
        'GET /api/best-practices',
        'GET /api/encryption-methods',
      ],
    },
    authentication: {
      method: 'Header-based API Key',
      header: 'x-api-key',
      example: 'x-api-key: your-api-key-here',
    },
  });
});

// Apply API key validation to all protected routes
app.use('/api/', validateApiKey);

// ============================================
// TYPES & INTERFACES
// ============================================
interface PasswordStrengthResult {
  score: number;
  strength: 'Weak' | 'Fair' | 'Good' | 'Strong' | 'Very Strong';
  issues: string[];
  suggestions: string[];
}

interface VulnerabilityResult {
  hasVulnerabilities: boolean;
  vulnerabilities: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
}

interface PhishingIndicators {
  isLikely: boolean;
  indicators: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
}

interface ThreatAnalysis {
  threatType: string;
  description: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  mitigation: string[];
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

// Password Strength Checker
function checkPasswordStrength(password: string): PasswordStrengthResult {
  let score = 0;
  const issues: string[] = [];
  const suggestions: string[] = [];

  if (password.length >= 8) score += 20;
  else issues.push('Password should be at least 8 characters long');

  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;

  if (/[a-z]/.test(password)) score += 15;
  else issues.push('Add lowercase letters');

  if (/[A-Z]/.test(password)) score += 15;
  else issues.push('Add uppercase letters');

  if (/[0-9]/.test(password)) score += 15;
  else issues.push('Add numbers');

  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 15;
  else issues.push('Add special characters (!@#$%^&*)');

  if (!/(.)\1{2,}/.test(password)) score += 5;
  else issues.push('Avoid repeating characters');

  if (score < 30) {
    suggestions.push('Use a passphrase or random combination');
    suggestions.push('Avoid common words or personal information');
  }

  let strength: 'Weak' | 'Fair' | 'Good' | 'Strong' | 'Very Strong';
  if (score >= 90) strength = 'Very Strong';
  else if (score >= 70) strength = 'Strong';
  else if (score >= 50) strength = 'Good';
  else if (score >= 30) strength = 'Fair';
  else strength = 'Weak';

  return { score, strength, issues, suggestions };
}

// Phishing URL Detector
function detectPhishingIndicators(url: string): PhishingIndicators {
  const indicators: string[] = [];
  let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const pathname = urlObj.pathname;

    // Check for suspicious patterns
    if (hostname.includes('-') && !hostname.startsWith('xn--')) {
      indicators.push('Suspicious hyphens in domain');
      riskLevel = 'Medium';
    }

    if (/(\d{1,3}\.){3}\d{1,3}/.test(hostname)) {
      indicators.push('IP address instead of domain name');
      riskLevel = 'High';
    }

    if (hostname.length > 50) {
      indicators.push('Unusually long domain name');
      riskLevel = 'Medium';
    }

    if (pathname.includes('login') || pathname.includes('signin') || pathname.includes('verify')) {
      indicators.push('Login-related path detected');
      riskLevel = 'High';
    }

    if (urlObj.protocol !== 'https:') {
      indicators.push('Not using HTTPS encryption');
      riskLevel = 'High';
    }

    if (hostname.split('.').length > 4) {
      indicators.push('Too many subdomains');
      riskLevel = 'Medium';
    }

    // Common phishing keywords
    const phishingKeywords = ['verify', 'confirm', 'update', 'urgent', 'action', 'secure', 'account'];
    if (phishingKeywords.some(keyword => hostname.includes(keyword) || pathname.includes(keyword))) {
      indicators.push('Contains common phishing keywords');
      riskLevel = 'High';
    }
  } catch {
    indicators.push('Invalid URL format');
    riskLevel = 'Critical';
  }

  return {
    isLikely: indicators.length > 2,
    indicators,
    riskLevel,
  };
}

// Vulnerability Assessment
function assessVulnerabilities(data: any): VulnerabilityResult {
  const vulnerabilities: string[] = [];
  let riskLevel: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';

  // Check for SQL injection patterns
  if (data.input && typeof data.input === 'string') {
    const sqlPatterns = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'UNION', 'SELECT'];
    if (sqlPatterns.some(pattern => data.input.toUpperCase().includes(pattern))) {
      vulnerabilities.push('Potential SQL injection');
      riskLevel = 'Critical';
    }
  }

  // Check for script injection
  if (data.input && typeof data.input === 'string') {
    if (/<script|javascript:|onerror|onload/.test(data.input)) {
      vulnerabilities.push('Potential XSS (Cross-Site Scripting)');
      riskLevel = 'Critical';
    }
  }

  // Check for sensitive data exposure
  if (data.password || data.apiKey || data.token) {
    vulnerabilities.push('Sensitive data transmitted in payload');
    riskLevel = 'High';
  }

  return {
    hasVulnerabilities: vulnerabilities.length > 0,
    vulnerabilities,
    riskLevel,
  };
}

// ============================================
// ROUTES
// ============================================



// Password Strength Checker
app.post('/api/password-strength', (req: Request, res: Response) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        error: 'Password is required',
        message: 'Please provide a password to check',
      });
    }

    const result = checkPasswordStrength(password);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Phishing URL Check
app.post('/api/phishing-check', (req: Request, res: Response) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        error: 'URL is required',
        message: 'Please provide a URL to check for phishing indicators',
      });
    }

    const result = detectPhishingIndicators(url);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Vulnerability Scanner
app.post('/api/vulnerability-scan', (req: Request, res: Response) => {
  try {
    const result = assessVulnerabilities(req.body);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Security Tips
app.get('/api/security-tips', (req: Request, res: Response) => {
  const tips = [
    {
      id: 1,
      title: 'Use Strong Passwords',
      description: 'Create passwords with a mix of uppercase, lowercase, numbers, and special characters.',
      priority: 'Critical',
    },
    {
      id: 2,
      title: 'Enable Two-Factor Authentication',
      description: 'Add an extra layer of security by enabling 2FA on all important accounts.',
      priority: 'Critical',
    },
    {
      id: 3,
      title: 'Keep Software Updated',
      description: 'Regularly update your operating system, browsers, and applications.',
      priority: 'High',
    },
    {
      id: 4,
      title: 'Avoid Public WiFi for Sensitive Tasks',
      description: 'Do not access banking or sensitive accounts on unsecured public networks.',
      priority: 'High',
    },
    {
      id: 5,
      title: 'Use VPN',
      description: 'Encrypt your internet connection when using public networks.',
      priority: 'High',
    },
    {
      id: 6,
      title: 'Be Cautious with Email Attachments',
      description: 'Verify sender identity before opening attachments from unknown sources.',
      priority: 'Medium',
    },
    {
      id: 7,
      title: 'Backup Your Data',
      description: 'Regularly back up important data to prevent loss from ransomware.',
      priority: 'High',
    },
    {
      id: 8,
      title: 'Use Password Manager',
      description: 'Store passwords securely using a reputable password manager.',
      priority: 'Medium',
    },
  ];

  res.json({
    total: tips.length,
    tips,
  });
});

// Threat Types
app.get('/api/threat-types', (req: Request, res: Response) => {
  const threats = [
    { type: 'Malware', description: 'Malicious software designed to harm your system' },
    { type: 'Phishing', description: 'Fraudulent attempts to obtain sensitive information' },
    { type: 'Ransomware', description: 'Malware that encrypts data and demands payment' },
    { type: 'DDoS', description: 'Denial of Service attacks that disrupt services' },
    { type: 'SQL Injection', description: 'Attack exploiting database vulnerabilities' },
    { type: 'XSS (Cross-Site Scripting)', description: 'Injecting malicious scripts into web pages' },
    { type: 'Man-in-the-Middle', description: 'Intercepting communication between parties' },
    { type: 'Social Engineering', description: 'Manipulating people to divulge sensitive information' },
    { type: 'Zero-Day Exploit', description: 'Attacking unknown/unpatched vulnerabilities' },
    { type: 'Brute Force', description: 'Attempting to gain access through password guessing' },
  ];

  res.json({
    total: threats.length,
    threats,
  });
});

// Threat Analysis
app.post('/api/threat-analysis', (req: Request, res: Response) => {
  try {
    const { threatType } = req.body;

    if (!threatType) {
      return res.status(400).json({
        error: 'Threat type is required',
        message: 'Please specify the threat type for analysis',
      });
    }

    const threatAnalysis: { [key: string]: ThreatAnalysis } = {
      malware: {
        threatType: 'Malware',
        description: 'Malicious software designed to exploit, damage, or gain unauthorized access to systems.',
        riskLevel: 'Critical',
        mitigation: [
          'Use antivirus software',
          'Keep system updated',
          'Avoid downloading from untrusted sources',
          'Run regular system scans',
          'Use firewalls',
        ],
      },
      phishing: {
        threatType: 'Phishing',
        description: 'Fraudulent emails or websites designed to steal login credentials and sensitive data.',
        riskLevel: 'High',
        mitigation: [
          'Verify email sender identity',
          'Check for HTTPS in URLs',
          'Never click links in suspicious emails',
          'Use email filters',
          'Educate users on phishing techniques',
        ],
      },
      ransomware: {
        threatType: 'Ransomware',
        description: 'Malware that encrypts files and demands payment for decryption.',
        riskLevel: 'Critical',
        mitigation: [
          'Backup data regularly',
          'Use backup solutions with versioning',
          'Keep backups offline',
          'Maintain updated security software',
          'Educate users about suspicious attachments',
        ],
      },
    };

    const analysis = threatAnalysis[threatType.toLowerCase()];

    if (!analysis) {
      return res.status(404).json({
        error: 'Threat type not found',
        message: 'Provide a valid threat type for analysis',
      });
    }

    res.json(analysis);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Best Practices
app.get('/api/best-practices', (req: Request, res: Response) => {
  const practices = [
    {
      category: 'Authentication',
      practices: [
        'Use multi-factor authentication (MFA)',
        'Implement strong password policies',
        'Use OAuth 2.0 for third-party authentication',
        'Implement account lockout after failed attempts',
      ],
    },
    {
      category: 'Data Protection',
      practices: [
        'Encrypt sensitive data at rest and in transit',
        'Use HTTPS/TLS for all communications',
        'Implement data classification',
        'Regular data backups with recovery testing',
      ],
    },
    {
      category: 'Access Control',
      practices: [
        'Implement principle of least privilege',
        'Regular access reviews',
        'Role-based access control (RBAC)',
        'Monitor and log all access attempts',
      ],
    },
    {
      category: 'Incident Response',
      practices: [
        'Maintain incident response plan',
        'Regular security drills',
        'Document all incidents',
        'Establish communication protocols',
      ],
    },
  ];

  res.json({
    total: practices.length,
    practices,
  });
});

// Encryption Methods
app.get('/api/encryption-methods', (req: Request, res: Response) => {
  const methods = [
    {
      name: 'AES (Advanced Encryption Standard)',
      type: 'Symmetric',
      description: 'Industry-standard symmetric encryption',
      keySize: '128, 192, 256 bits',
      use: 'Data at rest, file encryption',
    },
    {
      name: 'RSA',
      type: 'Asymmetric',
      description: 'Public-key cryptography for secure key exchange',
      keySize: '2048, 3072, 4096 bits',
      use: 'Digital signatures, key exchange',
    },
    {
      name: 'SHA-256',
      type: 'Hash Function',
      description: 'Cryptographic hash function',
      keySize: 'Fixed 256-bit output',
      use: 'Data integrity, password hashing',
    },
    {
      name: 'TLS 1.3',
      type: 'Protocol',
      description: 'Modern transport layer security',
      keySize: 'Variable',
      use: 'HTTPS, secure communication',
    },
    {
      name: 'bcrypt',
      type: 'Key Derivation',
      description: 'Adaptive password hashing',
      keySize: 'Variable',
      use: 'Password storage',
    },
  ];

  res.json({
    total: methods.length,
    methods,
  });
});

// Error handling middleware
app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    status: 404,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Cybersecurity API running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Visit http://localhost:${PORT} for available endpoints`);
});

export default app;
