/**
 * Which One Did I Send? — Privacy Leak Shield
 * Local pattern inspection for sensitive information:
 * - Email addresses
 * - Phone numbers
 * - API keys / Access tokens (OpenAI, GitHub, AWS, Bearer, etc.)
 * - Private key markers (RSA, EC, OPENSSH, etc.)
 * 
 * Includes value masking to avoid leaking secrets in UI and logs.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PrivacyLeakShield = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Severity levels
  const SEVERITY = {
    CRITICAL: 'critical', // Likely exposed secret or private-key material
    HIGH: 'high',         // Potentially sensitive credential or token
    REVIEW: 'review'      // Possible email address, phone number, or personal info
  };

  // Rule definitions with compiled regular expressions
  const DETECTION_RULES = [
    {
      id: 'private_key',
      name: 'Private Key Block',
      category: 'Cryptographic Key',
      severity: SEVERITY.CRITICAL,
      regex: /-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----/gi,
      mask: (val) => '-----BEGIN PRIVATE KEY----- [MASKED KEY CONTENT] -----END PRIVATE KEY-----'
    },
    {
      id: 'aws_access_key',
      name: 'AWS Access Key ID',
      category: 'Cloud Credential',
      severity: SEVERITY.CRITICAL,
      regex: /\b(AKIA[0-9A-Z]{16})\b/g,
      mask: (val) => val.slice(0, 4) + '****************'
    },
    {
      id: 'openai_api_key',
      name: 'OpenAI API Key Pattern',
      category: 'API Token',
      severity: SEVERITY.CRITICAL,
      regex: /\b(sk-[a-zA-Z0-9_-]{20,})\b/g,
      mask: (val) => val.slice(0, 5) + '...' + val.slice(-4)
    },
    {
      id: 'github_token',
      name: 'GitHub Personal Access Token',
      category: 'API Token',
      severity: SEVERITY.CRITICAL,
      regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,})\b/g,
      mask: (val) => val.slice(0, 4) + '...' + val.slice(-4)
    },
    {
      id: 'generic_api_token',
      name: 'Generic API Key / Bearer Token',
      category: 'Credential Pattern',
      severity: SEVERITY.HIGH,
      regex: /(?:api[_-]?key|access[_-]?token|secret[_-]?key|bearer\s+)["':=\s]+([a-zA-Z0-9_\-\.]{24,})/gi,
      captureIndex: 1,
      mask: (val) => val.slice(0, 4) + '...' + val.slice(-4)
    },
    {
      id: 'email_address',
      name: 'Email Address',
      category: 'Personal Information',
      severity: SEVERITY.REVIEW,
      regex: /\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b/g,
      mask: (val) => {
        const parts = val.split('@');
        if (parts.length !== 2) return '***@***.com';
        const user = parts[0];
        const maskedUser = user.length <= 2 ? user[0] + '*' : user[0] + '***' + user.slice(-1);
        return maskedUser + '@' + parts[1];
      }
    },
    {
      id: 'phone_number',
      name: 'Phone Number',
      category: 'Personal Information',
      severity: SEVERITY.REVIEW,
      // Common international and domestic phone number patterns (e.g. +1-555-555-5555, (555) 555-5555, 9876543210)
      regex: /(?:(?:\+?[1-9]\d{0,2}[ -]?)?(?:\(?\d{3}\)?[ -]?)|\b)(\d{3}[ -]?\d{3}[ -]?\d{4}|\d{10})\b/g,
      mask: (val) => {
        const digits = val.replace(/\D/g, '');
        if (digits.length < 4) return '***-***-****';
        return '***-***-' + digits.slice(-4);
      }
    }
  ];

  /**
   * Safe text snippet extractor with surrounding context and masked match
   */
  function extractContextSnippet(text, matchStart, matchEnd, maskedValue, contextRadius = 24) {
    const start = Math.max(0, matchStart - contextRadius);
    const end = Math.min(text.length, matchEnd + contextRadius);

    const prefix = (start > 0 ? '...' : '') + text.slice(start, matchStart).replace(/\r?\n/g, ' ');
    const suffix = text.slice(matchEnd, end).replace(/\r?\n/g, ' ') + (end < text.length ? '...' : '');

    return `${prefix}${maskedValue}${suffix}`;
  }

  /**
   * Scan plain text content for privacy leaks
   * @param {string} content - Raw string content to scan
   * @param {object} options - Options (e.g. custom rules)
   * @returns {object} Scan result with findings, counts, highest severity, etc.
   */
  function scanText(content, options = {}) {
    if (typeof content !== 'string') {
      return {
        supported: false,
        reason: 'Input is not textual string',
        findings: [],
        hasFindings: false
      };
    }

    const findings = [];
    const countsBySeverity = {
      [SEVERITY.CRITICAL]: 0,
      [SEVERITY.HIGH]: 0,
      [SEVERITY.REVIEW]: 0
    };

    const rules = options.rules || DETECTION_RULES;

    for (const rule of rules) {
      // Reset regex index for global search
      rule.regex.lastIndex = 0;
      let match;
      const seenValuesInRule = new Set();

      while ((match = rule.regex.exec(content)) !== null) {
        const fullMatch = match[0];
        const sensitiveValue = rule.captureIndex ? (match[rule.captureIndex] || fullMatch) : fullMatch;
        const matchIndex = rule.captureIndex && match[rule.captureIndex] ? match.index + fullMatch.indexOf(sensitiveValue) : match.index;

        // Skip duplicates within same rule to keep findings clear
        if (seenValuesInRule.has(sensitiveValue)) {
          continue;
        }
        seenValuesInRule.add(sensitiveValue);

        const masked = rule.mask ? rule.mask(sensitiveValue) : '********';
        const snippet = extractContextSnippet(content, matchIndex, matchIndex + sensitiveValue.length, masked);

        findings.push({
          ruleId: rule.id,
          name: rule.name,
          category: rule.category,
          severity: rule.severity,
          maskedValue: masked,
          snippet: snippet,
          location: matchIndex
        });

        countsBySeverity[rule.severity] = (countsBySeverity[rule.severity] || 0) + 1;

        // Prevent infinite loops on zero-length matches
        if (rule.regex.lastIndex === match.index) {
          rule.regex.lastIndex++;
        }
      }
    }

    // Determine highest overall severity
    let highestSeverity = null;
    if (countsBySeverity[SEVERITY.CRITICAL] > 0) highestSeverity = SEVERITY.CRITICAL;
    else if (countsBySeverity[SEVERITY.HIGH] > 0) highestSeverity = SEVERITY.HIGH;
    else if (countsBySeverity[SEVERITY.REVIEW] > 0) highestSeverity = SEVERITY.REVIEW;

    return {
      supported: true,
      hasFindings: findings.length > 0,
      highestSeverity: highestSeverity,
      countsBySeverity: countsBySeverity,
      totalFindings: findings.length,
      findings: findings,
      scanTimestamp: new Date().toISOString()
    };
  }

  /**
   * Determine if a file type can be safely scanned as text
   */
  function isSupportedTextFile(file) {
    if (!file) return false;
    const name = file.name || '';
    const type = file.type || '';

    const textExtensions = [
      '.txt', '.csv', '.tsv', '.json', '.md', '.markdown',
      '.xml', '.html', '.htm', '.js', '.ts', '.jsx', '.tsx',
      '.py', '.java', '.c', '.cpp', '.h', '.sh', '.yaml', '.yml',
      '.env', '.conf', '.cfg', '.ini', '.log', '.sql'
    ];

    const lowerName = name.toLowerCase();
    const hasTextExt = textExtensions.some(ext => lowerName.endsWith(ext));
    const isTextMime = type.startsWith('text/') || type.includes('json') || type.includes('csv');

    return hasTextExt || isTextMime;
  }

  /**
   * Asynchronously scan a browser File object
   */
  async function scanFile(file) {
    if (!file) {
      return { supported: false, reason: 'No file provided', findings: [] };
    }

    if (!isSupportedTextFile(file)) {
      return {
        supported: false,
        reason: 'Content scan unavailable for this file type.',
        hasFindings: false,
        findings: [],
        highestSeverity: null
      };
    }

    try {
      const text = await file.text();
      return scanText(text);
    } catch (err) {
      return {
        supported: false,
        reason: `Failed to read file content: ${err.message}`,
        hasFindings: false,
        findings: []
      };
    }
  }

  return {
    SEVERITY,
    DETECTION_RULES,
    scanText,
    scanFile,
    isSupportedTextFile
  };
});
