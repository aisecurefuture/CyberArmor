/**
 * AI Code Suggestion Monitor
 * Monitors Copilot and other AI code completions for suspicious patterns.
 */

import * as vscode from 'vscode';
import { PolicyClient } from './policy-client';

const SUSPICIOUS_PATTERNS = [
  { name: 'eval_usage', pattern: /\beval\s*\(/, severity: 'high' },
  { name: 'exec_usage', pattern: /\b(exec|execSync|child_process)\s*\(/, severity: 'high' },
  { name: 'shell_injection', pattern: /\b(os\.system|subprocess\.call|Runtime\.exec)\s*\(/, severity: 'critical' },
  { name: 'sql_concatenation', pattern: /["'`]\s*\+\s*.*\+\s*["'`].*(?:SELECT|INSERT|UPDATE|DELETE)/i, severity: 'high' },
  { name: 'hardcoded_secret', pattern: /(?:password|secret|token|api_key)\s*[=:]\s*["'][^"']{8,}["']/i, severity: 'critical' },
  { name: 'disable_security', pattern: /verify\s*[=:]\s*(?:false|False|0)|CURLOPT_SSL_VERIFYPEER.*0/i, severity: 'high' },
  { name: 'dangerous_deserialization', pattern: /\b(pickle\.loads|yaml\.load|unserialize)\s*\(/, severity: 'critical' },
  { name: 'xss_pattern', pattern: /innerHTML\s*=|document\.write\s*\(|\.html\s*\(/, severity: 'medium' },
];

export class AIMonitor {
  private monitoredCount = 0;
  private policyClient: PolicyClient;

  constructor(policyClient: PolicyClient) {
    this.policyClient = policyClient;
  }

  getMonitoredCount(): number { return this.monitoredCount; }

  getCompletionProvider(): vscode.InlineCompletionItemProvider {
    const self = this;
    return {
      provideInlineCompletionItems(document, position, context, token) {
        // We don't provide completions — we just monitor when they're shown
        self.monitoredCount++;
        return [];
      }
    };
  }

  scanCodeSnippet(code: string): Array<{name: string, severity: string, match: string}> {
    const findings: Array<{name: string, severity: string, match: string}> = [];
    for (const pat of SUSPICIOUS_PATTERNS) {
      const match = code.match(pat.pattern);
      if (match) {
        findings.push({ name: pat.name, severity: pat.severity, match: match[0] });
      }
    }
    return findings;
  }
}
