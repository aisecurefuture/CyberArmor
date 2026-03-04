/**
 * DLP Scanner — Detect sensitive data in source files.
 */

import * as vscode from 'vscode';
import { PolicyClient } from './policy-client';

interface Finding { name: string; line: number; match: string; severity: string; }

const PATTERNS = [
  { name: 'AWS Access Key',   pattern: /AKIA[0-9A-Z]{16}/g,                        severity: 'critical' },
  { name: 'AWS Secret Key',   pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}/g, severity: 'critical' },
  { name: 'GitHub Token',     pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { name: 'Private Key',      pattern: /-----BEGIN\s+(RSA|EC|DSA|PRIVATE)\s+KEY-----/g, severity: 'critical' },
  { name: 'Generic API Key',  pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9]{20,}/gi, severity: 'high' },
  { name: 'JWT',              pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, severity: 'high' },
  { name: 'Password in Code', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi, severity: 'high' },
  { name: 'Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi, severity: 'high' },
  { name: 'SSN',              pattern: /\b\d{3}-\d{2}-\d{4}\b/g,                   severity: 'critical' },
  { name: 'Credit Card',      pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/g,             severity: 'critical' },
  { name: 'Email Address',    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, severity: 'low' },
  { name: 'IP Address',       pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, severity: 'low' },
];

const IGNORED_FILES = /\.(lock|min\.js|min\.css|map|svg|png|jpg|gif|ico|woff|ttf|eot)$/;

export class DLPScanner {
  private policyClient: PolicyClient;
  private diagnostics: vscode.DiagnosticCollection | null = null;
  private sessionFindings = 0;

  constructor(policyClient: PolicyClient) {
    this.policyClient = policyClient;
  }

  setDiagnostics(diag: vscode.DiagnosticCollection) { this.diagnostics = diag; }
  getSessionFindings(): number { return this.sessionFindings; }

  scanDocument(document: vscode.TextDocument): Finding[] {
    if (IGNORED_FILES.test(document.fileName)) return [];

    const text = document.getText();
    const findings: Finding[] = [];
    const diagList: vscode.Diagnostic[] = [];

    for (const pat of PATTERNS) {
      pat.pattern.lastIndex = 0;
      let match;
      while ((match = pat.pattern.exec(text)) !== null) {
        const pos = document.positionAt(match.index);
        findings.push({
          name: pat.name,
          line: pos.line + 1,
          match: match[0].substring(0, 40),
          severity: pat.severity,
        });

        const range = new vscode.Range(pos, document.positionAt(match.index + match[0].length));
        const sev = pat.severity === 'critical' ? vscode.DiagnosticSeverity.Error :
                     pat.severity === 'high' ? vscode.DiagnosticSeverity.Warning :
                     vscode.DiagnosticSeverity.Information;
        diagList.push(new vscode.Diagnostic(range, `AIShields DLP: ${pat.name} detected`, sev));
      }
    }

    if (this.diagnostics) {
      this.diagnostics.set(document.uri, diagList);
    }

    this.sessionFindings += findings.length;
    return findings;
  }
}
