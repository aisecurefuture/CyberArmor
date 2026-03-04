/**
 * AIShields Protect — Kiro IDE Extension
 * Kiro is an AWS-powered AI IDE. This extension monitors AI-generated code
 * from Kiro's spec-driven development for security issues and sensitive data.
 */

import * as vscode from 'vscode';

const DLP_PATTERNS = [
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'GitHub Token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/g },
  { name: 'Password', pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/gi },
  { name: 'Connection String', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/gi },
];

const SUSPICIOUS_CODE = [
  { name: 'eval', pattern: /\beval\s*\(/g },
  { name: 'shell_exec', pattern: /\b(exec|execSync|child_process|os\.system|subprocess)\s*\(/g },
  { name: 'disable_ssl', pattern: /verify\s*[=:]\s*(?:false|False|0)|rejectUnauthorized\s*:\s*false/g },
];

let diagnostics: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) AIShields';
  statusBar.tooltip = 'AIShields Protect for Kiro';
  statusBar.show();
  context.subscriptions.push(statusBar);

  diagnostics = vscode.languages.createDiagnosticCollection('aishields-kiro');
  context.subscriptions.push(diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand('aishields-kiro.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        const count = scanDocument(editor.document);
        vscode.window.showInformationMessage(`AIShields: ${count} finding(s)`);
      }
    }),
  );

  // Monitor Kiro's AI spec-driven code generation
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      // Kiro generates code from specs — large insertions are likely AI-generated
      const hasLargeInsert = event.contentChanges.some(c => c.text.length > 100);
      if (hasLargeInsert) {
        scanDocument(event.document);
      }
    }),
    vscode.workspace.onWillSaveTextDocument(event => {
      scanDocument(event.document);
    })
  );

  vscode.window.showInformationMessage('AIShields Protect for Kiro activated');
}

export function deactivate() {}

function scanDocument(doc: vscode.TextDocument): number {
  const text = doc.getText();
  const diagList: vscode.Diagnostic[] = [];

  for (const pat of [...DLP_PATTERNS, ...SUSPICIOUS_CODE]) {
    pat.pattern.lastIndex = 0;
    let m;
    while ((m = pat.pattern.exec(text)) !== null) {
      const pos = doc.positionAt(m.index);
      const range = new vscode.Range(pos, doc.positionAt(m.index + m[0].length));
      diagList.push(new vscode.Diagnostic(range, `AIShields: ${pat.name}`, vscode.DiagnosticSeverity.Warning));
    }
  }

  diagnostics.set(doc.uri, diagList);
  return diagList.length;
}
