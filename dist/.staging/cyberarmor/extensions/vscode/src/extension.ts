/**
 * AIShields Protect — VS Code Extension
 * Monitors AI code suggestions, scans for secrets/PII, syncs with control plane.
 */

import * as vscode from 'vscode';
import { AIMonitor } from './ai-monitor';
import { DLPScanner } from './dlp-scanner';
import { PolicyClient } from './policy-client';

let aiMonitor: AIMonitor;
let dlpScanner: DLPScanner;
let policyClient: PolicyClient;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  console.log('AIShields Protect extension activating...');

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = '$(shield) AIShields';
  statusBarItem.tooltip = 'AIShields Protect — Active';
  statusBarItem.command = 'aishields.showStatus';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Init components
  const config = vscode.workspace.getConfiguration('aishields');
  policyClient = new PolicyClient(
    config.get('controlPlaneUrl', 'http://localhost:8000'),
    config.get('apiKey', ''),
    config.get('tenantId', 'default'),
  );
  aiMonitor = new AIMonitor(policyClient);
  dlpScanner = new DLPScanner(policyClient);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('aishields.showStatus', () => showStatusPanel()),
    vscode.commands.registerCommand('aishields.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('aishields.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('aishields.toggleMonitoring', () => toggleMonitoring()),
  );

  // File save hook — scan for secrets
  context.subscriptions.push(
    vscode.workspace.onWillSaveTextDocument(event => {
      if (config.get('dlpOnSave', true)) {
        const findings = dlpScanner.scanDocument(event.document);
        if (findings.length > 0) {
          vscode.window.showWarningMessage(
            `AIShields: ${findings.length} sensitive data finding(s) in ${event.document.fileName}`,
            'Show Details', 'Ignore'
          ).then(choice => {
            if (choice === 'Show Details') {
              showFindings(findings);
            }
          });
        }
      }
    })
  );

  // Watch for AI extension completions
  context.subscriptions.push(
    vscode.languages.registerInlineCompletionItemProvider(
      { pattern: '**' },
      aiMonitor.getCompletionProvider()
    )
  );

  // Diagnostics collection for DLP findings
  const diagnostics = vscode.languages.createDiagnosticCollection('aishields');
  context.subscriptions.push(diagnostics);
  dlpScanner.setDiagnostics(diagnostics);

  // Active editor change — scan
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor && config.get('dlpOnOpen', false)) {
        dlpScanner.scanDocument(editor.document);
      }
    })
  );

  // Policy sync
  policyClient.startSync(config.get('syncIntervalSeconds', 60));

  vscode.window.showInformationMessage('AIShields Protect activated');
}

export function deactivate() {
  policyClient?.stopSync();
  console.log('AIShields Protect deactivated');
}

function showStatusPanel() {
  const panel = vscode.window.createWebviewPanel('aishieldsStatus', 'AIShields Status', vscode.ViewColumn.One, {});
  panel.webview.html = `<html><body style="font-family:system-ui;padding:20px;background:#1e1e1e;color:#ccc;">
    <h1>AIShields Protect</h1>
    <p>Status: Active</p>
    <p>Policies loaded: ${policyClient.getPolicyCount()}</p>
    <p>AI suggestions monitored: ${aiMonitor.getMonitoredCount()}</p>
    <p>DLP findings (session): ${dlpScanner.getSessionFindings()}</p>
  </body></html>`;
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) { vscode.window.showWarningMessage('No active file'); return; }
  const findings = dlpScanner.scanDocument(editor.document);
  vscode.window.showInformationMessage(`AIShields: ${findings.length} finding(s) in current file`);
}

async function scanWorkspace() {
  const files = await vscode.workspace.findFiles('**/*.{ts,js,py,java,cs,go,rs,rb,php,json,yaml,yml,env,cfg,ini}', '**/node_modules/**', 500);
  let totalFindings = 0;
  for (const file of files) {
    const doc = await vscode.workspace.openTextDocument(file);
    totalFindings += dlpScanner.scanDocument(doc).length;
  }
  vscode.window.showInformationMessage(`AIShields: Scanned ${files.length} files, ${totalFindings} total finding(s)`);
}

function toggleMonitoring() {
  const config = vscode.workspace.getConfiguration('aishields');
  const current = config.get('enabled', true);
  config.update('enabled', !current, vscode.ConfigurationTarget.Workspace);
  statusBarItem.text = !current ? '$(shield) AIShields' : '$(shield) AIShields (OFF)';
  vscode.window.showInformationMessage(`AIShields monitoring ${!current ? 'enabled' : 'disabled'}`);
}

function showFindings(findings: Array<{name: string, line: number, match: string}>) {
  const channel = vscode.window.createOutputChannel('AIShields DLP');
  channel.show();
  findings.forEach(f => channel.appendLine(`[${f.name}] Line ${f.line}: ${f.match}`));
}
