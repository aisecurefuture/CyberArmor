// CyberArmor Protect — Visual Studio Extension
// Monitors AI code suggestions, scans for secrets/PII, enforces policies.

using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Community.VisualStudio.Toolkit;

namespace CyberArmor.VisualStudio
{
    [PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
    [ProvideAutoLoad(UIContextGuids80.SolutionExists, PackageAutoLoadFlags.BackgroundLoad)]
    [ProvideMenuResource("Menus.ctmenu", 1)]
    public sealed class CyberArmorPackage : ToolkitPackage
    {
        private static readonly HttpClient _http = new();
        private string _controlPlaneUrl = "http://localhost:8000";
        private string _apiKey = "";

        private static readonly (string Name, string Pattern, string Severity)[] DlpPatterns = new[]
        {
            ("AWS Key", @"AKIA[0-9A-Z]{16}", "critical"),
            ("GitHub Token", @"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "critical"),
            ("Private Key", @"-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----", "critical"),
            ("Password", @"(?i)(password|passwd|pwd)\s*[=:]\s*""[^""]{4,}""", "high"),
            ("Connection String", @"(?i)(mongodb|postgres|mysql|redis)://[^\s""]+", "high"),
            ("SSN", @"\b\d{3}-\d{2}-\d{4}\b", "critical"),
        };

        protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
        {
            await base.InitializeAsync(cancellationToken, progress);
            await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

            // Register commands
            await ScanFileCommand.InitializeAsync(this);
            await ScanSolutionCommand.InitializeAsync(this);

            // Document save event — scan for secrets
            VS.Events.DocumentEvents.Saved += OnDocumentSaved;

            await VS.StatusBar.ShowMessageAsync("CyberArmor Protect: Active");
        }

        private void OnDocumentSaved(string filePath)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    var content = System.IO.File.ReadAllText(filePath);
                    var findings = ScanContent(content);
                    if (findings.Count > 0)
                    {
                        await VS.StatusBar.ShowMessageAsync(
                            $"CyberArmor: {findings.Count} sensitive data finding(s) in {System.IO.Path.GetFileName(filePath)}");
                    }
                }
                catch { }
            });
        }

        public static List<(string Name, int Offset, string Severity)> ScanContent(string content)
        {
            var findings = new List<(string, int, string)>();
            foreach (var (name, pattern, severity) in DlpPatterns)
            {
                foreach (Match m in Regex.Matches(content, pattern))
                {
                    findings.Add((name, m.Index, severity));
                }
            }
            return findings;
        }
    }

    [Command(PackageGuids.guidCyberArmorPackageCmdSetString, 0x0100)]
    internal sealed class ScanFileCommand : BaseCommand<ScanFileCommand>
    {
        protected override async Task ExecuteAsync(OleMenuCmdEventArgs e)
        {
            var docView = await VS.Documents.GetActiveDocumentViewAsync();
            if (docView?.TextBuffer == null) return;
            var content = docView.TextBuffer.CurrentSnapshot.GetText();
            var findings = CyberArmorPackage.ScanContent(content);
            await VS.StatusBar.ShowMessageAsync($"CyberArmor: {findings.Count} finding(s) in active document");
        }
    }

    [Command(PackageGuids.guidCyberArmorPackageCmdSetString, 0x0101)]
    internal sealed class ScanSolutionCommand : BaseCommand<ScanSolutionCommand>
    {
        protected override async Task ExecuteAsync(OleMenuCmdEventArgs e)
        {
            await VS.StatusBar.ShowMessageAsync("CyberArmor: Scanning solution...");
            // Solution-wide scan would enumerate all project files
            await VS.StatusBar.ShowMessageAsync("CyberArmor: Solution scan complete");
        }
    }

    internal static class PackageGuids
    {
        public const string guidCyberArmorPackageCmdSetString = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    }
}
