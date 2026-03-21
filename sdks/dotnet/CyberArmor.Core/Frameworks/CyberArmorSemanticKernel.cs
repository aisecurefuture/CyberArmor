using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace CyberArmor.Frameworks;

/// <summary>
/// Semantic-Kernel-style adapter that enforces CyberArmor policy
/// and emits audit events around an arbitrary prompt executor delegate.
/// </summary>
public sealed class CyberArmorSemanticKernel
{
    private readonly CyberArmorClient _client;
    private readonly string _provider;
    private readonly string _model;
    private readonly string _tenantId;

    public CyberArmorSemanticKernel(
        CyberArmorClient client,
        string provider = "openai",
        string model = "gpt-4o",
        string? tenantId = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _provider = string.IsNullOrWhiteSpace(provider) ? "openai" : provider;
        _model = string.IsNullOrWhiteSpace(model) ? "gpt-4o" : model;
        _tenantId = string.IsNullOrWhiteSpace(tenantId) ? _client.Config.AgentId : tenantId;
    }

    public async Task<string> InvokeAsync(
        string prompt,
        Func<string, CancellationToken, Task<string>> executor,
        CancellationToken ct = default)
    {
        if (executor is null) throw new ArgumentNullException(nameof(executor));

        var decision = await _client.Policy.EvaluateAsync(
            prompt: prompt,
            model: _model,
            provider: _provider,
            tenantId: _tenantId,
            ct: ct).ConfigureAwait(false);

        _client.Policy.Enforce(decision);

        var sw = Stopwatch.StartNew();
        try
        {
            var output = await executor(prompt, ct).ConfigureAwait(false);
            sw.Stop();
            _client.Audit.Emit(Audit.AuditEvent.Create(
                tenantId: _tenantId,
                agentId: _client.Config.AgentId,
                action: "framework.semantic_kernel.invoke",
                model: _model,
                provider: _provider,
                riskScore: decision.RiskScore,
                blocked: false,
                metadata: new Dictionary<string, object?>
                {
                    ["duration_ms"] = sw.ElapsedMilliseconds,
                }));
            return output;
        }
        catch
        {
            sw.Stop();
            _client.Audit.Emit(Audit.AuditEvent.Create(
                tenantId: _tenantId,
                agentId: _client.Config.AgentId,
                action: "framework.semantic_kernel.error",
                model: _model,
                provider: _provider,
                riskScore: decision.RiskScore,
                blocked: false,
                metadata: new Dictionary<string, object?>
                {
                    ["duration_ms"] = sw.ElapsedMilliseconds,
                }));
            throw;
        }
    }
}
