// <copyright file="PolicyEnforcer.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CyberArmor.Policy;

/// <summary>
/// Evaluates AI prompts against the CyberArmor control-plane policy engine and,
/// in enforce mode, blocks requests that violate policy.
/// </summary>
public sealed class PolicyEnforcer
{
    private readonly CyberArmorConfig _config;
    private readonly HttpClient _http;
    private readonly ILogger _logger;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Initialises a new <see cref="PolicyEnforcer"/>.
    /// </summary>
    /// <param name="config">SDK configuration.</param>
    /// <param name="httpClient">Shared <see cref="HttpClient"/> with auth headers pre-set.</param>
    /// <param name="logger">Logger instance.</param>
    public PolicyEnforcer(CyberArmorConfig config, HttpClient httpClient, ILogger logger)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Sends the prompt to the CyberArmor policy engine and returns a <see cref="PolicyDecision"/>.
    /// </summary>
    /// <remarks>
    /// On network failure the method falls back to a local decision according to
    /// <see cref="CyberArmorConfig.FailOpen"/>: fail-open returns <see cref="DecisionType.Allow"/>,
    /// fail-closed returns <see cref="DecisionType.Deny"/>.
    /// </remarks>
    /// <param name="prompt">The raw user or system prompt to evaluate.</param>
    /// <param name="model">The target model identifier (e.g. <c>gpt-4o</c>).</param>
    /// <param name="provider">The AI provider name (e.g. <c>openai</c>, <c>anthropic</c>).</param>
    /// <param name="tenantId">The tenant/organisation identifier for multi-tenant deployments.</param>
    /// <param name="ct">Optional cancellation token.</param>
    /// <returns>A <see cref="PolicyDecision"/> describing the policy outcome.</returns>
    public async Task<PolicyDecision> EvaluateAsync(
        string prompt,
        string model,
        string provider,
        string tenantId,
        CancellationToken ct = default)
    {
        if (_config.EnforceMode == EnforceMode.Off)
        {
            _logger.LogDebug("CyberArmor policy checks are disabled (mode=Off); allowing request.");
            return new PolicyDecision(
                Allowed: true,
                DecisionType: DecisionType.Allow,
                Reason: "Policy enforcement disabled (mode=Off)",
                RedactedPrompt: null,
                RiskScore: 0.0,
                LatencyMs: 0);
        }

        if (string.IsNullOrWhiteSpace(_config.Url))
        {
            _logger.LogWarning("CyberArmor URL not configured; applying fail-{Mode} decision.",
                _config.FailOpen ? "open" : "closed");
            return _config.FailOpen
                ? PolicyDecision.FailOpenAllow()
                : PolicyDecision.FailClosedDeny();
        }

        var requestBody = new PolicyEvaluateRequest(
            Prompt: prompt,
            Model: model,
            Provider: provider,
            TenantId: tenantId,
            AgentId: _config.AgentId);

        var endpoint = _config.Url.TrimEnd('/') + "/v2/policy/evaluate";

        var sw = Stopwatch.StartNew();
        try
        {
            _logger.LogDebug("Evaluating policy for model={Model} provider={Provider} tenant={TenantId}",
                model, provider, tenantId);

            using var response = await _http.PostAsJsonAsync(endpoint, requestBody, SerializerOptions, ct)
                .ConfigureAwait(false);

            sw.Stop();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Policy endpoint returned HTTP {StatusCode}; applying fail-{Mode} decision.",
                    (int)response.StatusCode,
                    _config.FailOpen ? "open" : "closed");

                return _config.FailOpen
                    ? PolicyDecision.FailOpenAllow()
                    : PolicyDecision.FailClosedDeny();
            }

            var raw = await response.Content
                .ReadFromJsonAsync<PolicyEvaluateResponse>(SerializerOptions, ct)
                .ConfigureAwait(false);

            if (raw is null)
            {
                _logger.LogWarning("Policy endpoint returned empty body; applying fail-{Mode} decision.",
                    _config.FailOpen ? "open" : "closed");
                return _config.FailOpen
                    ? PolicyDecision.FailOpenAllow()
                    : PolicyDecision.FailClosedDeny();
            }

            var decisionType = ParseDecisionType(raw.Decision);
            var allowed = decisionType is
                DecisionType.Allow or
                DecisionType.AllowWithRedaction or
                DecisionType.AllowWithLimits or
                DecisionType.AllowWithAuditOnly;

            var decision = new PolicyDecision(
                Allowed: allowed,
                DecisionType: decisionType,
                Reason: raw.Reason,
                RedactedPrompt: raw.RedactedPrompt,
                RiskScore: raw.RiskScore,
                LatencyMs: (int)sw.ElapsedMilliseconds);

            _logger.LogInformation(
                "Policy decision: {DecisionType} (risk={RiskScore:F2}, latency={LatencyMs}ms)",
                decisionType, raw.RiskScore, (int)sw.ElapsedMilliseconds);

            return decision;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Timeout from HttpClient
            sw.Stop();
            _logger.LogWarning(
                "Policy request timed out after {ElapsedMs}ms; applying fail-{Mode} decision.",
                sw.ElapsedMilliseconds,
                _config.FailOpen ? "open" : "closed");
            return _config.FailOpen
                ? PolicyDecision.FailOpenAllow()
                : PolicyDecision.FailClosedDeny();
        }
        catch (HttpRequestException ex)
        {
            sw.Stop();
            _logger.LogWarning(ex,
                "Policy request failed (network error); applying fail-{Mode} decision.",
                _config.FailOpen ? "open" : "closed");
            return _config.FailOpen
                ? PolicyDecision.FailOpenAllow()
                : PolicyDecision.FailClosedDeny();
        }
        catch (JsonException ex)
        {
            sw.Stop();
            _logger.LogWarning(ex,
                "Policy response deserialization failed; applying fail-{Mode} decision.",
                _config.FailOpen ? "open" : "closed");
            return _config.FailOpen
                ? PolicyDecision.FailOpenAllow()
                : PolicyDecision.FailClosedDeny();
        }
    }

    /// <summary>
    /// Inspects a <see cref="PolicyDecision"/> and, if the request is denied while
    /// <see cref="EnforceMode.Enforce"/> mode is active, throws a
    /// <see cref="PolicyViolationException"/>.
    /// </summary>
    /// <param name="decision">The decision to enforce.</param>
    /// <exception cref="PolicyViolationException">
    ///   Thrown when <paramref name="decision"/> is not allowed and the current
    ///   <see cref="CyberArmorConfig.EnforceMode"/> is <see cref="EnforceMode.Enforce"/>.
    /// </exception>
    public void Enforce(PolicyDecision decision)
    {
        if (decision is null) throw new ArgumentNullException(nameof(decision));

        if (decision.Allowed) return;

        if (_config.EnforceMode == EnforceMode.Enforce)
        {
            _logger.LogWarning(
                "Policy violation enforced: {DecisionType} — {Reason}",
                decision.DecisionType, decision.Reason ?? "(no reason)");
            throw new PolicyViolationException(decision);
        }

        // Monitor mode: log but do not block.
        _logger.LogWarning(
            "Policy violation (monitor mode, not blocking): {DecisionType} — {Reason}",
            decision.DecisionType, decision.Reason ?? "(no reason)");
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static DecisionType ParseDecisionType(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return DecisionType.Deny;

        // Normalise: snake_case → PascalCase for enum parsing.
        var normalised = System.Globalization.CultureInfo.InvariantCulture.TextInfo
            .ToTitleCase(raw.Replace('_', ' '))
            .Replace(" ", string.Empty);

        return Enum.TryParse<DecisionType>(normalised, ignoreCase: true, out var result)
            ? result
            : DecisionType.Deny;
    }

    // -------------------------------------------------------------------------
    // Private DTOs
    // -------------------------------------------------------------------------

    private sealed record PolicyEvaluateRequest(
        string Prompt,
        string Model,
        string Provider,
        string TenantId,
        string AgentId);

    private sealed record PolicyEvaluateResponse(
        string? Decision,
        string? Reason,
        string? RedactedPrompt,
        double RiskScore,
        string? PolicyId);
}
