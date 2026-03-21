// <copyright file="CyberArmorAnthropic.cs" company="CyberArmor AI">
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
using CyberArmor.Audit;
using CyberArmor.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CyberArmor.Providers;

/// <summary>
/// A policy-enforcing, audit-emitting wrapper for the Anthropic Messages API.
/// </summary>
/// <remarks>
/// There is no official Anthropic .NET SDK at this time, so this class communicates
/// with the Anthropic REST API directly via <see cref="HttpClient"/>.
/// The <c>anthropic-version</c> header is set to <c>2023-06-01</c> which is the
/// latest stable API version as of the SDK release date.
///
/// Every call to <see cref="CreateMessageAsync"/> automatically:
/// <list type="number">
///   <item>Extracts the prompt from the request body for policy evaluation.</item>
///   <item>Calls <see cref="PolicyEnforcer.EvaluateAsync"/> on the control plane.</item>
///   <item>Enforces the decision (throws on DENY in Enforce mode).</item>
///   <item>Applies prompt redaction when the decision type warrants it.</item>
///   <item>Forwards the request to <c>https://api.anthropic.com/v1/messages</c>.</item>
///   <item>Emits an <see cref="AuditEvent"/>.</item>
/// </list>
/// </remarks>
public sealed class CyberArmorAnthropic
{
    private const string ProviderName = "anthropic";
    private const string AnthropicApiBase = "https://api.anthropic.com";
    private const string AnthropicVersion = "2023-06-01";
    private const string MessagesEndpoint = "/v1/messages";

    private readonly CyberArmorClient _client;
    private readonly HttpClient _anthropicHttp;
    private readonly string _model;
    private readonly ILogger<CyberArmorAnthropic> _logger;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Initialises a new <see cref="CyberArmorAnthropic"/> wrapper.
    /// </summary>
    /// <param name="client">The CyberArmor SDK client providing policy and audit services.</param>
    /// <param name="apiKey">
    ///   Anthropic API key (set as <c>x-api-key</c> header). Never stored in plain text beyond
    ///   the <see cref="HttpClient"/> headers.
    /// </param>
    /// <param name="model">
    ///   Anthropic model identifier, e.g. <c>claude-opus-4-6</c>. Defaults to <c>claude-opus-4-6</c>.
    /// </param>
    /// <param name="logger">Optional logger. Defaults to <see cref="NullLogger{T}"/>.</param>
    public CyberArmorAnthropic(
        CyberArmorClient client,
        string apiKey,
        string model = "claude-opus-4-6",
        ILogger<CyberArmorAnthropic>? logger = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("Anthropic API key must not be empty.", nameof(apiKey));

        _model = string.IsNullOrWhiteSpace(model) ? "claude-opus-4-6" : model;
        _logger = logger ?? NullLogger<CyberArmorAnthropic>.Instance;

        // Build a dedicated HttpClient for Anthropic; do NOT reuse the CyberArmor client
        // because it carries Bearer credentials meant for the CyberArmor control plane.
        _anthropicHttp = new HttpClient
        {
            BaseAddress = new Uri(AnthropicApiBase),
            Timeout = TimeSpan.FromSeconds(120), // LLM calls can be slow
        };
        _anthropicHttp.DefaultRequestHeaders.Add("x-api-key", apiKey);
        _anthropicHttp.DefaultRequestHeaders.Add("anthropic-version", AnthropicVersion);
        _anthropicHttp.DefaultRequestHeaders.Add("User-Agent", "CyberArmor-SDK-DotNet/2.0.0");
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Evaluates policy, enforces the decision, then POSTs to the Anthropic Messages API.
    /// </summary>
    /// <param name="request">
    ///   The Anthropic messages request body as an arbitrary object that will be serialised
    ///   to JSON. Expected to conform to the
    ///   <see href="https://docs.anthropic.com/en/api/messages">Anthropic Messages API schema</see>.
    ///   The <c>model</c> field will be injected/overwritten with the value supplied to the
    ///   constructor if not already present.
    /// </param>
    /// <param name="tenantId">
    ///   Tenant identifier forwarded to the policy engine and audit service.
    ///   Defaults to the agent ID when not supplied.
    /// </param>
    /// <param name="ct">Optional cancellation token.</param>
    /// <returns>
    ///   The raw Anthropic API response as a <see cref="JsonDocument"/>. The caller is
    ///   responsible for disposing the returned document.
    /// </returns>
    /// <exception cref="PolicyViolationException">
    ///   Thrown when the policy decision is DENY and <see cref="EnforceMode.Enforce"/> is active.
    /// </exception>
    /// <exception cref="HttpRequestException">
    ///   Thrown when the Anthropic API returns a non-success status code.
    /// </exception>
    public async Task<JsonDocument> CreateMessageAsync(
        object request,
        string? tenantId = null,
        CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));

        var effectiveTenantId = tenantId ?? _client.Config.AgentId;

        // Serialise request to a JsonDocument so we can inspect and mutate it.
        var requestJson = SerialiseRequest(request);

        // Extract prompt text for policy evaluation.
        var promptText = ExtractPromptText(requestJson);

        // Step 1: Policy evaluation.
        var decision = await _client.Policy.EvaluateAsync(
            prompt: promptText,
            model: _model,
            provider: ProviderName,
            tenantId: effectiveTenantId,
            ct: ct).ConfigureAwait(false);

        var blocked = !decision.Allowed;

        try
        {
            // Step 2: Enforce.
            _client.Policy.Enforce(decision);

            // Step 3: Apply redaction if needed.
            if (decision.DecisionType == DecisionType.AllowWithRedaction
                && decision.RedactedPrompt is not null)
            {
                _logger.LogDebug("Applying prompt redaction before forwarding to Anthropic.");
                requestJson = ApplyRedaction(requestJson, decision.RedactedPrompt);
            }

            // Ensure the model field in the payload matches what we were constructed with.
            requestJson = EnsureModelField(requestJson, _model);

            // Step 4: Forward to Anthropic.
            var sw = Stopwatch.StartNew();
            using var httpContent = new StringContent(
                requestJson,
                System.Text.Encoding.UTF8,
                "application/json");

            using var response = await _anthropicHttp
                .PostAsync(MessagesEndpoint, httpContent, ct)
                .ConfigureAwait(false);

            sw.Stop();
            _logger.LogDebug(
                "Anthropic API responded HTTP {Status} in {ElapsedMs}ms.",
                (int)response.StatusCode, sw.ElapsedMilliseconds);

            var responseBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Anthropic API returned HTTP {(int)response.StatusCode}: {responseBody}",
                    inner: null,
                    statusCode: response.StatusCode);
            }

            return JsonDocument.Parse(responseBody);
        }
        catch (PolicyViolationException)
        {
            blocked = true;
            throw;
        }
        finally
        {
            EmitAudit(effectiveTenantId, decision, blocked);
        }
    }

    // -------------------------------------------------------------------------
    // IDisposable — owned HttpClient must be disposed
    // -------------------------------------------------------------------------

    /// <summary>
    /// Disposes the internal Anthropic <see cref="HttpClient"/>.
    /// </summary>
    public void Dispose()
    {
        _anthropicHttp.Dispose();
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void EmitAudit(string tenantId, PolicyDecision decision, bool blocked)
    {
        try
        {
            _client.Audit.Emit(AuditEvent.Create(
                tenantId: tenantId,
                agentId: _client.Config.AgentId,
                action: "create_message",
                model: _model,
                provider: ProviderName,
                riskScore: decision.RiskScore,
                blocked: blocked));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to emit audit event for Anthropic call.");
        }
    }

    private static string SerialiseRequest(object request)
    {
        if (request is string s) return s;
        return JsonSerializer.Serialize(request, SerializerOptions);
    }

    /// <summary>
    /// Attempts to extract prompt text from the Anthropic messages payload.
    /// Looks for <c>messages[].content</c> strings (last user turn preferred).
    /// </summary>
    private static string ExtractPromptText(string requestJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(requestJson);
            var root = doc.RootElement;

            if (!root.TryGetProperty("messages", out var messages)) return string.Empty;

            // Walk backwards for the last user message.
            var arr = messages.EnumerateArray();
            var all = new System.Collections.Generic.List<JsonElement>();
            foreach (var msg in arr) all.Add(msg);

            for (int i = all.Count - 1; i >= 0; i--)
            {
                var msg = all[i];
                if (msg.TryGetProperty("role", out var role) && role.GetString() == "user")
                {
                    if (msg.TryGetProperty("content", out var content))
                    {
                        if (content.ValueKind == JsonValueKind.String)
                            return content.GetString() ?? string.Empty;

                        if (content.ValueKind == JsonValueKind.Array)
                        {
                            var parts = new System.Text.StringBuilder();
                            foreach (var part in content.EnumerateArray())
                            {
                                if (part.TryGetProperty("type", out var type)
                                    && type.GetString() == "text"
                                    && part.TryGetProperty("text", out var text))
                                {
                                    parts.Append(text.GetString());
                                }
                            }
                            return parts.ToString();
                        }
                    }
                }
            }
        }
        catch (JsonException) { /* malformed JSON — return empty string */ }

        return string.Empty;
    }

    /// <summary>
    /// Returns a copy of the JSON request with the last user message content replaced
    /// by <paramref name="redactedPrompt"/>.
    /// </summary>
    private static string ApplyRedaction(string requestJson, string redactedPrompt)
    {
        try
        {
            using var doc = JsonDocument.Parse(requestJson);
            // Clone the document into a mutable dictionary.
            var dict = JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, JsonElement>>(requestJson);
            if (dict is null) return requestJson;

            if (dict.TryGetValue("messages", out var msgs) && msgs.ValueKind == JsonValueKind.Array)
            {
                var messageList = JsonSerializer.Deserialize<System.Collections.Generic.List<System.Collections.Generic.Dictionary<string, JsonElement>>>(msgs.GetRawText());
                if (messageList is not null)
                {
                    for (int i = messageList.Count - 1; i >= 0; i--)
                    {
                        if (messageList[i].TryGetValue("role", out var roleEl)
                            && roleEl.GetString() == "user")
                        {
                            // Replace content with redacted string.
                            messageList[i]["content"] = JsonDocument.Parse(
                                JsonSerializer.Serialize(redactedPrompt)).RootElement;
                            break;
                        }
                    }

                    dict["messages"] = JsonDocument.Parse(
                        JsonSerializer.Serialize(messageList)).RootElement;
                }
            }

            return JsonSerializer.Serialize(dict, SerializerOptions);
        }
        catch (JsonException)
        {
            return requestJson; // return original on any parse error
        }
    }

    /// <summary>
    /// Ensures the <c>model</c> field in the JSON payload is set to <paramref name="model"/>.
    /// </summary>
    private static string EnsureModelField(string requestJson, string model)
    {
        try
        {
            var dict = JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, JsonElement>>(requestJson);
            if (dict is null) return requestJson;

            dict["model"] = JsonDocument.Parse(JsonSerializer.Serialize(model)).RootElement;
            return JsonSerializer.Serialize(dict, SerializerOptions);
        }
        catch (JsonException)
        {
            return requestJson;
        }
    }
}
