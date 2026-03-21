// <copyright file="CyberArmorDelegatingHandler.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using CyberArmor.Audit;
using CyberArmor.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CyberArmor.Middleware;

/// <summary>
/// An <see cref="HttpMessageHandler"/> that intercepts outgoing HTTP requests destined
/// for known AI API hosts and subjects them to CyberArmor policy evaluation before
/// forwarding. Audit events are emitted for every intercepted request.
/// </summary>
/// <remarks>
/// <para>
/// Register with the .NET HTTP client factory via:
/// <code>
/// services.AddHttpClient("openai")
///         .AddHttpMessageHandler&lt;CyberArmorDelegatingHandler&gt;();
/// </code>
/// or inject directly:
/// <code>
/// var handler = new CyberArmorDelegatingHandler(cyberArmorClient);
/// var http = new HttpClient(handler);
/// </code>
/// </para>
/// <para>
/// The handler recognises the following AI API hosts and maps them to provider names:
/// <list type="bullet">
///   <item><c>api.openai.com</c> → <c>openai</c></item>
///   <item><c>api.anthropic.com</c> → <c>anthropic</c></item>
///   <item><c>generativelanguage.googleapis.com</c> → <c>google</c></item>
///   <item><c>api.cohere.com</c> → <c>cohere</c></item>
///   <item><c>api.mistral.ai</c> → <c>mistral</c></item>
///   <item><c>api.together.xyz</c> → <c>together</c></item>
///   <item><c>api.groq.com</c> → <c>groq</c></item>
///   <item><c>openrouter.ai</c> → <c>openrouter</c></item>
///   <item><c>*.openai.azure.com</c> → <c>azure_openai</c></item>
/// </list>
/// Requests to unrecognised hosts are forwarded without policy checks.
/// </para>
/// </remarks>
public sealed class CyberArmorDelegatingHandler : DelegatingHandler
{
    // -------------------------------------------------------------------------
    // Known AI hosts → provider name mappings
    // -------------------------------------------------------------------------

    private static readonly Dictionary<string, string> KnownAiHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["api.openai.com"]                       = "openai",
        ["api.anthropic.com"]                    = "anthropic",
        ["generativelanguage.googleapis.com"]    = "google",
        ["api.cohere.com"]                       = "cohere",
        ["api.cohere.ai"]                        = "cohere",
        ["api.mistral.ai"]                       = "mistral",
        ["api.together.xyz"]                     = "together",
        ["api.groq.com"]                         = "groq",
        ["openrouter.ai"]                        = "openrouter",
    };

    // Azure OpenAI endpoints follow the pattern: {resource}.openai.azure.com
    private const string AzureOpenAiSuffix = ".openai.azure.com";
    private const string AzureOpenAiProvider = "azure_openai";

    // -------------------------------------------------------------------------
    // Private state
    // -------------------------------------------------------------------------

    private readonly CyberArmorClient _client;
    private readonly ILogger<CyberArmorDelegatingHandler> _logger;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Initialises a new <see cref="CyberArmorDelegatingHandler"/>.
    /// </summary>
    /// <param name="client">The CyberArmor SDK client providing policy and audit services.</param>
    /// <param name="logger">Optional logger. Defaults to <see cref="NullLogger{T}"/>.</param>
    public CyberArmorDelegatingHandler(
        CyberArmorClient client,
        ILogger<CyberArmorDelegatingHandler>? logger = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _logger = logger ?? NullLogger<CyberArmorDelegatingHandler>.Instance;
    }

    // -------------------------------------------------------------------------
    // Core interception logic
    // -------------------------------------------------------------------------

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken ct)
    {
        if (request?.RequestUri is null)
            return await base.SendAsync(request!, ct).ConfigureAwait(false);

        var host = request.RequestUri.Host;
        var provider = ResolveProvider(host);

        // Pass through if the host is not a known AI API.
        if (provider is null)
        {
            return await base.SendAsync(request, ct).ConfigureAwait(false);
        }

        _logger.LogDebug(
            "CyberArmorDelegatingHandler intercepting request to {Host} (provider={Provider}).",
            host, provider);

        // Extract prompt and model from the request body for policy evaluation.
        var (promptText, model) = await ExtractPayloadAsync(request, ct).ConfigureAwait(false);

        var tenantId = _client.Config.AgentId; // use agent ID as tenant proxy if not injected

        // Step 1: Policy evaluation.
        var decision = await _client.Policy.EvaluateAsync(
            prompt: promptText,
            model: model,
            provider: provider,
            tenantId: tenantId,
            ct: ct).ConfigureAwait(false);

        var blocked = !decision.Allowed;

        try
        {
            // Step 2: Enforce.
            _client.Policy.Enforce(decision);

            // Step 3: Apply redaction by rebuilding request body if needed.
            if (decision.DecisionType == DecisionType.AllowWithRedaction
                && decision.RedactedPrompt is not null
                && request.Content is not null)
            {
                request = await ApplyRedactionAsync(request, decision.RedactedPrompt, provider, ct)
                    .ConfigureAwait(false);
            }

            // Step 4: Forward request.
            var response = await base.SendAsync(request, ct).ConfigureAwait(false);

            _logger.LogDebug(
                "AI API {Provider} responded HTTP {Status}.", provider, (int)response.StatusCode);

            return response;
        }
        catch (PolicyViolationException pve)
        {
            blocked = true;
            _logger.LogWarning(
                "Request to {Provider} blocked by policy: {Reason}", provider, pve.Reason);
            // Return a synthetic 403 response so callers see an HTTP-level error.
            return new HttpResponseMessage(System.Net.HttpStatusCode.Forbidden)
            {
                Content = new StringContent(
                    $"{{\"error\":\"policy_violation\",\"reason\":\"{EscapeJson(pve.Reason)}\"}}",
                    Encoding.UTF8,
                    "application/json"),
                ReasonPhrase = "Policy Violation",
            };
        }
        finally
        {
            EmitAudit(tenantId, provider, model, decision, blocked);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static string? ResolveProvider(string host)
    {
        if (KnownAiHosts.TryGetValue(host, out var provider))
            return provider;

        if (host.EndsWith(AzureOpenAiSuffix, StringComparison.OrdinalIgnoreCase))
            return AzureOpenAiProvider;

        return null;
    }

    /// <summary>
    /// Reads and buffers the request body (if any) and extracts prompt text and model name.
    /// The body stream is replaced so downstream handlers can still read it.
    /// </summary>
    private static async Task<(string Prompt, string Model)> ExtractPayloadAsync(
        HttpRequestMessage request,
        CancellationToken ct)
    {
        if (request.Content is null) return (string.Empty, "unknown");

        try
        {
            // Buffer the body so we can read it without consuming the stream.
            await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
            var body = await request.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(body)) return (string.Empty, "unknown");

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            var model = root.TryGetProperty("model", out var modelEl)
                ? modelEl.GetString() ?? "unknown"
                : "unknown";

            // Try to extract text from OpenAI-style messages array.
            if (root.TryGetProperty("messages", out var messages))
            {
                var prompt = ExtractLastUserText(messages);
                return (prompt, model);
            }

            // Try Anthropic-style messages array (same shape, just confirming).
            // Also handle simple "prompt" field (Anthropic legacy completions).
            if (root.TryGetProperty("prompt", out var promptEl))
                return (promptEl.GetString() ?? string.Empty, model);

            return (string.Empty, model);
        }
        catch (JsonException)
        {
            return (string.Empty, "unknown");
        }
    }

    private static string ExtractLastUserText(JsonElement messages)
    {
        if (messages.ValueKind != JsonValueKind.Array) return string.Empty;

        var items = new List<JsonElement>();
        foreach (var m in messages.EnumerateArray()) items.Add(m);

        for (int i = items.Count - 1; i >= 0; i--)
        {
            var msg = items[i];
            if (!msg.TryGetProperty("role", out var roleEl)) continue;
            var role = roleEl.GetString();
            if (role is not "user") continue;

            if (!msg.TryGetProperty("content", out var content)) continue;

            if (content.ValueKind == JsonValueKind.String)
                return content.GetString() ?? string.Empty;

            if (content.ValueKind == JsonValueKind.Array)
            {
                var sb = new StringBuilder();
                foreach (var part in content.EnumerateArray())
                {
                    if (part.TryGetProperty("type", out var typeEl)
                        && typeEl.GetString() == "text"
                        && part.TryGetProperty("text", out var textEl))
                    {
                        sb.Append(textEl.GetString());
                    }
                }
                return sb.ToString();
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Replaces the last user message content in the request body with the redacted prompt,
    /// and returns a new <see cref="HttpRequestMessage"/> with the modified body.
    /// </summary>
    private static async Task<HttpRequestMessage> ApplyRedactionAsync(
        HttpRequestMessage original,
        string redactedPrompt,
        string provider,
        CancellationToken ct)
    {
        try
        {
            var body = await original.Content!.ReadAsStringAsync(ct).ConfigureAwait(false);
            var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body);
            if (dict is null) return original;

            if (dict.TryGetValue("messages", out var msgs) && msgs.ValueKind == JsonValueKind.Array)
            {
                var messageList = JsonSerializer
                    .Deserialize<List<Dictionary<string, JsonElement>>>(msgs.GetRawText());

                if (messageList is not null)
                {
                    for (int i = messageList.Count - 1; i >= 0; i--)
                    {
                        if (messageList[i].TryGetValue("role", out var roleEl)
                            && roleEl.GetString() == "user")
                        {
                            messageList[i]["content"] =
                                JsonDocument.Parse(JsonSerializer.Serialize(redactedPrompt)).RootElement;
                            break;
                        }
                    }

                    dict["messages"] = JsonDocument.Parse(JsonSerializer.Serialize(messageList)).RootElement;
                }
            }
            else if (dict.ContainsKey("prompt"))
            {
                dict["prompt"] = JsonDocument.Parse(JsonSerializer.Serialize(redactedPrompt)).RootElement;
            }

            var newBody = JsonSerializer.Serialize(dict, SerializerOptions);

            // Clone the request — HttpRequestMessage is not reusable after sending.
            var clone = new HttpRequestMessage(original.Method, original.RequestUri)
            {
                Version = original.Version,
                Content = new StringContent(newBody, Encoding.UTF8, "application/json"),
            };

            foreach (var header in original.Headers)
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

            return clone;
        }
        catch (JsonException)
        {
            return original; // return unmodified on parse failure
        }
    }

    private void EmitAudit(
        string tenantId, string provider, string model,
        PolicyDecision decision, bool blocked)
    {
        try
        {
            _client.Audit.Emit(AuditEvent.Create(
                tenantId: tenantId,
                agentId: _client.Config.AgentId,
                action: "proxy_request",
                model: model,
                provider: provider,
                riskScore: decision.RiskScore,
                blocked: blocked));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to emit proxy audit event.");
        }
    }

    private static string EscapeJson(string? s) =>
        s?.Replace("\\", "\\\\").Replace("\"", "\\\"") ?? string.Empty;
}
