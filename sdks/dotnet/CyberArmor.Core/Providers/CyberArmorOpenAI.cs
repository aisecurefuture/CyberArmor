// <copyright file="CyberArmorOpenAI.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CyberArmor.Audit;
using CyberArmor.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using OpenAI.Chat;

namespace CyberArmor.Providers;

/// <summary>
/// A policy-enforcing, audit-emitting wrapper around the OpenAI <see cref="ChatClient"/>.
/// </summary>
/// <remarks>
/// Drop-in replacement for direct use of <see cref="ChatClient"/>. Every call to
/// <see cref="CompleteChatAsync"/> automatically:
/// <list type="number">
///   <item>Extracts the prompt text from the message list.</item>
///   <item>Calls <see cref="PolicyEnforcer.EvaluateAsync"/> on the control plane.</item>
///   <item>Enforces the decision (throws <see cref="PolicyViolationException"/> on DENY in Enforce mode).</item>
///   <item>Applies prompt redaction when the decision type is <see cref="DecisionType.AllowWithRedaction"/>.</item>
///   <item>Forwards the (possibly modified) request to OpenAI.</item>
///   <item>Emits an <see cref="AuditEvent"/> regardless of the outcome.</item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// var guard = new CyberArmorOpenAI(cyberArmorClient, openAiApiKey);
/// var result = await guard.CompleteChatAsync(messages, tenantId: "tenant-abc");
/// Console.WriteLine(result.Content[0].Text);
/// </code>
/// </example>
public sealed class CyberArmorOpenAI
{
    private const string ProviderName = "openai";

    private readonly CyberArmorClient _client;
    private readonly ChatClient _chatClient;
    private readonly string _model;
    private readonly ILogger<CyberArmorOpenAI> _logger;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Initialises a new <see cref="CyberArmorOpenAI"/> wrapper.
    /// </summary>
    /// <param name="client">The CyberArmor SDK client providing policy and audit services.</param>
    /// <param name="apiKey">OpenAI API key.</param>
    /// <param name="model">
    ///   Model identifier. Defaults to <c>gpt-4o</c>.
    ///   This value is also forwarded to the policy engine for model-specific rules.
    /// </param>
    /// <param name="logger">
    ///   Optional logger. Defaults to <see cref="NullLogger{T}"/> when omitted.
    /// </param>
    public CyberArmorOpenAI(
        CyberArmorClient client,
        string apiKey,
        string model = "gpt-4o",
        ILogger<CyberArmorOpenAI>? logger = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("OpenAI API key must not be empty.", nameof(apiKey));

        _model = string.IsNullOrWhiteSpace(model) ? "gpt-4o" : model;
        _logger = logger ?? NullLogger<CyberArmorOpenAI>.Instance;

        _chatClient = new ChatClient(model: _model, apiKey: apiKey);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Evaluates policy, enforces the decision, then calls the OpenAI Chat Completions API.
    /// </summary>
    /// <param name="messages">The list of chat messages to send to the model.</param>
    /// <param name="tenantId">
    ///   Tenant identifier forwarded to the policy engine and audit service.
    ///   Defaults to the agent ID when not supplied.
    /// </param>
    /// <param name="options">Optional <see cref="ChatCompletionOptions"/> forwarded to OpenAI.</param>
    /// <param name="ct">Optional cancellation token.</param>
    /// <returns>The <see cref="ChatCompletion"/> from OpenAI.</returns>
    /// <exception cref="PolicyViolationException">
    ///   Thrown when the policy decision is DENY and <see cref="EnforceMode.Enforce"/> is active.
    /// </exception>
    public async Task<ChatCompletion> CompleteChatAsync(
        IEnumerable<ChatMessage> messages,
        string? tenantId = null,
        ChatCompletionOptions? options = null,
        CancellationToken ct = default)
    {
        var messageList = messages is IList<ChatMessage> l ? l : new List<ChatMessage>(messages);
        var effectiveTenantId = tenantId ?? _client.Config.AgentId;

        // Extract a representative prompt string for policy evaluation.
        var promptText = ExtractPromptText(messageList);

        // Step 1: Policy evaluation.
        var decision = await _client.Policy.EvaluateAsync(
            prompt: promptText,
            model: _model,
            provider: ProviderName,
            tenantId: effectiveTenantId,
            ct: ct).ConfigureAwait(false);

        var blocked = !decision.Allowed;
        bool threw = false;

        try
        {
            // Step 2: Enforce.
            _client.Policy.Enforce(decision);

            // Step 3: Apply redaction if indicated.
            if (decision.DecisionType == DecisionType.AllowWithRedaction
                && decision.RedactedPrompt is not null)
            {
                _logger.LogDebug("Applying prompt redaction before forwarding to OpenAI.");
                messageList = ApplyRedaction(messageList, decision.RedactedPrompt);
            }

            // Step 4: Call OpenAI.
            var sw = Stopwatch.StartNew();
            var result = await _chatClient
                .CompleteChatAsync(messageList, options, ct)
                .ConfigureAwait(false);
            sw.Stop();

            _logger.LogDebug(
                "OpenAI chat completion succeeded in {ElapsedMs}ms.", sw.ElapsedMilliseconds);

            var valueProp = result?.GetType().GetProperty("Value");
            if (valueProp is not null)
            {
                return (ChatCompletion)valueProp.GetValue(result)!;
            }
            return (ChatCompletion)(object)result!;
        }
        catch (PolicyViolationException)
        {
            threw = true;
            blocked = true;
            throw;
        }
        finally
        {
            // Step 5: Always emit audit (even if blocked or an exception was thrown).
            _ = threw; // suppress unused-variable warning in older compilers
            EmitAudit(effectiveTenantId, decision, blocked);
        }
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
                action: "complete_chat",
                model: _model,
                provider: ProviderName,
                riskScore: decision.RiskScore,
                blocked: blocked));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to emit audit event for OpenAI call.");
        }
    }

    /// <summary>
    /// Produces a single string representation of the message list suitable for
    /// policy evaluation. Uses the last user message, or concatenates all messages
    /// when no user message is present.
    /// </summary>
    private static string ExtractPromptText(IList<ChatMessage> messages)
    {
        if (messages.Count == 0) return string.Empty;

        // Prefer the last user message for concise evaluation.
        for (int i = messages.Count - 1; i >= 0; i--)
        {
            if (messages[i] is UserChatMessage userMsg)
            {
                // Concatenate all text content parts.
                var parts = userMsg.Content;
                if (parts.Count > 0)
                {
                    return string.Concat(parts
                        .Where(p => p.Kind == ChatMessageContentPartKind.Text)
                        .Select(p => p.Text));
                }
            }
        }

        // Fallback: concatenate all message text.
        return string.Join("\n", messages
            .SelectMany(m => m.Content)
            .Where(p => p.Kind == ChatMessageContentPartKind.Text)
            .Select(p => p.Text));
    }

    /// <summary>
    /// Replaces the last user message text with the redacted version supplied by the
    /// policy engine, leaving all other messages unchanged.
    /// </summary>
    private static IList<ChatMessage> ApplyRedaction(IList<ChatMessage> messages, string redactedPrompt)
    {
        var copy = new List<ChatMessage>(messages);
        for (int i = copy.Count - 1; i >= 0; i--)
        {
            if (copy[i] is UserChatMessage)
            {
                copy[i] = new UserChatMessage(redactedPrompt);
                break;
            }
        }
        return copy;
    }
}
