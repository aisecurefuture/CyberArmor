// <copyright file="AuditEvent.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace CyberArmor.Audit;

/// <summary>
/// A structured audit record emitted for every AI interaction handled by the CyberArmor SDK.
/// </summary>
/// <param name="EventId">
///   Globally unique identifier for this event.
///   Callers should use <see cref="Guid.NewGuid()"/> unless a specific ID is required.
/// </param>
/// <param name="TraceId">
///   Distributed-tracing trace identifier (e.g. W3C TraceContext or OpenTelemetry trace ID).
///   Pass an empty string when tracing is not in use.
/// </param>
/// <param name="SpanId">
///   Span identifier within the trace. Pass an empty string when tracing is not in use.
/// </param>
/// <param name="TenantId">
///   Tenant or organisation identifier. Used for multi-tenant audit segregation.
/// </param>
/// <param name="AgentId">
///   Identifier of the RASP/SDK agent that emitted this event.
/// </param>
/// <param name="Action">
///   Short verb describing the SDK action, e.g. <c>evaluate_policy</c>, <c>complete_chat</c>,
///   <c>create_message</c>, <c>proxy_request</c>.
/// </param>
/// <param name="Model">
///   Model identifier targeted by this request (e.g. <c>gpt-4o</c>, <c>claude-3-5-sonnet</c>).
/// </param>
/// <param name="Provider">
///   AI provider name, lower-case (e.g. <c>openai</c>, <c>anthropic</c>, <c>azure</c>).
/// </param>
/// <param name="RiskScore">
///   Risk score [0.0–1.0] from the policy engine for this request. Zero when policy was not invoked.
/// </param>
/// <param name="Blocked">
///   <see langword="true"/> when the request was blocked by policy; otherwise <see langword="false"/>.
/// </param>
/// <param name="Timestamp">
///   UTC timestamp at which the event was created.
/// </param>
/// <param name="Metadata">
///   Optional key-value bag for additional context (prompt hash, response token count, etc.).
///   Values must be JSON-serialisable primitives or strings. May be <see langword="null"/>.
/// </param>
public sealed record AuditEvent(
    Guid EventId,
    string TraceId,
    string SpanId,
    string TenantId,
    string AgentId,
    string Action,
    string Model,
    string Provider,
    double RiskScore,
    bool Blocked,
    DateTimeOffset Timestamp,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    Dictionary<string, object?>? Metadata = null)
{
    // -------------------------------------------------------------------------
    // Factory helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a new <see cref="AuditEvent"/> with a fresh <see cref="EventId"/> and
    /// the current UTC timestamp.
    /// </summary>
    /// <param name="tenantId">Tenant identifier.</param>
    /// <param name="agentId">Agent identifier.</param>
    /// <param name="action">Action verb.</param>
    /// <param name="model">Target model.</param>
    /// <param name="provider">AI provider.</param>
    /// <param name="riskScore">Risk score from policy evaluation.</param>
    /// <param name="blocked">Whether the request was blocked.</param>
    /// <param name="traceId">Optional trace identifier.</param>
    /// <param name="spanId">Optional span identifier.</param>
    /// <param name="metadata">Optional extra metadata.</param>
    /// <returns>A fully populated <see cref="AuditEvent"/>.</returns>
    public static AuditEvent Create(
        string tenantId,
        string agentId,
        string action,
        string model,
        string provider,
        double riskScore,
        bool blocked,
        string? traceId = null,
        string? spanId = null,
        Dictionary<string, object?>? metadata = null)
    {
        return new AuditEvent(
            EventId: Guid.NewGuid(),
            TraceId: traceId ?? string.Empty,
            SpanId: spanId ?? string.Empty,
            TenantId: tenantId,
            AgentId: agentId,
            Action: action,
            Model: model,
            Provider: provider,
            RiskScore: riskScore,
            Blocked: blocked,
            Timestamp: DateTimeOffset.UtcNow,
            Metadata: metadata);
    }
}
