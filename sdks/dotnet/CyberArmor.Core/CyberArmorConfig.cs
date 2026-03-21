// <copyright file="CyberArmorConfig.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;

namespace CyberArmor;

/// <summary>
/// Controls how the SDK reacts when a policy decision is DENY.
/// </summary>
public enum EnforceMode
{
    /// <summary>Block the request and throw a <see cref="Policy.PolicyViolationException"/>.</summary>
    Enforce,

    /// <summary>Allow the request through but log the violation for review.</summary>
    Monitor,

    /// <summary>SDK checks are entirely disabled; all requests pass unchecked.</summary>
    Off,
}

/// <summary>
/// Immutable runtime configuration for the CyberArmor SDK.
/// Populate via constructor or <see cref="FromEnvironment()"/> for twelve-factor apps.
/// </summary>
public sealed class CyberArmorConfig
{
    /// <summary>
    /// Base URL of the CyberArmor Control Plane API.
    /// Example: <c>https://cyberarmor.example.com</c>
    /// </summary>
    public string Url { get; init; } = string.Empty;

    /// <summary>Unique identifier for this agent registration.</summary>
    public string AgentId { get; init; } = string.Empty;

    /// <summary>Shared secret used to authenticate this agent against the control plane.</summary>
    public string AgentSecret { get; init; } = string.Empty;

    /// <summary>
    /// Determines whether policy violations block the request, are observed only, or checks are skipped.
    /// Defaults to <see cref="EnforceMode.Enforce"/>.
    /// </summary>
    public EnforceMode EnforceMode { get; init; } = EnforceMode.Enforce;

    /// <summary>
    /// When <see langword="true"/>, failures reaching the control plane allow the request through
    /// (fail-open). When <see langword="false"/>, unreachable control plane causes a DENY (fail-closed).
    /// Defaults to <see langword="false"/> (fail-closed) for maximum security.
    /// </summary>
    public bool FailOpen { get; init; } = false;

    /// <summary>
    /// Optional override URL for the audit/event ingestion endpoint.
    /// Defaults to <c>{Url}/audit</c> when not set.
    /// </summary>
    public string? AuditUrl { get; init; }

    /// <summary>
    /// Optional override URL for the AI request router.
    /// Defaults to <c>{Url}/router</c> when not set.
    /// </summary>
    public string? RouterUrl { get; init; }

    // -------------------------------------------------------------------------
    // Derived helpers
    // -------------------------------------------------------------------------

    /// <summary>Returns the effective audit base URL.</summary>
    public string EffectiveAuditUrl =>
        AuditUrl ?? (string.IsNullOrWhiteSpace(Url) ? string.Empty : Url.TrimEnd('/') + "/audit");

    /// <summary>Returns the effective router base URL.</summary>
    public string EffectiveRouterUrl =>
        RouterUrl ?? (string.IsNullOrWhiteSpace(Url) ? string.Empty : Url.TrimEnd('/') + "/router");

    // -------------------------------------------------------------------------
    // Factory
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a <see cref="CyberArmorConfig"/> from environment variables.
    /// </summary>
    /// <remarks>
    /// Reads:
    /// <list type="bullet">
    ///   <item><c>CYBERARMOR_URL</c></item>
    ///   <item><c>CYBERARMOR_AGENT_ID</c></item>
    ///   <item><c>CYBERARMOR_AGENT_SECRET</c></item>
    ///   <item><c>CYBERARMOR_ENFORCE_MODE</c> (Enforce | Monitor | Off)</item>
    ///   <item><c>CYBERARMOR_FAIL_OPEN</c> (true | false | 1 | 0)</item>
    ///   <item><c>CYBERARMOR_AUDIT_URL</c></item>
    ///   <item><c>CYBERARMOR_ROUTER_URL</c></item>
    /// </list>
    /// </remarks>
    /// <returns>A fully populated <see cref="CyberArmorConfig"/>.</returns>
    public static CyberArmorConfig FromEnvironment()
    {
        static string? Env(string primary, string? fallback = null) =>
            Environment.GetEnvironmentVariable(primary)
            ?? (fallback is not null ? Environment.GetEnvironmentVariable(fallback) : null);

        var url = Env("CYBERARMOR_URL") ?? string.Empty;
        var agentId = Env("CYBERARMOR_AGENT_ID") ?? string.Empty;
        var agentSecret = Env("CYBERARMOR_AGENT_SECRET") ?? string.Empty;

        var enforceMode = EnforceMode.Enforce;
        var enforceModeRaw = Env("CYBERARMOR_ENFORCE_MODE");
        if (!string.IsNullOrWhiteSpace(enforceModeRaw)
            && Enum.TryParse<EnforceMode>(enforceModeRaw, ignoreCase: true, out var parsed))
        {
            enforceMode = parsed;
        }

        var failOpen = false;
        var failOpenRaw = Env("CYBERARMOR_FAIL_OPEN");
        if (!string.IsNullOrWhiteSpace(failOpenRaw))
        {
            failOpen = failOpenRaw is "1" or "true" or "True" or "TRUE" or "yes" or "YES";
        }

        return new CyberArmorConfig
        {
            Url = url,
            AgentId = agentId,
            AgentSecret = agentSecret,
            EnforceMode = enforceMode,
            FailOpen = failOpen,
            AuditUrl = Env("CYBERARMOR_AUDIT_URL"),
            RouterUrl = Env("CYBERARMOR_ROUTER_URL"),
        };
    }
}
