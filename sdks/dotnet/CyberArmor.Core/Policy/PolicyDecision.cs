// <copyright file="PolicyDecision.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

namespace CyberArmor.Policy;

/// <summary>
/// The immutable result of a policy evaluation returned by <see cref="PolicyEnforcer.EvaluateAsync"/>.
/// </summary>
/// <param name="Allowed">
///   <see langword="true"/> when the request may proceed (possibly with modifications),
///   <see langword="false"/> when the request must be blocked.
/// </param>
/// <param name="DecisionType">
///   Fine-grained classification of the outcome; see <see cref="Policy.DecisionType"/>.
/// </param>
/// <param name="Reason">
///   Human-readable explanation of why this decision was reached, if provided by the
///   control plane. May be <see langword="null"/> for simple allow decisions.
/// </param>
/// <param name="RedactedPrompt">
///   When <paramref name="DecisionType"/> is <see cref="Policy.DecisionType.AllowWithRedaction"/>
///   this contains the sanitised version of the original prompt that should be forwarded
///   to the model. <see langword="null"/> in all other cases.
/// </param>
/// <param name="RiskScore">
///   Normalised risk score in the range [0.0, 1.0] assigned by the policy engine.
///   Higher values indicate higher assessed risk.
/// </param>
/// <param name="LatencyMs">
///   Round-trip latency of the policy evaluation call in milliseconds.
///   Zero for decisions generated locally (e.g. fail-open fallbacks).
/// </param>
public sealed record PolicyDecision(
    bool Allowed,
    DecisionType DecisionType,
    string? Reason,
    string? RedactedPrompt,
    double RiskScore,
    int LatencyMs)
{
    // -------------------------------------------------------------------------
    // Convenience factory methods
    // -------------------------------------------------------------------------

    /// <summary>Creates a local fail-open allow decision (no control-plane call).</summary>
    internal static PolicyDecision FailOpenAllow() =>
        new(Allowed: true,
            DecisionType: DecisionType.Allow,
            Reason: "Fail-open: control plane unreachable",
            RedactedPrompt: null,
            RiskScore: 0.0,
            LatencyMs: 0);

    /// <summary>Creates a local fail-closed deny decision (no control-plane call).</summary>
    internal static PolicyDecision FailClosedDeny() =>
        new(Allowed: false,
            DecisionType: DecisionType.Deny,
            Reason: "Fail-closed: control plane unreachable",
            RedactedPrompt: null,
            RiskScore: 1.0,
            LatencyMs: 0);

    /// <summary>
    /// Returns the effective prompt text to use for a model call.
    /// When this decision includes a redacted prompt, that is returned;
    /// otherwise the caller's original prompt is returned unchanged.
    /// </summary>
    /// <param name="originalPrompt">The unmodified prompt submitted for evaluation.</param>
    /// <returns>The prompt text that should be forwarded to the model.</returns>
    public string EffectivePrompt(string originalPrompt) =>
        DecisionType == DecisionType.AllowWithRedaction && RedactedPrompt is not null
            ? RedactedPrompt
            : originalPrompt;
}
