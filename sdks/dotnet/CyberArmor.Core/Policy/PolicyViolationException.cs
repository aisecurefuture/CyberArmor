// <copyright file="PolicyViolationException.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;

namespace CyberArmor.Policy;

/// <summary>
/// Thrown by <see cref="PolicyEnforcer.Enforce(PolicyDecision)"/> when a policy decision
/// results in a request being blocked while <see cref="EnforceMode.Enforce"/> mode is active.
/// </summary>
/// <remarks>
/// Catch this exception at the outermost layer of your AI call site to surface a meaningful
/// error to the end user. Do not suppress it silently — doing so defeats the purpose of
/// enforce mode.
/// </remarks>
[Serializable]
public sealed class PolicyViolationException : Exception
{
    /// <summary>
    /// Initialises a new <see cref="PolicyViolationException"/> from a <see cref="PolicyDecision"/>.
    /// </summary>
    /// <param name="decision">The decision that caused the violation.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="decision"/> is <see langword="null"/>.</exception>
    public PolicyViolationException(PolicyDecision decision)
        : base(BuildMessage(decision))
    {
        Decision = decision ?? throw new ArgumentNullException(nameof(decision));
        DecisionType = decision.DecisionType;
        Reason = decision.Reason;
    }

    /// <summary>
    /// Initialises a new <see cref="PolicyViolationException"/> with a custom message.
    /// Used for wrapping or re-throwing scenarios.
    /// </summary>
    /// <param name="decision">The decision that caused the violation.</param>
    /// <param name="innerException">The inner exception.</param>
    public PolicyViolationException(PolicyDecision decision, Exception innerException)
        : base(BuildMessage(decision), innerException)
    {
        Decision = decision ?? throw new ArgumentNullException(nameof(decision));
        DecisionType = decision.DecisionType;
        Reason = decision.Reason;
    }

    // -------------------------------------------------------------------------
    // Properties
    // -------------------------------------------------------------------------

    /// <summary>The full <see cref="PolicyDecision"/> that caused this exception.</summary>
    public PolicyDecision Decision { get; }

    /// <summary>The <see cref="Policy.DecisionType"/> from the offending decision.</summary>
    public DecisionType DecisionType { get; }

    /// <summary>
    /// Human-readable reason provided by the policy engine, if any.
    /// May be <see langword="null"/> when the control plane did not supply one.
    /// </summary>
    public string? Reason { get; }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static string BuildMessage(PolicyDecision decision)
    {
        if (decision is null) return "AI request blocked by CyberArmor policy.";

        var reason = string.IsNullOrWhiteSpace(decision.Reason)
            ? "No reason provided."
            : decision.Reason;

        return $"AI request blocked by CyberArmor policy [{decision.DecisionType}]: {reason} " +
               $"(risk_score={decision.RiskScore:F2})";
    }
}
