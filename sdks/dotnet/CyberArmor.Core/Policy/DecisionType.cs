// <copyright file="DecisionType.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

namespace CyberArmor.Policy;

/// <summary>
/// Classifies the outcome of a policy evaluation.
/// </summary>
/// <remarks>
/// Decision types are ordered roughly by severity. Values are serialised as strings
/// in audit events and API responses.
/// </remarks>
public enum DecisionType
{
    /// <summary>
    /// The request passes all policy checks and is forwarded without modification.
    /// </summary>
    Allow,

    /// <summary>
    /// The request is blocked by policy. In <see cref="EnforceMode.Enforce"/> mode
    /// the SDK throws a <see cref="PolicyViolationException"/>.
    /// </summary>
    Deny,

    /// <summary>
    /// The request is allowed but PII or sensitive tokens detected in the prompt
    /// have been removed or substituted before the request reaches the model.
    /// </summary>
    AllowWithRedaction,

    /// <summary>
    /// The request is allowed subject to additional rate-limit or token-budget
    /// constraints returned in the decision payload.
    /// </summary>
    AllowWithLimits,

    /// <summary>
    /// The request must be approved by a human reviewer before it is forwarded.
    /// The SDK surfaces this as a blocked state until approval is granted.
    /// </summary>
    RequireApproval,

    /// <summary>
    /// The request is allowed but every detail is written to the audit log for
    /// later review — typically used for high-risk but permitted operations.
    /// </summary>
    AllowWithAuditOnly,

    /// <summary>
    /// The request is isolated: the model call is allowed to proceed in a sandboxed
    /// context, but responses are withheld pending security review.
    /// </summary>
    Quarantine,
}
