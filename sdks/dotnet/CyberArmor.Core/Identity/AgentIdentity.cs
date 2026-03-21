// <copyright file="AgentIdentity.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CyberArmor.Identity;

/// <summary>
/// Represents the registered identity of a CyberArmor RASP/SDK agent and provides
/// methods for issuing short-lived JWT tokens scoped to specific operations.
/// </summary>
/// <remarks>
/// Tokens are issued by the CyberArmor Identity Service (port 8004 in the default deployment).
/// They are signed with the agent's registered secret and include the requested scopes so that
/// downstream services can authorise calls without contacting the identity service on every request.
/// </remarks>
public sealed class AgentIdentity
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
    /// Initialises a new <see cref="AgentIdentity"/>.
    /// </summary>
    /// <param name="config">SDK configuration.</param>
    /// <param name="httpClient">Authenticated <see cref="HttpClient"/>.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="agentId">Agent identifier (overrides <paramref name="config"/> when non-null).</param>
    /// <param name="tenantId">Tenant identifier resolved during registration.</param>
    /// <param name="trustLevel">Trust level string returned by the identity service (e.g. <c>high</c>).</param>
    /// <param name="capabilities">List of capabilities granted to this agent.</param>
    public AgentIdentity(
        CyberArmorConfig config,
        HttpClient httpClient,
        ILogger logger,
        string? agentId = null,
        string? tenantId = null,
        string? trustLevel = null,
        IReadOnlyList<string>? capabilities = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        AgentId = agentId ?? config.AgentId;
        TenantId = tenantId ?? string.Empty;
        TrustLevel = trustLevel ?? "unknown";
        Capabilities = capabilities ?? Array.Empty<string>();
    }

    // -------------------------------------------------------------------------
    // Properties
    // -------------------------------------------------------------------------

    /// <summary>The unique identifier for this agent.</summary>
    public string AgentId { get; }

    /// <summary>The tenant/organisation this agent belongs to.</summary>
    public string TenantId { get; }

    /// <summary>
    /// Trust level string (e.g. <c>high</c>, <c>medium</c>, <c>low</c>) as assigned by
    /// the CyberArmor control plane during registration.
    /// </summary>
    public string TrustLevel { get; }

    /// <summary>
    /// The set of capabilities granted to this agent (e.g. <c>policy.evaluate</c>,
    /// <c>audit.write</c>, <c>model.invoke</c>).
    /// </summary>
    public IReadOnlyList<string> Capabilities { get; }

    // -------------------------------------------------------------------------
    // Token issuance
    // -------------------------------------------------------------------------

    /// <summary>
    /// Requests a short-lived JWT from the CyberArmor Identity Service that is
    /// scoped to the specified operations.
    /// </summary>
    /// <param name="scopes">
    ///   Array of OAuth2-style scope strings (e.g. <c>policy.evaluate</c>,
    ///   <c>audit.write</c>, <c>model.invoke</c>).
    /// </param>
    /// <param name="expiresInSeconds">
    ///   Requested token lifetime in seconds. Defaults to 3600 (one hour).
    ///   The identity service may cap this to its own maximum.
    /// </param>
    /// <param name="ct">Optional cancellation token.</param>
    /// <returns>A signed JWT string.</returns>
    /// <exception cref="InvalidOperationException">
    ///   Thrown when the identity service returns an unsuccessful response or an
    ///   empty token.
    /// </exception>
    public async Task<string> IssueTokenAsync(
        string[] scopes,
        int expiresInSeconds = 3600,
        CancellationToken ct = default)
    {
        if (scopes is null || scopes.Length == 0)
            throw new ArgumentException("At least one scope must be specified.", nameof(scopes));

        var identityBaseUrl = _config.Url.TrimEnd('/');
        var endpoint = identityBaseUrl + "/v2/identity/token";

        var requestBody = new TokenRequest(
            AgentId: AgentId,
            TenantId: TenantId,
            Scopes: scopes,
            ExpiresIn: expiresInSeconds);

        _logger.LogDebug(
            "Requesting identity token for agent={AgentId} scopes={Scopes} ttl={Ttl}s",
            AgentId, string.Join(",", scopes), expiresInSeconds);

        try
        {
            using var response = await _http.PostAsJsonAsync(endpoint, requestBody, SerializerOptions, ct)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                throw new InvalidOperationException(
                    $"Identity service returned HTTP {(int)response.StatusCode}: {body}");
            }

            var tokenResponse = await response.Content
                .ReadFromJsonAsync<TokenResponse>(SerializerOptions, ct)
                .ConfigureAwait(false);

            if (tokenResponse is null || string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
                throw new InvalidOperationException("Identity service returned an empty token.");

            _logger.LogDebug(
                "Identity token issued; expires_in={ExpiresIn}s token_type={TokenType}",
                tokenResponse.ExpiresIn, tokenResponse.TokenType);

            return tokenResponse.AccessToken;
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"Failed to reach the CyberArmor Identity Service at {endpoint}.", ex);
        }
    }

    // -------------------------------------------------------------------------
    // Factory: resolve from control plane
    // -------------------------------------------------------------------------

    /// <summary>
    /// Registers (or refreshes) this agent's identity with the control plane and
    /// returns a populated <see cref="AgentIdentity"/>.
    /// </summary>
    /// <param name="config">SDK configuration.</param>
    /// <param name="httpClient">Authenticated <see cref="HttpClient"/>.</param>
    /// <param name="logger">Logger instance.</param>
    /// <param name="ct">Optional cancellation token.</param>
    /// <returns>A resolved <see cref="AgentIdentity"/>.</returns>
    public static async Task<AgentIdentity> ResolveAsync(
        CyberArmorConfig config,
        HttpClient httpClient,
        ILogger logger,
        CancellationToken ct = default)
    {
        if (config is null) throw new ArgumentNullException(nameof(config));
        if (httpClient is null) throw new ArgumentNullException(nameof(httpClient));
        if (logger is null) throw new ArgumentNullException(nameof(logger));

        var endpoint = config.Url.TrimEnd('/') + "/v2/identity/agents/" + Uri.EscapeDataString(config.AgentId);

        logger.LogDebug("Resolving agent identity for {AgentId}", config.AgentId);

        try
        {
            var registration = await httpClient
                .GetFromJsonAsync<AgentRegistrationResponse>(endpoint, SerializerOptions, ct)
                .ConfigureAwait(false);

            if (registration is null)
                throw new InvalidOperationException("Identity service returned empty registration.");

            return new AgentIdentity(
                config: config,
                httpClient: httpClient,
                logger: logger,
                agentId: registration.AgentId,
                tenantId: registration.TenantId,
                trustLevel: registration.TrustLevel,
                capabilities: registration.Capabilities);
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "Could not resolve agent identity; returning default.");
            return new AgentIdentity(config, httpClient, logger);
        }
    }

    // -------------------------------------------------------------------------
    // Private DTOs
    // -------------------------------------------------------------------------

    private sealed record TokenRequest(
        string AgentId,
        string TenantId,
        string[] Scopes,
        int ExpiresIn);

    private sealed record TokenResponse(
        string AccessToken,
        string TokenType,
        int ExpiresIn);

    private sealed record AgentRegistrationResponse(
        string AgentId,
        string TenantId,
        string TrustLevel,
        IReadOnlyList<string> Capabilities);
}
