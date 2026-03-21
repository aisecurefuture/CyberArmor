// <copyright file="CyberArmorClient.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Net.Http;
using CyberArmor.Audit;
using CyberArmor.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CyberArmor;

/// <summary>
/// The primary entry-point for the CyberArmor SDK.
/// Holds references to the <see cref="PolicyEnforcer"/> and <see cref="AuditEmitter"/>
/// and owns the lifecycle of any internally created <see cref="HttpClient"/>.
/// </summary>
/// <example>
/// <code>
/// // Simplest usage — reads configuration from environment variables.
/// using var client = CyberArmorClient.FromEnvironment();
/// var decision = await client.Policy.EvaluateAsync(prompt, "gpt-4o", "openai", tenantId);
/// client.Policy.Enforce(decision);
/// </code>
/// </example>
public sealed class CyberArmorClient : IDisposable
{
    private readonly bool _ownsHttpClient;
    private bool _disposed;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Initialises a new <see cref="CyberArmorClient"/>.
    /// </summary>
    /// <param name="config">SDK configuration.</param>
    /// <param name="httpClient">
    ///   Optional pre-configured <see cref="HttpClient"/>.
    ///   When <see langword="null"/> the client creates and owns an internal instance.
    /// </param>
    /// <param name="logger">
    ///   Optional logger. Defaults to <see cref="NullLogger{T}"/> when omitted.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="config"/> is <see langword="null"/>.</exception>
    public CyberArmorClient(
        CyberArmorConfig config,
        HttpClient? httpClient = null,
        ILogger<CyberArmorClient>? logger = null)
    {
        Config = config ?? throw new ArgumentNullException(nameof(config));

        ILogger effectiveLogger = logger ?? NullLogger<CyberArmorClient>.Instance;

        if (httpClient is null)
        {
            httpClient = BuildDefaultHttpClient(config);
            _ownsHttpClient = true;
        }

        HttpClient = httpClient;

        Policy = new PolicyEnforcer(config, HttpClient, effectiveLogger);
        Audit = new AuditEmitter(config, HttpClient, effectiveLogger);
    }

    // -------------------------------------------------------------------------
    // Public surface
    // -------------------------------------------------------------------------

    /// <summary>The configuration used to create this client.</summary>
    public CyberArmorConfig Config { get; }

    /// <summary>Evaluates and enforces AI request policy decisions.</summary>
    public PolicyEnforcer Policy { get; }

    /// <summary>Emits audit events to the CyberArmor audit service.</summary>
    public AuditEmitter Audit { get; }

    /// <summary>
    /// The underlying <see cref="HttpClient"/> shared by sub-components.
    /// Do not dispose this directly; dispose the <see cref="CyberArmorClient"/> instead.
    /// </summary>
    public HttpClient HttpClient { get; }

    // -------------------------------------------------------------------------
    // Factory helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a <see cref="CyberArmorClient"/> from environment variables via
    /// <see cref="CyberArmorConfig.FromEnvironment()"/>.
    /// </summary>
    /// <param name="httpClient">Optional pre-configured <see cref="HttpClient"/>.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>A fully configured <see cref="CyberArmorClient"/>.</returns>
    public static CyberArmorClient FromEnvironment(
        HttpClient? httpClient = null,
        ILogger<CyberArmorClient>? logger = null)
    {
        var config = CyberArmorConfig.FromEnvironment();
        return new CyberArmorClient(config, httpClient, logger);
    }

    // -------------------------------------------------------------------------
    // IDisposable
    // -------------------------------------------------------------------------

    /// <summary>
    /// Releases resources held by the <see cref="CyberArmorClient"/>, including the
    /// <see cref="AuditEmitter"/> background worker and, if created internally, the
    /// <see cref="HttpClient"/>.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Audit.Dispose();

        if (_ownsHttpClient)
        {
            HttpClient.Dispose();
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static HttpClient BuildDefaultHttpClient(CyberArmorConfig config)
    {
        var client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10),
        };

        if (!string.IsNullOrWhiteSpace(config.AgentId))
        {
            client.DefaultRequestHeaders.Add("X-CyberArmor-Agent-Id", config.AgentId);
        }

        if (!string.IsNullOrWhiteSpace(config.AgentSecret))
        {
            // Use Bearer token authentication for the agent secret.
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", config.AgentSecret);
        }

        client.DefaultRequestHeaders.Add("User-Agent", "CyberArmor-SDK-DotNet/2.0.0");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        return client;
    }
}
