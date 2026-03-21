// <copyright file="ServiceCollectionExtensions.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Net.Http;
using CyberArmor.Audit;
using CyberArmor.Middleware;
using CyberArmor.Policy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace CyberArmor.Extensions;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> that register CyberArmor SDK services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all CyberArmor SDK services into the ASP.NET Core / Generic Host DI container.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Registers the following singletons:
    /// <list type="bullet">
    ///   <item><see cref="CyberArmorConfig"/> — resolved from environment variables unless overridden via <paramref name="configure"/>.</item>
    ///   <item><see cref="CyberArmorClient"/> — the primary SDK entry-point.</item>
    ///   <item><see cref="PolicyEnforcer"/> — used directly or through <see cref="CyberArmorClient.Policy"/>.</item>
    ///   <item><see cref="AuditEmitter"/> — used directly or through <see cref="CyberArmorClient.Audit"/>.</item>
    ///   <item><see cref="CyberArmorDelegatingHandler"/> — a transient handler for <c>IHttpClientFactory</c> pipelines.</item>
    /// </list>
    /// </para>
    /// <para>
    /// Typical usage in <c>Program.cs</c>:
    /// <code>
    /// builder.Services.AddCyberArmor(cfg =>
    /// {
    ///     cfg.Url = "https://cyberarmor.internal";
    ///     cfg.AgentId = "my-service";
    ///     cfg.AgentSecret = builder.Configuration["CyberArmor:Secret"]!;
    ///     cfg.EnforceMode = EnforceMode.Enforce;
    /// });
    ///
    /// // Attach to a named HttpClient so every AI API call is intercepted:
    /// builder.Services.AddHttpClient("openai")
    ///                 .AddHttpMessageHandler&lt;CyberArmorDelegatingHandler&gt;();
    /// </code>
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">
    ///   Optional delegate to customise <see cref="CyberArmorConfig"/> after it has been
    ///   populated from environment variables. Use this to supply values from
    ///   <c>appsettings.json</c> or <c>IConfiguration</c>.
    /// </param>
    /// <returns>The <paramref name="services"/> for fluent chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddCyberArmor(
        this IServiceCollection services,
        Action<MutableCyberArmorConfig>? configure = null)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        // -------------------------------------------------------------------------
        // 1. Configuration
        // -------------------------------------------------------------------------

        services.TryAddSingleton(sp =>
        {
            var config = CyberArmorConfig.FromEnvironment();

            if (configure is not null)
            {
                // CyberArmorConfig uses init-only setters; we build a mutable copy via the
                // MutableCyberArmorConfig helper and then project back.
                var mutable = new MutableCyberArmorConfig
                {
                    Url = config.Url,
                    AgentId = config.AgentId,
                    AgentSecret = config.AgentSecret,
                    EnforceMode = config.EnforceMode,
                    FailOpen = config.FailOpen,
                    AuditUrl = config.AuditUrl,
                    RouterUrl = config.RouterUrl,
                };

                configure(mutable);
                config = mutable.ToConfig();
            }

            return config;
        });

        // -------------------------------------------------------------------------
        // 2. Shared HttpClient for CyberArmor control-plane calls
        //    We use IHttpClientFactory to participate in handler pooling.
        // -------------------------------------------------------------------------

        services.AddHttpClient(CyberArmorHttpClientName, (sp, http) =>
        {
            var config = sp.GetRequiredService<CyberArmorConfig>();

            if (!string.IsNullOrWhiteSpace(config.AgentId))
                http.DefaultRequestHeaders.Add("X-CyberArmor-Agent-Id", config.AgentId);

            if (!string.IsNullOrWhiteSpace(config.AgentSecret))
                http.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", config.AgentSecret);

            http.DefaultRequestHeaders.Add("User-Agent", "CyberArmor-SDK-DotNet/2.0.0");
            http.DefaultRequestHeaders.Add("Accept", "application/json");
            http.Timeout = TimeSpan.FromSeconds(10);
        });

        // -------------------------------------------------------------------------
        // 3. Core services — singletons
        // -------------------------------------------------------------------------

        services.TryAddSingleton<PolicyEnforcer>(sp =>
        {
            var config = sp.GetRequiredService<CyberArmorConfig>();
            var http = sp.GetRequiredService<IHttpClientFactory>()
                         .CreateClient(CyberArmorHttpClientName);
            var logger = sp.GetRequiredService<ILogger<CyberArmorClient>>();
            return new PolicyEnforcer(config, http, logger);
        });

        services.TryAddSingleton<AuditEmitter>(sp =>
        {
            var config = sp.GetRequiredService<CyberArmorConfig>();
            var http = sp.GetRequiredService<IHttpClientFactory>()
                         .CreateClient(CyberArmorHttpClientName);
            var logger = sp.GetRequiredService<ILogger<CyberArmorClient>>();
            return new AuditEmitter(config, http, logger);
        });

        services.TryAddSingleton<CyberArmorClient>(sp =>
        {
            var config = sp.GetRequiredService<CyberArmorConfig>();
            var http = sp.GetRequiredService<IHttpClientFactory>()
                         .CreateClient(CyberArmorHttpClientName);
            var logger = sp.GetService<ILogger<CyberArmorClient>>();
            return new CyberArmorClient(config, http, logger);
        });

        // -------------------------------------------------------------------------
        // 4. Delegating handler — transient so each named client gets its own instance
        // -------------------------------------------------------------------------

        services.TryAddTransient<CyberArmorDelegatingHandler>(sp =>
        {
            var client = sp.GetRequiredService<CyberArmorClient>();
            var logger = sp.GetService<ILogger<CyberArmorDelegatingHandler>>();
            return new CyberArmorDelegatingHandler(client, logger);
        });

        return services;
    }

    // -------------------------------------------------------------------------
    // Internal constants
    // -------------------------------------------------------------------------

    /// <summary>
    /// The named HTTP client key used by the CyberArmor SDK internally.
    /// Can be used with <c>IHttpClientFactory.CreateClient(CyberArmorHttpClientName)</c>
    /// when you want to obtain the pre-configured control-plane client directly.
    /// </summary>
    public const string CyberArmorHttpClientName = "CyberArmor.ControlPlane";

    // -------------------------------------------------------------------------
    // Private mutable projection of CyberArmorConfig for the configure delegate
    // -------------------------------------------------------------------------

    /// <summary>
    /// A mutable projection of <see cref="CyberArmorConfig"/> used only inside
    /// <see cref="AddCyberArmor"/> to allow the <c>configure</c> Action delegate to mutate values
    /// before they are frozen into the immutable record.
    /// </summary>
    public sealed class MutableCyberArmorConfig
    {
        public string Url { get; set; } = string.Empty;
        public string AgentId { get; set; } = string.Empty;
        public string AgentSecret { get; set; } = string.Empty;
        public EnforceMode EnforceMode { get; set; } = EnforceMode.Enforce;
        public bool FailOpen { get; set; } = false;
        public string? AuditUrl { get; set; }
        public string? RouterUrl { get; set; }

        public CyberArmorConfig ToConfig() => new()
        {
            Url = Url,
            AgentId = AgentId,
            AgentSecret = AgentSecret,
            EnforceMode = EnforceMode,
            FailOpen = FailOpen,
            AuditUrl = AuditUrl,
            RouterUrl = RouterUrl,
        };
    }
}
