// AIShields RASP — .NET ASP.NET Core Middleware
// Intercepts AI/LLM API calls, detects prompt injection, enforces DLP, reports telemetry.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AIShields.RASP
{
    public class AIShieldsOptions
    {
        public string ControlPlaneUrl { get; set; } = "http://localhost:8000";
        public string ApiKey { get; set; } = "";
        public string TenantId { get; set; } = "default";
        public bool MonitorMode { get; set; } = true;   // true=log only, false=block
        public bool DlpEnabled { get; set; } = true;
        public bool PromptInjectionDetection { get; set; } = true;
        public int TelemetryBatchSize { get; set; } = 50;
    }

    /// <summary>ASP.NET Core middleware for AI traffic inspection.</summary>
    public class AIShieldsMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<AIShieldsMiddleware> _logger;
        private readonly AIShieldsOptions _options;
        private readonly List<string> _aiEndpoints;
        private readonly List<Regex> _promptInjectionPatterns;
        private readonly List<Regex> _dlpPatterns;
        private readonly List<TelemetryEvent> _eventBuffer = new();
        private readonly SemaphoreSlim _bufferLock = new(1, 1);

        public AIShieldsMiddleware(RequestDelegate next, ILogger<AIShieldsMiddleware> logger, IOptions<AIShieldsOptions> options)
        {
            _next = next;
            _logger = logger;
            _options = options.Value;
            _aiEndpoints = new List<string>
            {
                "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
                "api.cohere.ai", "api.mistral.ai", "api-inference.huggingface.co",
                "api.together.xyz", "api.replicate.com",
                "cognitiveservices.azure.com", "openai.azure.com",
            };
            _promptInjectionPatterns = new List<Regex>
            {
                new(@"ignore\s+(all\s+)?previous\s+instructions", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new(@"you\s+are\s+now\s+(a|an|in)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new(@"system\s*:\s*you\s+are", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new(@"do\s+not\s+follow\s+(any|your)\s+(previous|original)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new(@"<\s*(system|prompt|instruction)\s*>", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new(@"jailbreak|DAN\s+mode|bypass\s+filter", RegexOptions.IgnoreCase | RegexOptions.Compiled),
                new(@"forget\s+(everything|all|your)\s+(you|instructions|rules)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            };
            _dlpPatterns = new List<Regex>
            {
                new(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled),  // SSN
                new(@"\b4[0-9]{12}(?:[0-9]{3})?\b", RegexOptions.Compiled),  // Visa
                new(@"\b5[1-5][0-9]{14}\b", RegexOptions.Compiled),  // Mastercard
                new(@"(?i)AKIA[0-9A-Z]{16}", RegexOptions.Compiled),  // AWS key
                new(@"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", RegexOptions.Compiled),  // GitHub token
                new(@"(?i)-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----", RegexOptions.Compiled),
            };
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var request = context.Request;

            // Check if this is a proxied AI API call
            bool isAiRequest = false;
            string targetHost = request.Headers["X-Forwarded-Host"].FirstOrDefault()
                ?? request.Headers["Host"].FirstOrDefault() ?? "";
            if (_aiEndpoints.Any(ep => targetHost.Contains(ep, StringComparison.OrdinalIgnoreCase)))
                isAiRequest = true;

            if (!isAiRequest || request.Method != "POST")
            {
                await _next(context);
                return;
            }

            // Read and inspect request body
            request.EnableBuffering();
            string body;
            using (var reader = new StreamReader(request.Body, Encoding.UTF8, leaveOpen: true))
            {
                body = await reader.ReadToEndAsync();
                request.Body.Position = 0;
            }

            // Prompt injection detection
            if (_options.PromptInjectionDetection)
            {
                foreach (var pattern in _promptInjectionPatterns)
                {
                    if (pattern.IsMatch(body))
                    {
                        _logger.LogWarning("Prompt injection detected: {Pattern} in request to {Host}", pattern, targetHost);
                        await RecordEvent("prompt_injection", targetHost, body, pattern.ToString());

                        if (!_options.MonitorMode)
                        {
                            context.Response.StatusCode = 403;
                            await context.Response.WriteAsJsonAsync(new { error = "Blocked: prompt injection detected", policy = "aishields-rasp" });
                            return;
                        }
                    }
                }
            }

            // DLP scanning
            if (_options.DlpEnabled)
            {
                foreach (var pattern in _dlpPatterns)
                {
                    if (pattern.IsMatch(body))
                    {
                        _logger.LogWarning("Sensitive data detected in AI request to {Host}", targetHost);
                        await RecordEvent("sensitive_data", targetHost, "[REDACTED]", pattern.ToString());

                        if (!_options.MonitorMode)
                        {
                            context.Response.StatusCode = 403;
                            await context.Response.WriteAsJsonAsync(new { error = "Blocked: sensitive data in AI request", policy = "aishields-rasp-dlp" });
                            return;
                        }
                    }
                }
            }

            await RecordEvent("ai_request", targetHost, "", "");
            await _next(context);
        }

        private async Task RecordEvent(string eventType, string target, string detail, string pattern)
        {
            var evt = new TelemetryEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                EventType = eventType,
                Target = target,
                Detail = detail.Length > 200 ? detail[..200] + "..." : detail,
                Pattern = pattern,
                TenantId = _options.TenantId,
            };

            await _bufferLock.WaitAsync();
            try
            {
                _eventBuffer.Add(evt);
                if (_eventBuffer.Count >= _options.TelemetryBatchSize)
                {
                    var batch = new List<TelemetryEvent>(_eventBuffer);
                    _eventBuffer.Clear();
                    _ = Task.Run(() => FlushTelemetryAsync(batch));
                }
            }
            finally { _bufferLock.Release(); }
        }

        private async Task FlushTelemetryAsync(List<TelemetryEvent> batch)
        {
            if (string.IsNullOrEmpty(_options.ControlPlaneUrl)) return;
            try
            {
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
                var json = JsonSerializer.Serialize(batch);
                await client.PostAsync($"{_options.ControlPlaneUrl}/telemetry/ingest",
                    new StringContent(json, Encoding.UTF8, "application/json"));
            }
            catch (Exception ex)
            {
                _logger.LogDebug("Telemetry flush failed: {Error}", ex.Message);
            }
        }

        private class TelemetryEvent
        {
            public DateTimeOffset Timestamp { get; set; }
            public string EventType { get; set; } = "";
            public string Target { get; set; } = "";
            public string Detail { get; set; } = "";
            public string Pattern { get; set; } = "";
            public string TenantId { get; set; } = "";
        }
    }

    /// <summary>DelegatingHandler for intercepting outbound HttpClient calls to AI services.</summary>
    public class AIShieldsHttpHandler : DelegatingHandler
    {
        private readonly ILogger<AIShieldsHttpHandler> _logger;
        private readonly AIShieldsOptions _options;

        public AIShieldsHttpHandler(ILogger<AIShieldsHttpHandler> logger, IOptions<AIShieldsOptions> options)
        {
            _logger = logger;
            _options = options.Value;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri != null)
            {
                var host = request.RequestUri.Host;
                _logger.LogInformation("AIShields RASP: Outbound request to {Host}{Path}", host, request.RequestUri.PathAndQuery);
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>Extension methods for service registration.</summary>
    public static class AIShieldsExtensions
    {
        public static IServiceCollection AddAIShieldsRasp(this IServiceCollection services, Action<AIShieldsOptions> configure)
        {
            services.Configure(configure);
            services.AddTransient<AIShieldsHttpHandler>();
            return services;
        }

        public static IApplicationBuilder UseAIShieldsRasp(this IApplicationBuilder app)
        {
            return app.UseMiddleware<AIShieldsMiddleware>();
        }
    }
}
