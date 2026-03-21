// <copyright file="AuditEmitter.cs" company="CyberArmor AI">
// Copyright (c) 2026 CyberArmor AI. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CyberArmor.Audit;

/// <summary>
/// Asynchronously emits <see cref="AuditEvent"/> records to the CyberArmor audit ingestion service.
/// </summary>
/// <remarks>
/// Events are enqueued in a non-blocking, bounded in-memory channel and flushed to the remote
/// service either when the batch reaches <see cref="MaxBatchSize"/> events or when the flush
/// interval (<see cref="FlushIntervalSeconds"/> seconds) elapses, whichever comes first.
/// The emitter owns a dedicated background <see cref="Task"/> that runs for the lifetime of
/// the object and terminates gracefully when <see cref="Dispose"/> is called.
/// </remarks>
public sealed class AuditEmitter : IDisposable
{
    // -------------------------------------------------------------------------
    // Constants / tunables
    // -------------------------------------------------------------------------

    /// <summary>Maximum events included in a single batch POST.</summary>
    public const int MaxBatchSize = 50;

    /// <summary>Seconds between automatic flushes when the batch is not yet full.</summary>
    public const int FlushIntervalSeconds = 5;

    /// <summary>Maximum in-flight events held in the channel before Emit() starts dropping.</summary>
    private const int ChannelCapacity = 5_000;

    // -------------------------------------------------------------------------
    // Private state
    // -------------------------------------------------------------------------

    private readonly CyberArmorConfig _config;
    private readonly HttpClient _http;
    private readonly ILogger _logger;
    private readonly Channel<AuditEvent> _channel;
    private readonly CancellationTokenSource _cts;
    private readonly Task _backgroundTask;
    private bool _disposed;

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
    /// Initialises a new <see cref="AuditEmitter"/> and starts the background flush worker.
    /// </summary>
    /// <param name="config">SDK configuration, supplying the audit endpoint URL.</param>
    /// <param name="httpClient">Shared authenticated <see cref="HttpClient"/>.</param>
    /// <param name="logger">Logger instance.</param>
    public AuditEmitter(CyberArmorConfig config, HttpClient httpClient, ILogger logger)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _channel = Channel.CreateBounded<AuditEvent>(new BoundedChannelOptions(ChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        _cts = new CancellationTokenSource();
        _backgroundTask = Task.Run(() => RunFlushLoopAsync(_cts.Token), _cts.Token);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enqueues an <see cref="AuditEvent"/> for background delivery.
    /// This method is non-blocking and thread-safe. If the internal channel is full,
    /// the oldest undelivered event is silently dropped to protect application throughput.
    /// </summary>
    /// <param name="ev">The event to emit.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the emitter has been disposed.</exception>
    public void Emit(AuditEvent ev)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(AuditEmitter));
        if (ev is null) throw new ArgumentNullException(nameof(ev));

        // TryWrite is non-blocking; excess events are dropped per the BoundedChannelFullMode above.
        if (!_channel.Writer.TryWrite(ev))
        {
            _logger.LogWarning(
                "AuditEmitter channel full; dropping audit event {EventId}.", ev.EventId);
        }
    }

    // -------------------------------------------------------------------------
    // IDisposable
    // -------------------------------------------------------------------------

    /// <summary>
    /// Signals the background worker to stop and waits for any in-flight batch
    /// to complete before returning.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _channel.Writer.Complete();
        _cts.Cancel();

        try
        {
            // Allow up to 10 seconds for in-flight events to drain.
            _backgroundTask.Wait(TimeSpan.FromSeconds(10));
        }
        catch (AggregateException) { /* background task may be cancelled — that's fine */ }

        _cts.Dispose();
    }

    // -------------------------------------------------------------------------
    // Background flush loop
    // -------------------------------------------------------------------------

    private async Task RunFlushLoopAsync(CancellationToken ct)
    {
        var batch = new List<AuditEvent>(MaxBatchSize);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(FlushIntervalSeconds));

        try
        {
            while (!ct.IsCancellationRequested)
            {
                // Drain everything available right now, up to MaxBatchSize.
                while (batch.Count < MaxBatchSize
                       && _channel.Reader.TryRead(out var ev))
                {
                    batch.Add(ev);
                }

                if (batch.Count >= MaxBatchSize)
                {
                    await FlushBatchAsync(batch, ct).ConfigureAwait(false);
                    batch.Clear();
                    continue;
                }

                // Wait for either the timer tick or a new event to arrive.
                var timerTask = timer.WaitForNextTickAsync(ct).AsTask();
                var readTask = _channel.Reader.WaitToReadAsync(ct).AsTask();

                await Task.WhenAny(timerTask, readTask).ConfigureAwait(false);

                if (batch.Count > 0)
                {
                    await FlushBatchAsync(batch, ct).ConfigureAwait(false);
                    batch.Clear();
                }
            }
        }
        catch (OperationCanceledException) { /* expected on shutdown */ }

        // Drain remaining events on graceful shutdown.
        while (_channel.Reader.TryRead(out var remaining))
        {
            batch.Add(remaining);
            if (batch.Count >= MaxBatchSize)
            {
                await FlushBatchAsync(batch, CancellationToken.None).ConfigureAwait(false);
                batch.Clear();
            }
        }

        if (batch.Count > 0)
        {
            await FlushBatchAsync(batch, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task FlushBatchAsync(List<AuditEvent> batch, CancellationToken ct)
    {
        if (batch.Count == 0) return;

        var auditUrl = _config.EffectiveAuditUrl;
        if (string.IsNullOrWhiteSpace(auditUrl))
        {
            _logger.LogDebug("No audit URL configured; discarding {Count} audit event(s).", batch.Count);
            return;
        }

        var endpoint = auditUrl.TrimEnd('/') + "/events/batch";

        try
        {
            _logger.LogDebug("Flushing {Count} audit event(s) to {Endpoint}.", batch.Count, endpoint);

            using var response = await _http.PostAsJsonAsync(endpoint, batch, SerializerOptions, ct)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Audit batch POST to {Endpoint} returned HTTP {Status}; events may be lost.",
                    endpoint, (int)response.StatusCode);
            }
            else
            {
                _logger.LogDebug("Audit batch of {Count} event(s) accepted.", batch.Count);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _logger.LogDebug("Audit flush cancelled during shutdown.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _logger.LogWarning(ex,
                "Audit batch POST failed; {Count} event(s) may be lost.", batch.Count);
        }
    }
}
