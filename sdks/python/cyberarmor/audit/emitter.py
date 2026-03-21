"""
AuditEmitter — batched, background-threaded audit event pipeline.

Events are accumulated in an in-memory queue and flushed to the
CyberArmor audit service in configurable batches on a background thread,
minimising latency impact on the calling code.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import httpx

from .signer import EventSigner

logger = logging.getLogger(__name__)

# Sentinel to signal the background thread to stop
_STOP = object()


class AuditEmitter:
    """
    Thread-safe, batched audit event emitter.

    Usage
    -----
    emitter = AuditEmitter(
        api_url="https://api.cyberarmor.ai/v1",
        api_key="sk-...",
        tenant_id="acme",
        agent_id="my-agent",
    )
    emitter.start()
    emitter.emit("policy_evaluated", {"decision": "allow", "risk_score": 0.12})
    emitter.flush()   # optional: block until queue is empty
    emitter.stop()    # graceful shutdown (flushes remaining events)
    """

    def __init__(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        environment: str = "production",
        batch_size: int = 50,
        flush_interval: float = 5.0,
        max_queue_size: int = 10_000,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        signing_key: Optional[str] = None,
        on_error: Optional[Callable[[Exception, List[Dict]], None]] = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._agent_id = agent_id
        self._environment = environment
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._on_error = on_error

        self._signer = EventSigner(signing_key) if signing_key else None
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._flush_event = threading.Event()
        self._started = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background flush thread."""
        if self._started:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="cyberarmor-audit-emitter",
            daemon=True,
        )
        self._thread.start()
        self._started = True
        logger.debug("AuditEmitter started (batch_size=%d, flush_interval=%.1fs).",
                     self._batch_size, self._flush_interval)

    def stop(self, timeout: float = 10.0) -> None:
        """
        Stop the background thread gracefully, flushing all queued events.
        """
        if not self._started:
            return
        self._queue.put(_STOP)
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        self._started = False
        logger.debug("AuditEmitter stopped.")

    def flush(self, timeout: float = 5.0) -> None:
        """
        Block until the event queue is empty or *timeout* elapses.
        """
        self._flush_event.clear()
        deadline = time.time() + timeout
        while not self._queue.empty() and time.time() < deadline:
            self._flush_event.wait(timeout=0.1)
        self._flush_event.clear()

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def emit(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        severity: str = "info",
    ) -> bool:
        """
        Enqueue an audit event for background delivery.

        Returns True if enqueued, False if the queue is full (dropped).
        """
        if not self._started:
            self.start()

        event: Dict[str, Any] = {
            "event_type": event_type,
            "agent_id": agent_id or self._agent_id,
            "tenant_id": self._tenant_id,
            "environment": self._environment,
            "severity": severity,
            "timestamp": time.time(),
            "payload": payload or {},
        }

        # Sign the event if a signer is configured
        if self._signer:
            try:
                event["signature"] = self._signer.sign(event)
            except Exception as exc:
                logger.warning("Event signing failed (non-fatal): %s", exc)

        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            logger.warning(
                "AuditEmitter queue full (size=%d); event dropped: type=%s",
                self._queue.maxsize, event_type,
            )
            return False

    def emit_sync(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        severity: str = "info",
    ) -> bool:
        """
        Synchronously deliver a single event (bypasses queue/thread).
        Useful for critical events that must not be dropped.
        """
        event: Dict[str, Any] = {
            "event_type": event_type,
            "agent_id": agent_id or self._agent_id,
            "tenant_id": self._tenant_id,
            "environment": self._environment,
            "severity": severity,
            "timestamp": time.time(),
            "payload": payload or {},
        }
        if self._signer:
            try:
                event["signature"] = self._signer.sign(event)
            except Exception as exc:
                logger.warning("Event signing failed: %s", exc)

        return self._post_batch([event])

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Background flush loop."""
        batch: List[Dict[str, Any]] = []
        last_flush = time.monotonic()

        while True:
            try:
                # Wait at most flush_interval for the next event
                remaining = max(0.0, self._flush_interval - (time.monotonic() - last_flush))
                try:
                    item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    item = None

                if item is _STOP:
                    # Drain remaining queue items before exiting
                    while True:
                        try:
                            remaining_item = self._queue.get_nowait()
                            if remaining_item is not _STOP:
                                batch.append(remaining_item)  # type: ignore[arg-type]
                        except queue.Empty:
                            break
                    if batch:
                        self._post_batch(batch)
                    break

                if item is not None:
                    batch.append(item)  # type: ignore[arg-type]

                time_to_flush = (time.monotonic() - last_flush) >= self._flush_interval
                batch_full = len(batch) >= self._batch_size

                if (time_to_flush or batch_full) and batch:
                    self._post_batch(batch)
                    batch = []
                    last_flush = time.monotonic()
                    self._flush_event.set()

            except Exception as exc:
                logger.exception("Unexpected error in AuditEmitter background thread: %s", exc)
                batch = []

    def _post_batch(self, batch: List[Dict[str, Any]]) -> bool:
        """HTTP POST a batch of events to the audit service."""
        if not batch:
            return True
        try:
            with httpx.Client(timeout=self._timeout, verify=self._verify_ssl) as client:
                resp = client.post(
                    f"{self._api_url}/audit/events/batch",
                    json={"events": batch},
                    headers=self._build_headers(),
                )
                resp.raise_for_status()
                logger.debug("AuditEmitter flushed %d events.", len(batch))
                return True
        except Exception as exc:
            logger.warning("AuditEmitter flush failed (%d events): %s", len(batch), exc)
            if self._on_error:
                try:
                    self._on_error(exc, batch)
                except Exception:
                    pass
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-SDK-Version": "1.0.0",
        }
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        if self._tenant_id:
            headers["X-Tenant-ID"] = self._tenant_id
        return headers

    def queue_size(self) -> int:
        """Current number of events waiting to be flushed."""
        return self._queue.qsize()

    def __repr__(self) -> str:
        return (
            f"AuditEmitter("
            f"api_url={self._api_url!r}, "
            f"batch_size={self._batch_size}, "
            f"flush_interval={self._flush_interval}s, "
            f"queue_size={self.queue_size()}, "
            f"started={self._started})"
        )
