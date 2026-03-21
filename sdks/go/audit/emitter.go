// Package audit provides audit event emission for CyberArmor.
package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Event represents an audit event.
type Event struct {
	EventID            string         `json:"event_id"`
	TraceID            string         `json:"trace_id"`
	SpanID             string         `json:"span_id"`
	TenantID           string         `json:"tenant_id"`
	AgentID            string         `json:"agent_id"`
	EventType          string         `json:"event_type"`
	Provider           string         `json:"provider,omitempty"`
	Model              string         `json:"model,omitempty"`
	Framework          string         `json:"framework,omitempty"`
	Action             map[string]any `json:"action,omitempty"`
	PolicyDecision     map[string]any `json:"policy_decision,omitempty"`
	DataClassification []string       `json:"data_classification,omitempty"`
	Outcome            string         `json:"outcome"`
	LatencyMs          int            `json:"latency_ms,omitempty"`
	CostUSD            float64        `json:"cost_usd,omitempty"`
	Timestamp          string         `json:"timestamp"`
}

// EmitterConfig is the interface the emitter needs from the client.
type EmitterConfig interface {
	GetControlPlaneURL() string
	GetAgentID() string
	GetAgentSecret() string
	GetHTTPClient() *http.Client
}

// Emitter batches and sends audit events to the control plane.
type Emitter struct {
	cfg       EmitterConfig
	mu        sync.Mutex
	queue     []Event
	batchSize int
	done      chan struct{}
}

// NewEmitter creates a new audit emitter.
func NewEmitter(cfg EmitterConfig, batchSize int, flushInterval time.Duration) *Emitter {
	e := &Emitter{
		cfg:       cfg,
		batchSize: batchSize,
		done:      make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.Flush()
			case <-e.done:
				e.Flush()
				return
			}
		}
	}()
	return e
}

// Emit queues an audit event and returns the event ID.
func (e *Emitter) Emit(eventType string, data map[string]any) string {
	eventID := "evt_" + randomHex(10)
	traceID, _ := data["trace_id"].(string)
	if traceID == "" {
		traceID = "trc_" + randomHex(10)
	}

	evt := Event{
		EventID:   eventID,
		TraceID:   traceID,
		SpanID:    "spn_" + randomHex(8),
		TenantID:  strOrDefault(data["tenant_id"], "default"),
		AgentID:   e.cfg.GetAgentID(),
		EventType: eventType,
		Provider:  strOrDefault(data["provider"], ""),
		Model:     strOrDefault(data["model"], ""),
		Framework: strOrDefault(data["framework"], ""),
		Outcome:   strOrDefault(data["outcome"], "success"),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if action, ok := data["action"].(map[string]any); ok {
		evt.Action = action
	}
	if pd, ok := data["policy_decision"].(map[string]any); ok {
		evt.PolicyDecision = pd
	}

	e.mu.Lock()
	e.queue = append(e.queue, evt)
	shouldFlush := len(e.queue) >= e.batchSize
	e.mu.Unlock()

	if shouldFlush {
		e.Flush()
	}
	return eventID
}

// Flush sends all queued events to the control plane.
func (e *Emitter) Flush() {
	e.mu.Lock()
	if len(e.queue) == 0 {
		e.mu.Unlock()
		return
	}
	batch := make([]Event, len(e.queue))
	copy(batch, e.queue)
	e.queue = e.queue[:0]
	e.mu.Unlock()

	payload, _ := json.Marshal(map[string]any{"events": batch})
	req, err := http.NewRequest(http.MethodPost,
		e.cfg.GetControlPlaneURL()+"/audit/events/batch",
		bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", e.cfg.GetAgentSecret())
	resp, err := e.cfg.GetHTTPClient().Do(req)
	if err == nil && resp != nil {
		resp.Body.Close()
	}
}

// Close stops the background goroutine and flushes remaining events.
func (e *Emitter) Close() {
	close(e.done)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func strOrDefault(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func generateTraceID() string {
	return "trc_" + randomHex(10)
}

// Satisfy interface
var _ fmt.Stringer = Event{}

func (e Event) String() string { return e.EventID }
