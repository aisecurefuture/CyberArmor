// Package cyberarmor provides RASP (Runtime Application Self-Protection) for Go HTTP services.
// Includes http.RoundTripper wrapper, gin/chi/echo middleware, and AI endpoint detection.
package cyberarmor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config holds RASP configuration.
type Config struct {
	ControlPlaneURL string `json:"control_plane_url"`
	APIKey          string `json:"api_key"`
	TenantID        string `json:"tenant_id"`
	Mode            string `json:"mode"` // "monitor" or "block"
	DLPEnabled      bool   `json:"dlp_enabled"`
	PromptInjection bool   `json:"prompt_injection"`
}

// DefaultConfig returns a config from environment variables.
func DefaultConfig() Config {
	mode := envOrAny("monitor", "CYBERARMOR_MODE")
	if mode == "" {
		mode = "monitor"
	}
	return Config{
		ControlPlaneURL: envOrAny("http://localhost:8000", "CYBERARMOR_URL"),
		APIKey:          envOrAny("", "CYBERARMOR_API_KEY"),
		TenantID:        envOrAny("default", "CYBERARMOR_TENANT"),
		Mode:            mode,
		DLPEnabled:      true,
		PromptInjection: true,
	}
}

func envOrAny(defaultValue string, keys ...string) string {
	for _, key := range keys {
		v := os.Getenv(key)
		if v != "" {
			return v
		}
	}
	return defaultValue
}

// AI endpoint domains
var aiDomains = map[string]bool{
	"api.openai.com": true, "api.anthropic.com": true,
	"generativelanguage.googleapis.com": true, "api.cohere.ai": true,
	"api.mistral.ai": true, "api-inference.huggingface.co": true,
	"api.together.xyz": true, "api.replicate.com": true, "api.groq.com": true,
}

var azurePattern = regexp.MustCompile(`\.openai\.azure\.com$|\.cognitiveservices\.azure\.com$`)

func isAIEndpoint(host string) bool {
	h := strings.Split(host, ":")[0]
	return aiDomains[h] || azurePattern.MatchString(h)
}

// Prompt injection patterns
var promptInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|in)`),
	regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	regexp.MustCompile(`(?i)<\s*(system|prompt|instruction)\s*>`),
	regexp.MustCompile(`(?i)jailbreak|DAN\s+mode|bypass\s+filter`),
}

// DLP patterns
var dlpPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"credit_card", regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)},
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----`)},
}

// InspectionResult holds the result of request inspection.
type InspectionResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// Inspector is the main RASP inspector.
type Inspector struct {
	cfg    Config
	mu     sync.Mutex
	events []map[string]interface{}
}

// New creates a new Inspector with the given config.
func New(cfg Config) *Inspector {
	return &Inspector{cfg: cfg}
}

func (ins *Inspector) record(evtType, url, detail string) {
	ins.mu.Lock()
	ins.events = append(ins.events, map[string]interface{}{
		"ts": time.Now().Unix(), "type": evtType, "url": url,
		"detail": truncate(detail, 200), "tenant": ins.cfg.TenantID,
	})
	if len(ins.events) >= 50 {
		batch := ins.events
		ins.events = nil
		go ins.flush(batch)
	}
	ins.mu.Unlock()
}

func (ins *Inspector) flush(batch []map[string]interface{}) {
	if ins.cfg.ControlPlaneURL == "" {
		return
	}
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", ins.cfg.ControlPlaneURL+"/telemetry/ingest", bytes.NewReader(body))
	if req != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", ins.cfg.APIKey)
		client := &http.Client{Timeout: 5 * time.Second}
		client.Do(req) //nolint:errcheck
	}
}

// Inspect checks a request body for AI security threats.
func (ins *Inspector) Inspect(url, body string) InspectionResult {
	host := extractHost(url)
	if !isAIEndpoint(host) {
		return InspectionResult{Allowed: true}
	}
	ins.record("ai_request", url, "")

	if ins.cfg.PromptInjection && body != "" {
		for _, p := range promptInjectionPatterns {
			if p.MatchString(body) {
				ins.record("prompt_injection", url, p.String())
				if ins.cfg.Mode == "block" {
					return InspectionResult{Allowed: false, Reason: fmt.Sprintf("Prompt injection: %s", p.String())}
				}
			}
		}
	}

	if ins.cfg.DLPEnabled && body != "" {
		var findings []string
		for _, d := range dlpPatterns {
			if d.Pattern.MatchString(body) {
				findings = append(findings, d.Name)
			}
		}
		if len(findings) > 0 {
			ins.record("sensitive_data", url, strings.Join(findings, ","))
			if ins.cfg.Mode == "block" {
				return InspectionResult{Allowed: false, Reason: "Sensitive data: " + strings.Join(findings, ",")}
			}
		}
	}

	return InspectionResult{Allowed: true}
}

// RoundTripper wraps an http.RoundTripper with AI inspection.
func (ins *Inspector) RoundTripper(inner http.RoundTripper) http.RoundTripper {
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &raspTransport{inner: inner, ins: ins}
}

type raspTransport struct {
	inner http.RoundTripper
	ins   *Inspector
}

func (rt *raspTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == "POST" && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
			result := rt.ins.Inspect(req.URL.String(), string(body))
			if !result.Allowed {
				return &http.Response{
					StatusCode: 403,
					Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"error":"%s"}`, result.Reason))),
				}, nil
			}
		}
	}
	return rt.inner.RoundTrip(req)
}

// HTTPMiddleware returns an http.Handler middleware.
func (ins *Inspector) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			if isAIEndpoint(host) {
				body, err := io.ReadAll(r.Body)
				if err == nil {
					r.Body = io.NopCloser(bytes.NewReader(body))
					result := ins.Inspect(fmt.Sprintf("https://%s%s", host, r.URL.Path), string(body))
					if !result.Allowed {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(403)
						json.NewEncoder(w).Encode(map[string]string{"error": result.Reason})
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func extractHost(rawURL string) string {
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rawURL = rawURL[i+3:]
	}
	if i := strings.Index(rawURL, "/"); i >= 0 {
		rawURL = rawURL[:i]
	}
	return strings.Split(rawURL, ":")[0]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func init() {
	log.Println("[CyberArmor RASP] Go module loaded")
}
