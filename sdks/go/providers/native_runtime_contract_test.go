package providers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/amazon"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/anthropic"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/azure"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/google"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/openai"
)

func newContractClient(t *testing.T, controlPlaneURL string) *cyberarmor.Client {
	t.Helper()
	c, err := cyberarmor.NewClient(cyberarmor.Config{
		ControlPlaneURL: controlPlaneURL,
		AgentID:         "agt_contract",
		AgentSecret:     "secret",
		EnforceMode:     "block",
		TimeoutSeconds:  5,
		FailOpen:        false,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func TestOpenAINativeRuntimeContractAllowAndDeny(t *testing.T) {
	providerCalls := 0
	deny := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/policies/evaluate" {
			w.Header().Set("Content-Type", "application/json")
			if deny {
				_, _ = w.Write([]byte(`{"decision":"DENY","reason_code":"TEST_DENY","risk_score":0.9}`))
			} else {
				_, _ = w.Write([]byte(`{"decision":"ALLOW","reason_code":"OK","risk_score":0.1}`))
			}
			return
		}
		if r.URL.Path == "/chat/completions" {
			providerCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_openai_1"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := newContractClient(t, srv.URL)
	defer c.Close()

	p := openai.New(c, "k")
	p.BaseURL = srv.URL
	p.HTTP = srv.Client()

	out, err := p.ChatCompletion(context.Background(), "tenant-1", "gpt-4o", []map[string]any{
		{"role": "user", "content": "hello"},
	}, map[string]any{"temperature": 0})
	if err != nil {
		t.Fatalf("allow call failed: %v", err)
	}
	if out["id"] != "resp_openai_1" {
		t.Fatalf("unexpected response id: %v", out["id"])
	}
	if providerCalls != 1 {
		t.Fatalf("expected provider call once, got %d", providerCalls)
	}

	deny = true
	_, err = p.ChatCompletion(context.Background(), "tenant-1", "gpt-4o", []map[string]any{
		{"role": "user", "content": "blocked"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "policy violation") {
		t.Fatalf("expected policy violation, got %v", err)
	}
	if providerCalls != 1 {
		t.Fatalf("provider should not be called on deny; got %d calls", providerCalls)
	}
}

func TestAnthropicNativeRuntimeContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/policies/evaluate":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"decision":"ALLOW","reason_code":"OK","risk_score":0.0}`))
		case "/messages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_anthropic_1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newContractClient(t, srv.URL)
	defer c.Close()
	p := anthropic.New(c, "k")
	p.BaseURL = srv.URL
	p.HTTP = srv.Client()

	out, err := p.CreateMessage(context.Background(), "tenant-1", "claude-3-5-sonnet", []map[string]any{
		{"role": "user", "content": "hello"},
	}, 100, nil)
	if err != nil || out["id"] != "resp_anthropic_1" {
		t.Fatalf("unexpected anthropic result: out=%v err=%v", out, err)
	}
}

func TestGoogleAmazonAzureNativeRuntimeContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/policies/evaluate" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"decision":"ALLOW","reason_code":"OK","risk_score":0.0}`))
			return
		}
		if strings.Contains(r.URL.Path, ":generateContent") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_google_1"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/converse") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_amazon_1"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/chat/completions") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_azure_1"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := newContractClient(t, srv.URL)
	defer c.Close()

	g := google.NewNative(c, "k")
	g.BaseURL = srv.URL
	g.HTTP = srv.Client()
	gOut, gErr := g.GenerateContent(context.Background(), "tenant-1", "gemini-2.0-flash", "hello")
	if gErr != nil || gOut["id"] != "resp_google_1" {
		t.Fatalf("google native mismatch: out=%v err=%v", gOut, gErr)
	}

	a := amazon.NewNative(c, "k")
	a.BaseURL = srv.URL
	a.HTTP = srv.Client()
	aOut, aErr := a.Converse(context.Background(), "tenant-1", "model-1", []map[string]any{
		{"role": "user", "content": "hello"},
	})
	if aErr != nil || aOut["id"] != "resp_amazon_1" {
		t.Fatalf("amazon native mismatch: out=%v err=%v", aOut, aErr)
	}

	m := azure.NewNative(c, "k")
	m.BaseURL = srv.URL
	m.HTTP = srv.Client()
	mOut, mErr := m.ChatCompletions(context.Background(), "tenant-1", "deployment1", []map[string]any{
		{"role": "user", "content": "hello"},
	})
	if mErr != nil || mOut["id"] != "resp_azure_1" {
		t.Fatalf("azure native mismatch: out=%v err=%v", mOut, mErr)
	}
}

func TestPolicyPayloadShapeContract(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/policies/evaluate" {
			defer r.Body.Close()
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"decision":"ALLOW","reason_code":"OK","risk_score":0.0}`))
			return
		}
		if r.URL.Path == "/chat/completions" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_shape_1"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := newContractClient(t, srv.URL)
	defer c.Close()
	p := openai.New(c, "k")
	p.BaseURL = srv.URL
	p.HTTP = srv.Client()

	_, err := p.ChatCompletion(context.Background(), "tenant-1", "gpt-4o", []map[string]any{
		{"role": "user", "content": "shape"},
	}, nil)
	if err != nil {
		t.Fatalf("shape test call failed: %v", err)
	}
	if body["ai_provider"] != "openai" {
		t.Fatalf("expected ai_provider=openai got %v", body["ai_provider"])
	}
	if body["action_type"] == nil {
		t.Fatalf("expected action_type in policy payload")
	}
}
