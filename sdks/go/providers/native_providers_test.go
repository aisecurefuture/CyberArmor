package providers_test

import (
	"testing"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/anthropic"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/openai"
)

func newNativeTestClient(t *testing.T) *cyberarmor.Client {
	t.Helper()
	c, err := cyberarmor.NewClient(cyberarmor.Config{
		ControlPlaneURL: "http://localhost:8000",
		AgentID:         "agt_test",
		AgentSecret:     "secret",
		EnforceMode:     "block",
		TimeoutSeconds:  5,
		FailOpen:        true,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func TestNativeProviderDefaults(t *testing.T) {
	c := newNativeTestClient(t)
	defer c.Close()

	o := openai.New(c, "k")
	if o.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("unexpected openai base url: %s", o.BaseURL)
	}

	a := anthropic.New(c, "k")
	if a.BaseURL != "https://api.anthropic.com/v1" {
		t.Fatalf("unexpected anthropic base url: %s", a.BaseURL)
	}
}
