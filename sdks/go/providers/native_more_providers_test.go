package providers_test

import (
	"testing"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/amazon"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/azure"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/google"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/meta"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/perplexity"
	"github.com/cyberarmor-ai/cyberarmor-go/providers/xai"
)

func newMoreNativeTestClient(t *testing.T) *cyberarmor.Client {
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

func TestAdditionalNativeProviderDefaults(t *testing.T) {
	c := newMoreNativeTestClient(t)
	defer c.Close()

	g := google.NewNative(c, "k")
	if g.BaseURL != "https://generativelanguage.googleapis.com/v1beta" {
		t.Fatalf("unexpected google native base url: %s", g.BaseURL)
	}

	a := amazon.NewNative(c, "k")
	if a.BaseURL != "https://bedrock-runtime.us-east-1.amazonaws.com" {
		t.Fatalf("unexpected amazon native base url: %s", a.BaseURL)
	}

	m := azure.NewNative(c, "k")
	if m.BaseURL != "https://api.openai.azure.com" {
		t.Fatalf("unexpected microsoft native base url: %s", m.BaseURL)
	}

	x := xai.NewNative(c, "k")
	if x.BaseURL != "https://api.x.ai/v1" {
		t.Fatalf("unexpected xai native base url: %s", x.BaseURL)
	}

	mt := meta.NewNative(c, "k")
	if mt.BaseURL != "https://api.together.xyz/v1" {
		t.Fatalf("unexpected meta native base url: %s", mt.BaseURL)
	}

	p := perplexity.NewNative(c, "k")
	if p.BaseURL != "https://api.perplexity.ai" {
		t.Fatalf("unexpected perplexity native base url: %s", p.BaseURL)
	}
}
