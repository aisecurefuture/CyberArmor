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

func newTestClient(t *testing.T) *cyberarmor.Client {
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

func TestProviderWrapperDefaults(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()

	g := google.New(c, "")
	if g.Provider != "google" || g.ChatCompletionsEndpoint() != "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions" {
		t.Fatalf("unexpected google wrapper: provider=%s endpoint=%s", g.Provider, g.ChatCompletionsEndpoint())
	}

	a := amazon.New(c, "")
	if a.Provider != "amazon" || a.ChatCompletionsEndpoint() != "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1/chat/completions" {
		t.Fatalf("unexpected amazon wrapper: provider=%s endpoint=%s", a.Provider, a.ChatCompletionsEndpoint())
	}

	ms := azure.New(c, "")
	if ms.Provider != "microsoft" || ms.ChatCompletionsEndpoint() != "https://api.openai.azure.com/openai/deployments/default/chat/completions" {
		t.Fatalf("unexpected microsoft wrapper: provider=%s endpoint=%s", ms.Provider, ms.ChatCompletionsEndpoint())
	}

	x := xai.New(c, "")
	if x.Provider != "xai" || x.ChatCompletionsEndpoint() != "https://api.x.ai/v1/chat/completions" {
		t.Fatalf("unexpected xai wrapper: provider=%s endpoint=%s", x.Provider, x.ChatCompletionsEndpoint())
	}

	m := meta.New(c, "")
	if m.Provider != "meta" || m.ChatCompletionsEndpoint() != "https://api.together.xyz/v1/chat/completions" {
		t.Fatalf("unexpected meta wrapper: provider=%s endpoint=%s", m.Provider, m.ChatCompletionsEndpoint())
	}

	p := perplexity.New(c, "")
	if p.Provider != "perplexity" || p.ChatCompletionsEndpoint() != "https://api.perplexity.ai/chat/completions" {
		t.Fatalf("unexpected perplexity wrapper: provider=%s endpoint=%s", p.Provider, p.ChatCompletionsEndpoint())
	}
}

