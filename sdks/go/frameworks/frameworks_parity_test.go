package frameworks_test

import (
	"context"
	"testing"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	"github.com/cyberarmor-ai/cyberarmor-go/frameworks/langchain"
	"github.com/cyberarmor-ai/cyberarmor-go/frameworks/llamaindex"
	"github.com/cyberarmor-ai/cyberarmor-go/frameworks/vercelai"
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

func TestFrameworkGuardsInvokeDelegates(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()

	lcCalled := false
	lc := langchain.Guard(c, "openai", "gpt-4o", "tenant-1", func(ctx context.Context, prompt string) (string, error) {
		lcCalled = true
		return "lc:" + prompt, nil
	})
	out1, err1 := lc(context.Background(), "hello")
	if err1 != nil || out1 != "lc:hello" || !lcCalled {
		t.Fatalf("langchain guard mismatch: out=%q err=%v called=%v", out1, err1, lcCalled)
	}

	llamaCalled := false
	ll := llamaindex.Guard(c, "anthropic", "claude-3-5-sonnet", "tenant-1", func(ctx context.Context, query string) (string, error) {
		llamaCalled = true
		return "llama:" + query, nil
	})
	out2, err2 := ll(context.Background(), "q")
	if err2 != nil || out2 != "llama:q" || !llamaCalled {
		t.Fatalf("llamaindex guard mismatch: out=%q err=%v called=%v", out2, err2, llamaCalled)
	}

	vercelCalled := false
	vc := vercelai.Guard(c, "google", "gemini-2.0-flash", "tenant-1", func(ctx context.Context, input string) (string, error) {
		vercelCalled = true
		return "vc:" + input, nil
	})
	out3, err3 := vc(context.Background(), "test")
	if err3 != nil || out3 != "vc:test" || !vercelCalled {
		t.Fatalf("vercel guard mismatch: out=%q err=%v called=%v", out3, err3, vercelCalled)
	}
}
