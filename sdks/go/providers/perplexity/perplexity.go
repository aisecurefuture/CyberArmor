package perplexity

import (
	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	openaicompatible "github.com/cyberarmor-ai/cyberarmor-go/providers/openai_compatible"
)

func New(ca *cyberarmor.Client, baseURL string) *openaicompatible.Client {
	if baseURL == "" {
		baseURL = "https://api.perplexity.ai"
	}
	return openaicompatible.New(ca, "perplexity", baseURL)
}

