package amazon

import (
	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	openaicompatible "github.com/cyberarmor-ai/cyberarmor-go/providers/openai_compatible"
)

func New(ca *cyberarmor.Client, baseURL string) *openaicompatible.Client {
	if baseURL == "" {
		baseURL = "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1"
	}
	return openaicompatible.New(ca, "amazon", baseURL)
}

