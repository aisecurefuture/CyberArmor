package xai

import (
	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	openaicompatible "github.com/cyberarmor-ai/cyberarmor-go/providers/openai_compatible"
)

func New(ca *cyberarmor.Client, baseURL string) *openaicompatible.Client {
	if baseURL == "" {
		baseURL = "https://api.x.ai/v1"
	}
	return openaicompatible.New(ca, "xai", baseURL)
}

