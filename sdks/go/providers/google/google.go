package google

import (
	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	openaicompatible "github.com/cyberarmor-ai/cyberarmor-go/providers/openai_compatible"
)

func New(ca *cyberarmor.Client, baseURL string) *openaicompatible.Client {
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta/openai"
	}
	return openaicompatible.New(ca, "google", baseURL)
}

