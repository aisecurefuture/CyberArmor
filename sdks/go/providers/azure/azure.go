package azure

import (
	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
	openaicompatible "github.com/cyberarmor-ai/cyberarmor-go/providers/openai_compatible"
)

func New(ca *cyberarmor.Client, baseURL string) *openaicompatible.Client {
	if baseURL == "" {
		baseURL = "https://api.openai.azure.com/openai/deployments/default"
	}
	return openaicompatible.New(ca, "microsoft", baseURL)
}

