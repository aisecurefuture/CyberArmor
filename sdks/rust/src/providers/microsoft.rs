use std::sync::Arc;
use crate::client::CyberArmorClient;
use super::openai_compatible::OpenAICompatibleProvider;

/// Builds a Microsoft provider wrapper backed by an OpenAI-compatible endpoint.
pub fn new(client: Arc<CyberArmorClient>, api_key: impl Into<String>, tenant_id: impl Into<String>) -> OpenAICompatibleProvider {
    OpenAICompatibleProvider::new(client, api_key, "microsoft", tenant_id, "https://api.openai.azure.com/openai/deployments/default", "phi-4")
}
