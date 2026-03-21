use std::sync::Arc;
use crate::client::CyberArmorClient;
use super::openai_compatible::OpenAICompatibleProvider;

/// Builds an Amazon provider wrapper backed by an OpenAI-compatible endpoint.
pub fn new(client: Arc<CyberArmorClient>, api_key: impl Into<String>, tenant_id: impl Into<String>) -> OpenAICompatibleProvider {
    OpenAICompatibleProvider::new(client, api_key, "amazon", tenant_id, "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1", "amazon.nova-lite-v1:0")
}
