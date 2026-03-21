use std::sync::Arc;
use crate::client::CyberArmorClient;
use super::openai_compatible::OpenAICompatibleProvider;

/// Builds a Meta provider wrapper backed by an OpenAI-compatible endpoint.
pub fn new(client: Arc<CyberArmorClient>, api_key: impl Into<String>, tenant_id: impl Into<String>) -> OpenAICompatibleProvider {
    OpenAICompatibleProvider::new(client, api_key, "meta", tenant_id, "https://api.together.xyz/v1", "llama-3.3-70b-instruct")
}
