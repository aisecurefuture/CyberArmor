use std::sync::Arc;
use crate::client::CyberArmorClient;
use super::openai_compatible::OpenAICompatibleProvider;

/// Builds a Google provider wrapper backed by an OpenAI-compatible endpoint.
pub fn new(client: Arc<CyberArmorClient>, api_key: impl Into<String>, tenant_id: impl Into<String>) -> OpenAICompatibleProvider {
    OpenAICompatibleProvider::new(client, api_key, "google", tenant_id, "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.0-flash")
}
