use std::sync::Arc;

use crate::client::CyberArmorClient;

use super::openai_compatible::OpenAICompatibleProvider;

/// Anthropic provider constructor helper.
///
/// Uses the shared transport wrapper so requests still pass through
/// CyberArmor policy and audit hooks with provider id `anthropic`.
pub fn new(
    client: Arc<CyberArmorClient>,
    api_key: impl Into<String>,
    tenant_id: impl Into<String>,
) -> OpenAICompatibleProvider {
    OpenAICompatibleProvider::new(
        client,
        api_key,
        "anthropic",
        tenant_id,
        "https://api.anthropic.com/v1",
        "claude-3-5-sonnet",
    )
}
