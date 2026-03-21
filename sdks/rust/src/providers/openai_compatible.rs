use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tracing::error;

use crate::client::CyberArmorClient;
use crate::error::CyberArmorError;
use crate::policy::DecisionType;

/// Generic OpenAI-compatible provider wrapper with CyberArmor enforcement.
#[derive(Clone, Debug)]
pub struct OpenAICompatibleProvider {
    client: Arc<CyberArmorClient>,
    api_key: String,
    provider: String,
    base_url: String,
    tenant_id: String,
    default_model: String,
}

impl OpenAICompatibleProvider {
    /// Creates a new OpenAI-compatible provider wrapper.
    pub fn new(
        client: Arc<CyberArmorClient>,
        api_key: impl Into<String>,
        provider: impl Into<String>,
        tenant_id: impl Into<String>,
        base_url: impl Into<String>,
        default_model: impl Into<String>,
    ) -> Self {
        Self {
            client,
            api_key: api_key.into(),
            provider: provider.into(),
            base_url: base_url.into(),
            tenant_id: tenant_id.into(),
            default_model: default_model.into(),
        }
    }

    /// Checks policy, optionally redacts, forwards request, and emits audit.
    pub async fn chat_completions(&self, request: Value) -> Result<Value, CyberArmorError> {
        let mut req_obj = match request {
            Value::Object(m) => m,
            other => {
                return Err(CyberArmorError::ConfigError(format!(
                    "chat_completions expects object, got: {other}"
                )));
            }
        };
        if !req_obj.contains_key("model") {
            req_obj.insert("model".to_string(), Value::String(self.default_model.clone()));
        }

        let model = req_obj["model"].as_str().unwrap_or(&self.default_model).to_string();
        let messages = req_obj.get("messages").cloned().unwrap_or(Value::Array(vec![]));
        let prompt = messages.as_array()
            .map(|arr| {
                arr.iter()
                    .filter(|m| m.get("role").and_then(Value::as_str) == Some("user"))
                    .filter_map(|m| m.get("content").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        let decision = self.client.check_policy(&prompt, &model, &self.provider, &self.tenant_id).await?;
        if decision.decision_type == DecisionType::AllowWithRedaction {
            if let Some(ref redacted) = decision.redacted_prompt {
                if let Some(arr) = req_obj.get_mut("messages").and_then(Value::as_array_mut) {
                    if let Some((idx, _)) = arr.iter().enumerate().rev()
                        .find(|(_, m)| m.get("role").and_then(Value::as_str) == Some("user")) {
                        if let Some(obj) = arr[idx].as_object_mut() {
                            obj.insert("content".to_string(), Value::String(redacted.clone()));
                        }
                    }
                }
            }
        }

        let start = Instant::now();
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let result = self.client.http.post(&url)
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .json(&Value::Object(req_obj))
            .send().await;

        let duration_ms = start.elapsed().as_millis() as u64;
        match result {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    let err_body = resp.text().await.unwrap_or_default();
                    return Err(CyberArmorError::UnexpectedStatus { status: status.as_u16(), body: err_body });
                }
                let response: Value = resp.json().await?;
                self.emit_audit("completion_returned", json!({
                    "provider": self.provider,
                    "model": model,
                    "duration_ms": duration_ms,
                    "response_id": response.get("id"),
                })).await;
                Ok(response)
            }
            Err(e) => {
                self.emit_audit("completion_error", json!({
                    "provider": self.provider,
                    "model": model,
                    "duration_ms": duration_ms,
                    "error": e.to_string(),
                })).await;
                Err(CyberArmorError::HttpError(e))
            }
        }
    }

    /// Returns the provider identifier (for example: `openai`, `google`).
    pub fn provider_id(&self) -> &str {
        &self.provider
    }

    /// Returns the configured base URL for this provider wrapper.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn emit_audit(&self, event_type: &str, payload: Value) {
        if let Err(e) = self.client.emit_audit_event(&self.tenant_id, event_type, payload).await {
            error!("[CyberArmor] Audit emission failed: {}", e);
        }
    }
}
