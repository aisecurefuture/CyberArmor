// cyberarmor-sdk/src/providers/openai.rs
//
// CyberArmor-wrapped OpenAI chat completions provider.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};
use tracing::error;

use crate::client::CyberArmorClient;
use crate::error::CyberArmorError;
use crate::policy::DecisionType;

const OPENAI_API_BASE: &str = "https://api.openai.com";
const OPENAI_DEFAULT_MODEL: &str = "gpt-4o";

/// A CyberArmor-aware wrapper around the OpenAI Chat Completions API.
///
/// All requests are checked against the CyberArmor policy engine before being
/// forwarded to OpenAI.  Audit events are emitted on success and failure.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use cyberarmor_sdk::{CyberArmorClient, providers::openai::CyberArmorOpenAI};
/// use serde_json::json;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let cyberarmor = Arc::new(CyberArmorClient::from_env());
///     let openai = CyberArmorOpenAI::new(
///         cyberarmor,
///         std::env::var("OPENAI_API_KEY").unwrap(),
///         "acme-corp",
///         None,
///     );
///
///     let response = openai.chat_completions(json!({
///         "model":    "gpt-4o",
///         "messages": [{ "role": "user", "content": "Hello, AI!" }]
///     })).await?;
///
///     println!("{}", response);
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CyberArmorOpenAI {
    /// The underlying CyberArmor client for policy checks and audit emission.
    client: Arc<CyberArmorClient>,

    /// OpenAI API key.
    api_key: String,

    /// OpenAI API base URL (allows overriding for proxies / Azure OpenAI).
    base_url: String,

    /// Default tenant ID for policy evaluation.
    tenant_id: String,

    /// Default model to use when not specified in the request body.
    default_model: String,
}

impl CyberArmorOpenAI {
    /// Create a new `CyberArmorOpenAI` provider.
    ///
    /// # Arguments
    ///
    /// * `client`        — shared CyberArmor client
    /// * `api_key`       — OpenAI API key
    /// * `tenant_id`     — tenant identifier for policy evaluation
    /// * `base_url`      — optional override for the OpenAI base URL
    pub fn new(
        client: Arc<CyberArmorClient>,
        api_key: impl Into<String>,
        tenant_id: impl Into<String>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            client,
            api_key: api_key.into(),
            base_url: base_url.unwrap_or_else(|| OPENAI_API_BASE.to_string()),
            tenant_id: tenant_id.into(),
            default_model: OPENAI_DEFAULT_MODEL.to_string(),
        }
    }

    /// Override the default model.
    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = model.into();
        self
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Check policy then forward a chat completion request to OpenAI.
    ///
    /// `request` must be a JSON object matching the OpenAI Chat Completions API
    /// request schema.  At minimum it must contain a `"messages"` array.
    ///
    /// The `"model"` field will be set to the default model if not present.
    ///
    /// # Errors
    ///
    /// - [`CyberArmorError::PolicyViolation`] if the request is denied in
    ///   enforce mode.
    /// - [`CyberArmorError::HttpError`] if the OpenAI HTTP call fails.
    /// - [`CyberArmorError::SerdeError`] on JSON decode failure.
    pub async fn chat_completions(
        &self,
        request: Value,
    ) -> Result<Value, CyberArmorError> {
        let mut req_obj = match request {
            Value::Object(m) => m,
            other => {
                return Err(CyberArmorError::ConfigError(format!(
                    "chat_completions expects a JSON object, got: {other}"
                )));
            }
        };

        // Ensure model is set.
        if !req_obj.contains_key("model") {
            req_obj.insert("model".to_string(), Value::String(self.default_model.clone()));
        }

        let model    = req_obj["model"].as_str().unwrap_or(&self.default_model).to_string();
        let messages = req_obj.get("messages").cloned().unwrap_or(Value::Array(vec![]));
        let prompt   = self.extract_prompt(&messages);

        let decision = self.client.check_policy(
            &prompt,
            &model,
            "openai",
            &self.tenant_id,
        ).await?;

        // Apply redaction if needed.
        if decision.decision_type == DecisionType::AllowWithRedaction {
            if let Some(ref redacted) = decision.redacted_prompt {
                req_obj.insert(
                    "messages".to_string(),
                    self.apply_redaction(&messages, redacted),
                );
            }
        }

        let start = Instant::now();
        let body  = Value::Object(req_obj);

        let url = format!(
            "{}/v1/chat/completions",
            self.base_url.trim_end_matches('/')
        );

        let result = self
            .client
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    let err_body = resp.text().await.unwrap_or_default();
                    let err_str = format!("OpenAI HTTP {}: {}", status.as_u16(), err_body);

                    self.emit_audit("completion_error", json!({
                        "model":       model,
                        "prompt":      prompt,
                        "decision":    serde_json::to_value(&decision).unwrap_or_default(),
                        "error":       err_str,
                        "duration_ms": duration_ms,
                    })).await;

                    return Err(CyberArmorError::UnexpectedStatus {
                        status: status.as_u16(),
                        body: err_body,
                    });
                }

                let response: Value = resp.json().await?;

                self.emit_audit("completion_returned", json!({
                    "model":       model,
                    "prompt":      prompt,
                    "decision":    serde_json::to_value(&decision).unwrap_or_default(),
                    "response_id": response.get("id"),
                    "usage":       response.get("usage"),
                    "duration_ms": duration_ms,
                })).await;

                Ok(response)
            }
            Err(e) => {
                self.emit_audit("completion_error", json!({
                    "model":       model,
                    "prompt":      prompt,
                    "decision":    serde_json::to_value(&decision).unwrap_or_default(),
                    "error":       e.to_string(),
                    "duration_ms": duration_ms,
                })).await;

                Err(CyberArmorError::HttpError(e))
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Extract a single string from a messages array for policy evaluation.
    fn extract_prompt(&self, messages: &Value) -> String {
        let arr = match messages.as_array() {
            Some(a) => a,
            None => return String::new(),
        };

        arr.iter()
            .filter(|m| m.get("role").and_then(Value::as_str) == Some("user"))
            .filter_map(|m| m.get("content").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Replace the last user message with the redacted prompt.
    fn apply_redaction(&self, messages: &Value, redacted_prompt: &str) -> Value {
        let mut arr = match messages.as_array() {
            Some(a) => a.clone(),
            None => return messages.clone(),
        };

        let last_user_idx = arr
            .iter()
            .enumerate()
            .rev()
            .find(|(_, m)| m.get("role").and_then(Value::as_str) == Some("user"))
            .map(|(i, _)| i);

        if let Some(idx) = last_user_idx {
            if let Some(obj) = arr[idx].as_object_mut() {
                obj.insert("content".to_string(), Value::String(redacted_prompt.to_string()));
            }
        }

        Value::Array(arr)
    }

    /// Emit an audit event; failures are logged but non-fatal.
    async fn emit_audit(&self, event_type: &str, payload: Value) {
        if let Err(e) = self.client.emit_audit_event(&self.tenant_id, event_type, payload).await {
            error!("[CyberArmor] Audit emission failed: {}", e);
        }
    }
}
