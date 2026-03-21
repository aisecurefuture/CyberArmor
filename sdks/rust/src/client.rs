// cyberarmor-sdk/src/client.rs
//
// Primary async client for the CyberArmor AI Identity Control Plane.

use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::{header, Client as ReqwestClient};
use serde_json::{json, Value};
use sha2::Sha256;
use tracing::{error, warn};

use crate::audit;
use crate::config::{CyberArmorConfig, EnforceMode};
use crate::error::CyberArmorError;
use crate::policy::{DecisionType, PolicyDecision};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 3;
const SDK_USER_AGENT: &str = concat!("cyberarmor-sdk-rust/", env!("CARGO_PKG_VERSION"));

/// Primary client for interacting with the CyberArmor AI Identity Control Plane.
///
/// `CyberArmorClient` is cheaply cloneable (backed by an `Arc` inside `reqwest::Client`).
///
/// # Example
///
/// ```no_run
/// use cyberarmor_sdk::CyberArmorClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = CyberArmorClient::from_env();
///     let decision = client.check_policy(
///         "Tell me about AI safety",
///         "gpt-4o",
///         "openai",
///         "acme-corp",
///     ).await?;
///
///     println!("Allowed: {}", decision.is_allowed());
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CyberArmorClient {
    pub(crate) config: CyberArmorConfig,
    pub(crate) http: ReqwestClient,
}

impl CyberArmorClient {
    /// Create a new client from the provided configuration.
    pub fn new(config: CyberArmorConfig) -> Self {
        let http = ReqwestClient::builder()
            .user_agent(SDK_USER_AGENT)
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .build()
            .expect("failed to build reqwest client");

        Self { config, http }
    }

    /// Create a new client by reading configuration from environment variables.
    ///
    /// # Panics
    ///
    /// Panics if required environment variables are not set.
    /// See [`CyberArmorConfig::from_env`] for details.
    pub fn from_env() -> Self {
        Self::new(CyberArmorConfig::from_env())
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Evaluate the policy engine for an AI request.
    ///
    /// # Arguments
    ///
    /// * `prompt`    — raw user prompt
    /// * `model`     — model identifier, e.g. `"gpt-4o"`
    /// * `provider`  — provider name, e.g. `"openai"`
    /// * `tenant_id` — tenant identifier
    ///
    /// # Errors
    ///
    /// - [`CyberArmorError::PolicyViolation`] when the engine denies the request
    ///   and `enforce_mode` is `Enforce`.
    /// - [`CyberArmorError::ControlPlaneUnreachable`] when the control plane is
    ///   unreachable and `fail_open` is `false`.
    /// - [`CyberArmorError::HttpError`] on other HTTP failures.
    /// - [`CyberArmorError::SerdeError`] on JSON decode failure.
    pub async fn check_policy(
        &self,
        prompt: &str,
        model: &str,
        provider: &str,
        tenant_id: &str,
    ) -> Result<PolicyDecision, CyberArmorError> {
        let body = json!({
            "agent_id":  self.config.agent_id,
            "prompt":    prompt,
            "model":     model,
            "provider":  provider,
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });

        let path = format!(
            "/policies/{}/evaluate",
            percent_encode(tenant_id)
        );

        let decision = match self.post(&path, &body, None).await {
            Ok(val) => serde_json::from_value::<PolicyDecision>(val)?,
            Err(CyberArmorError::HttpError(e)) if e.is_connect() || e.is_timeout() => {
                return self.handle_control_plane_failure(e).await;
            }
            Err(e) => return Err(e),
        };

        if !decision.is_allowed() {
            match self.config.enforce_mode {
                EnforceMode::Enforce => {
                    return Err(CyberArmorError::PolicyViolation {
                        decision_type: decision.decision_type.to_string(),
                        reason: decision.reason.clone().unwrap_or_default(),
                    });
                }
                EnforceMode::Monitor => {
                    warn!(
                        decision_type = %decision.decision_type,
                        reason = ?decision.reason,
                        "[CyberArmor] Policy DENIED (monitor mode — allowing)"
                    );
                    return Ok(PolicyDecision {
                        allowed: true,
                        ..decision
                    });
                }
            }
        }

        Ok(decision)
    }

    /// Emit an audit event to the configured audit service.
    ///
    /// Failures are non-fatal and are only logged.
    pub async fn emit_audit(&self, event: Value) -> Result<(), CyberArmorError> {
        let audit_url = match &self.config.audit_url {
            Some(u) => u.clone(),
            None => return Ok(()),
        };

        if let Err(e) = self.post("/audit/events", &event, Some(&audit_url)).await {
            error!("[CyberArmor] Audit emission failed: {}", e);
        }

        Ok(())
    }

    /// Build and emit a standardised audit event.
    pub async fn emit_audit_event(
        &self,
        tenant_id: &str,
        event_type: &str,
        payload: Value,
    ) -> Result<(), CyberArmorError> {
        let event = audit::build_event(
            &self.config.agent_id,
            tenant_id,
            event_type,
            payload,
        );
        self.emit_audit(event).await
    }

    /// Return a reference to the current configuration.
    pub fn config(&self) -> &CyberArmorConfig {
        &self.config
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Perform a signed JSON POST request.
    async fn post(
        &self,
        path: &str,
        body: &Value,
        base_url: Option<&str>,
    ) -> Result<Value, CyberArmorError> {
        let target = base_url.unwrap_or(&self.config.url);
        let url    = format!("{}{}", target.trim_end_matches('/'), path);

        let body_bytes = serde_json::to_vec(body)?;
        let signature  = self.sign_request(&body_bytes)?;

        let response = self
            .http
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header("X-CyberArmor-Agent", &self.config.agent_id)
            .header("X-CyberArmor-Sig", signature)
            .header("X-CyberArmor-SDK", SDK_USER_AGENT)
            .body(body_bytes)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(CyberArmorError::UnexpectedStatus {
                status: status.as_u16(),
                body,
            });
        }

        let value: Value = response.json().await?;
        Ok(value)
    }

    /// HMAC-SHA256 sign the request body using the agent secret.
    fn sign_request(&self, body: &[u8]) -> Result<String, CyberArmorError> {
        let mut mac = HmacSha256::new_from_slice(self.config.agent_secret.as_bytes())
            .map_err(|e| CyberArmorError::SigningError(e.to_string()))?;
        mac.update(body);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Handle an unreachable control plane according to the `fail_open` policy.
    async fn handle_control_plane_failure(
        &self,
        error: reqwest::Error,
    ) -> Result<PolicyDecision, CyberArmorError> {
        error!("[CyberArmor] Control plane unreachable: {}", error);

        if self.config.fail_open {
            warn!("[CyberArmor] fail_open=true — allowing request despite control plane failure");
            return Ok(PolicyDecision {
                allowed:        true,
                decision_type:  DecisionType::Allow,
                reason:         Some("Control plane unreachable; fail_open=true".to_string()),
                redacted_prompt: None,
            });
        }

        match self.config.enforce_mode {
            EnforceMode::Enforce => {
                Err(CyberArmorError::ControlPlaneUnreachable { source: error })
            }
            EnforceMode::Monitor => {
                warn!("[CyberArmor] Control plane unreachable (monitor mode — allowing)");
                Ok(PolicyDecision {
                    allowed:        true,
                    decision_type:  DecisionType::Deny,
                    reason:         Some("Control plane unreachable (monitor mode)".to_string()),
                    redacted_prompt: None,
                })
            }
        }
    }
}

/// Percent-encode a path segment (RFC 3986).
fn percent_encode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                // Encode as %XX sequences
                let mut bytes = [0u8; 4];
                let len = c.encode_utf8(&mut bytes).len();
                bytes[..len]
                    .iter()
                    .flat_map(|b| {
                        let hi = char::from_digit(((*b >> 4) & 0xF) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase();
                        let lo = char::from_digit((*b & 0xF) as u32, 16)
                            .unwrap()
                            .to_ascii_uppercase();
                        vec!['%', hi, lo]
                    })
                    .collect::<Vec<char>>()
            }
        })
        .collect()
}
