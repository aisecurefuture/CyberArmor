// cyberarmor-sdk/src/config.rs
//
// Configuration loaded from environment variables with optional constructor
// overrides.

use std::env;

/// SDK configuration.
///
/// All fields are read from environment variables when [`CyberArmorConfig::from_env`]
/// is called.  Individual fields can be overridden programmatically via the
/// builder methods or by constructing the struct directly.
///
/// | Field         | Primary env var         | Default   |
/// |---------------|-------------------------|-----------|
/// | url           | `CYBERARMOR_URL`        | —         |
/// | agent_id      | `CYBERARMOR_AGENT_ID`   | —         |
/// | agent_secret  | `CYBERARMOR_AGENT_SECRET` | —                    | —         |
/// | enforce_mode  | `CYBERARMOR_ENFORCE_MODE` | —                    | `enforce` |
/// | fail_open     | `CYBERARMOR_FAIL_OPEN`  | —                      | `false`   |
/// | audit_url     | `CYBERARMOR_AUDIT_URL`  | —                      | `None`    |
#[derive(Debug, Clone)]
pub struct CyberArmorConfig {
    /// Base URL of the Agent Identity Service (no trailing slash).
    pub url: String,

    /// SDK agent identifier, registered in the control plane.
    pub agent_id: String,

    /// Shared HMAC secret used to sign outbound requests.
    pub agent_secret: String,

    /// `"enforce"` — raise an error on DENY decisions.
    /// `"monitor"` — log the decision but allow the request.
    pub enforce_mode: EnforceMode,

    /// When `true`, allow requests if the control plane is unreachable.
    pub fail_open: bool,

    /// Optional base URL of the audit service.
    pub audit_url: Option<String>,
}

/// How the SDK reacts to a DENY decision from the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforceMode {
    /// Raise [`crate::CyberArmorError::PolicyViolation`] on DENY.
    Enforce,
    /// Log the DENY decision and allow the request to proceed.
    Monitor,
}

impl EnforceMode {
    /// Parse an `EnforceMode` from a string slice.  Unrecognised values default
    /// to [`EnforceMode::Enforce`].
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "monitor" => Self::Monitor,
            _ => Self::Enforce,
        }
    }
}

impl CyberArmorConfig {
    /// Build a configuration from environment variables.
    ///
    /// # Panics
    ///
    /// Panics if `CYBERARMOR_URL`, `CYBERARMOR_AGENT_ID`, or
    /// `CYBERARMOR_AGENT_SECRET` are not set.
    pub fn from_env() -> Self {
        let url = env::var("CYBERARMOR_URL")
            .expect("CYBERARMOR_URL must be set");

        let agent_id = env::var("CYBERARMOR_AGENT_ID")
            .expect("CYBERARMOR_AGENT_ID must be set");

        let agent_secret = env::var("CYBERARMOR_AGENT_SECRET")
            .expect("CYBERARMOR_AGENT_SECRET must be set");

        let enforce_mode = EnforceMode::from_str(
            &env::var("CYBERARMOR_ENFORCE_MODE").unwrap_or_else(|_| "enforce".to_string()),
        );

        let fail_open = env::var("CYBERARMOR_FAIL_OPEN")
            .unwrap_or_else(|_| "false".to_string())
            .to_ascii_lowercase()
            == "true";

        let audit_url = env::var("CYBERARMOR_AUDIT_URL").ok();

        Self {
            url: url.trim_end_matches('/').to_string(),
            agent_id,
            agent_secret,
            enforce_mode,
            fail_open,
            audit_url,
        }
    }

    /// Override the base URL.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into().trim_end_matches('/').to_string();
        self
    }

    /// Override the agent ID.
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = agent_id.into();
        self
    }

    /// Override the agent secret.
    pub fn with_agent_secret(mut self, secret: impl Into<String>) -> Self {
        self.agent_secret = secret.into();
        self
    }

    /// Override enforce mode.
    pub fn with_enforce_mode(mut self, mode: EnforceMode) -> Self {
        self.enforce_mode = mode;
        self
    }

    /// Override fail-open behaviour.
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// Override audit URL.
    pub fn with_audit_url(mut self, url: impl Into<String>) -> Self {
        self.audit_url = Some(url.into().trim_end_matches('/').to_string());
        self
    }
}
