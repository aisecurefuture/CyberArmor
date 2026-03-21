// cyberarmor-sdk/src/error.rs
//
// Unified error type for the CyberArmor SDK.

use thiserror::Error;

/// All errors that can be returned by the CyberArmor SDK.
#[derive(Debug, Error)]
pub enum CyberArmorError {
    /// The policy engine denied the request.
    ///
    /// Only raised when the client is in `enforce` mode.
    #[error("CyberArmor policy violation [{decision_type}]: {reason}")]
    PolicyViolation {
        /// The decision type returned by the policy engine (e.g. `"DENY"`, `"QUARANTINE"`).
        decision_type: String,
        /// Human-readable explanation from the policy engine.
        reason: String,
    },

    /// The control plane was unreachable and `fail_open` is `false`.
    #[error("CyberArmor control plane unreachable (fail_open=false): {source}")]
    ControlPlaneUnreachable {
        /// Underlying transport error.
        #[source]
        source: reqwest::Error,
    },

    /// An HTTP request to the control plane or audit service failed.
    #[error("CyberArmor HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// JSON serialisation or deserialisation failed.
    #[error("CyberArmor JSON error: {0}")]
    SerdeError(#[from] serde_json::Error),

    /// The HTTP response contained an unexpected status code.
    #[error("CyberArmor unexpected HTTP status {status}: {body}")]
    UnexpectedStatus {
        /// HTTP status code.
        status: u16,
        /// Response body text.
        body: String,
    },

    /// HMAC signing failed (should never happen in practice).
    #[error("CyberArmor signing error: {0}")]
    SigningError(String),

    /// The SDK configuration is invalid.
    #[error("CyberArmor configuration error: {0}")]
    ConfigError(String),
}
