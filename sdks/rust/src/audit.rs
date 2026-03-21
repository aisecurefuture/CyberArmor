// cyberarmor-sdk/src/audit.rs
//
// Audit event construction helpers.

use chrono::Utc;
use serde_json::{json, Value};

pub(crate) const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const SDK_LANG: &str = "rust";

/// Build a standardised audit event `Value` ready to POST to the audit service.
pub fn build_event(
    agent_id: &str,
    tenant_id: &str,
    event_type: &str,
    payload: Value,
) -> Value {
    json!({
        "agent_id":    agent_id,
        "tenant_id":   tenant_id,
        "event_type":  event_type,
        "timestamp":   Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "sdk_version": SDK_VERSION,
        "sdk_lang":    SDK_LANG,
        "payload":     payload,
    })
}
