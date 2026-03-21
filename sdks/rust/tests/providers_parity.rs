use std::sync::Arc;

use cyberarmor_sdk::client::CyberArmorClient;
use cyberarmor_sdk::config::{CyberArmorConfig, EnforceMode};
use cyberarmor_sdk::providers;

fn test_client() -> Arc<CyberArmorClient> {
    Arc::new(CyberArmorClient::new(CyberArmorConfig {
        url: "http://localhost:8000".to_string(),
        agent_id: "agt_test".to_string(),
        agent_secret: "secret".to_string(),
        enforce_mode: EnforceMode::Enforce,
        fail_open: true,
        audit_url: None,
    }))
}

#[test]
fn provider_wrapper_defaults_have_expected_ids_and_urls() {
    let c = test_client();

    let an = providers::anthropic::new(c.clone(), "k", "tenant");
    assert_eq!(an.provider_id(), "anthropic");
    assert!(an.base_url().contains("api.anthropic.com"));

    let g = providers::google::new(c.clone(), "k", "tenant");
    assert_eq!(g.provider_id(), "google");
    assert!(g.base_url().contains("generativelanguage.googleapis.com"));

    let a = providers::amazon::new(c.clone(), "k", "tenant");
    assert_eq!(a.provider_id(), "amazon");
    assert!(a.base_url().contains("bedrock-runtime"));

    let m = providers::microsoft::new(c.clone(), "k", "tenant");
    assert_eq!(m.provider_id(), "microsoft");
    assert!(m.base_url().contains("openai.azure.com"));

    let x = providers::xai::new(c.clone(), "k", "tenant");
    assert_eq!(x.provider_id(), "xai");
    assert!(x.base_url().contains("x.ai"));

    let meta = providers::meta::new(c.clone(), "k", "tenant");
    assert_eq!(meta.provider_id(), "meta");
    assert!(meta.base_url().contains("together.xyz"));

    let p = providers::perplexity::new(c, "k", "tenant");
    assert_eq!(p.provider_id(), "perplexity");
    assert!(p.base_url().contains("perplexity.ai"));
}
