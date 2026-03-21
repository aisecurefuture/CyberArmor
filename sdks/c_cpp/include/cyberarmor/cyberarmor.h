/*
 * CyberArmor AI Identity Control Plane — C/C++ SDK
 * Copyright (c) 2026 CyberArmor / CyberArmor. All rights reserved.
 *
 * Header: cyberarmor.h
 * Version: 2.0.0
 *
 * Provides:
 *   - C API for policy evaluation and audit emission
 *   - C++ RAII wrapper class CyberArmorClient
 *
 * Link against: -lcyberarmor -lcurl
 */

#ifndef CYBERARMOR_H
#define CYBERARMOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* -------------------------------------------------------------------------
 * Platform export macro
 * ------------------------------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
#  ifdef CYBERARMOR_BUILDING_DLL
#    define CA_EXPORT __declspec(dllexport)
#  else
#    define CA_EXPORT __declspec(dllimport)
#  endif
#else
#  if defined(__GNUC__) && __GNUC__ >= 4
#    define CA_EXPORT __attribute__((visibility("default")))
#  else
#    define CA_EXPORT
#  endif
#endif

/* -------------------------------------------------------------------------
 * Version
 * ------------------------------------------------------------------------- */
#define CA_VERSION_MAJOR  2
#define CA_VERSION_MINOR  0
#define CA_VERSION_PATCH  0
#define CA_VERSION_STRING "2.0.0"

/* -------------------------------------------------------------------------
 * Decision type constants
 * ------------------------------------------------------------------------- */
#define CA_DECISION_ALLOW          0
#define CA_DECISION_DENY           1
#define CA_DECISION_REDACT         2
#define CA_DECISION_WARN           3
#define CA_DECISION_REQUIRE_MFA    4

/* Return codes */
#define CA_OK                      0
#define CA_ERR_INVALID_ARGUMENT   -1
#define CA_ERR_NETWORK            -2
#define CA_ERR_PARSE              -3
#define CA_ERR_UNAUTHORIZED       -4
#define CA_ERR_POLICY_DENIED      -5
#define CA_ERR_TIMEOUT            -6
#define CA_ERR_INTERNAL           -9

/* -------------------------------------------------------------------------
 * Configuration struct
 * ca_config_t — passed to ca_client_create()
 * ------------------------------------------------------------------------- */
typedef struct ca_config_s {
    char url[512];           /* CyberArmor control-plane base URL,
                                e.g. "https://ca.example.com" */
    char agent_id[128];      /* Registered AI agent identifier */
    char agent_secret[256];  /* Agent shared secret / API key */
    char enforce_mode[32];   /* "enforce" | "audit" | "permissive" */
    int  fail_open;          /* 1 = allow on network/timeout error;
                                0 = deny on error (fail-closed, default) */
    int  timeout_ms;         /* HTTP timeout in milliseconds (0 = default 5000) */
    int  max_retries;        /* Number of retries on transient error (0 = no retry) */
    char ca_cert_path[512];  /* Optional: path to CA certificate bundle */
    char _reserved[256];     /* Reserved for future use — zero-initialize */
} ca_config_t;

/* -------------------------------------------------------------------------
 * Policy decision struct
 * ca_decision_t — filled in by ca_check_policy()
 * ------------------------------------------------------------------------- */
typedef struct ca_decision_s {
    int  allowed;                  /* 1 = allowed, 0 = blocked */
    char decision_type[64];        /* "ALLOW", "DENY", "REDACT", "WARN", … */
    char reason[512];              /* Human-readable policy reason */
    char redacted_prompt[4096];    /* Prompt after PII/secret redaction
                                      (may be empty if no redaction) */
    double risk_score;             /* 0.0 – 1.0 */
    long   latency_ms;             /* Round-trip latency of policy call */
    char   policy_id[128];         /* ID of the matched policy rule */
    char   _reserved[128];
} ca_decision_t;

/* -------------------------------------------------------------------------
 * Audit event struct
 * ca_audit_event_t — passed to ca_emit_audit()
 * ------------------------------------------------------------------------- */
typedef struct ca_audit_event_s {
    char   event_id[64];       /* UUIDv4, or leave empty to auto-generate */
    char   trace_id[64];       /* Distributed trace ID */
    char   span_id[32];        /* Span within the trace */
    char   agent_id[128];      /* The agent performing the action */
    char   human_id[128];      /* Upstream human user (may be empty) */
    char   action[128];        /* "ai.inference", "ai.embed", "ai.image", … */
    char   model[128];         /* Model identifier, e.g. "gpt-4o" */
    char   provider[64];       /* "openai", "anthropic", "google", … */
    char   tenant_id[128];     /* Tenant/organisation identifier */
    char   timestamp[32];      /* ISO-8601, e.g. "2026-03-05T12:00:00Z"
                                  — filled automatically if empty */
    double risk_score;         /* 0.0 – 1.0 */
    int    blocked;            /* 1 = request was blocked by policy */
    char   prompt_hash[128];   /* SHA-256 hex of original prompt */
    char   response_hash[128]; /* SHA-256 hex of model response */
    char   hmac_signature[128];/* HMAC-SHA256 computed by SDK */
    char   metadata_json[2048];/* Arbitrary extra metadata as JSON object string */
    char   _reserved[128];
} ca_audit_event_t;

/* -------------------------------------------------------------------------
 * Opaque client handle
 * ------------------------------------------------------------------------- */
typedef struct ca_client_s ca_client_t;

/* =========================================================================
 * C API — Function Declarations
 * ========================================================================= */

/**
 * ca_client_create — Create a client from an explicit configuration struct.
 *
 * @param config  Pointer to a fully populated ca_config_t.
 * @return        Opaque client handle, or NULL on allocation/init failure.
 *                Caller must call ca_client_destroy() when done.
 */
CA_EXPORT ca_client_t* ca_client_create(const ca_config_t* config);

/**
 * ca_client_from_env — Create a client reading configuration from environment
 * variables:
 *   CYBERARMOR_URL          (fallback: CYBERARMOR_URL)
 *   CYBERARMOR_AGENT_ID
 *   CYBERARMOR_AGENT_SECRET
 *   CYBERARMOR_ENFORCE_MODE (default: "enforce")
 *   CYBERARMOR_FAIL_OPEN    ("1" = fail-open, default fail-closed)
 *   CYBERARMOR_TIMEOUT_MS   (default: 5000)
 *   CYBERARMOR_CA_CERT      (optional path to CA cert bundle)
 *
 * @return  Opaque client handle, or NULL if required env vars are missing.
 */
CA_EXPORT ca_client_t* ca_client_from_env(void);

/**
 * ca_client_destroy — Release all resources held by a client.
 * Safe to call with NULL.
 */
CA_EXPORT void ca_client_destroy(ca_client_t* client);

/**
 * ca_check_policy — Evaluate a prompt against the tenant policy engine.
 *
 * Sends an HTTP POST to {url}/policies/{tenant_id}/evaluate.
 * Populates *decision_out with the policy decision.
 *
 * @param client       Valid client handle.
 * @param prompt       The AI prompt / input text (UTF-8, null-terminated).
 * @param model        Target model name (e.g. "gpt-4o"), or NULL.
 * @param provider     Provider name (e.g. "openai"), or NULL.
 * @param tenant_id    Tenant identifier string, or NULL to use agent default.
 * @param decision_out Caller-allocated ca_decision_t that will be filled.
 *
 * @return  CA_OK on success (check decision_out->allowed for allow/deny).
 *          On network/parse error: CA_ERR_NETWORK or CA_ERR_PARSE.
 *          If fail_open=0 and an error occurs, decision_out->allowed is set 0.
 *          If fail_open=1 and an error occurs, decision_out->allowed is set 1.
 */
CA_EXPORT int ca_check_policy(
    ca_client_t*   client,
    const char*    prompt,
    const char*    model,
    const char*    provider,
    const char*    tenant_id,
    ca_decision_t* decision_out
);

/**
 * ca_emit_audit — Emit an audit event to the Audit Graph service.
 *
 * Sends an HTTP POST to {url}/events.
 * The SDK will auto-fill timestamp and hmac_signature if left empty.
 *
 * @param client  Valid client handle.
 * @param event   Pointer to a populated ca_audit_event_t.
 *
 * @return  CA_OK on success, negative error code on failure.
 */
CA_EXPORT int ca_emit_audit(
    ca_client_t*           client,
    const ca_audit_event_t* event
);

/**
 * ca_version — Return the SDK version string.
 * @return  Pointer to static string, e.g. "2.0.0". Never NULL.
 */
CA_EXPORT const char* ca_version(void);

/**
 * ca_last_error — Return a human-readable description of the last error
 * that occurred on the given client. The string is stored per-client and
 * is overwritten on the next API call. Thread-safe per client handle.
 *
 * @param client  Client handle (may be NULL, returns generic message).
 * @return        Null-terminated error string. Never NULL.
 */
CA_EXPORT const char* ca_last_error(ca_client_t* client);

#ifdef __cplusplus
} /* extern "C" */
#endif


/* =========================================================================
 * C++ Wrapper — CyberArmorClient (header-only RAII class)
 * ========================================================================= */
#ifdef __cplusplus

#include <string>
#include <stdexcept>

namespace cyberarmor {

/**
 * PolicyDecision — value type returned by CyberArmorClient::checkPolicy()
 */
struct PolicyDecision {
    bool        allowed;
    std::string decisionType;
    std::string reason;
    std::string redactedPrompt;
    double      riskScore;
    long        latencyMs;
    std::string policyId;

    explicit PolicyDecision(const ca_decision_t& d)
        : allowed(d.allowed != 0)
        , decisionType(d.decision_type)
        , reason(d.reason)
        , redactedPrompt(d.redacted_prompt)
        , riskScore(d.risk_score)
        , latencyMs(d.latency_ms)
        , policyId(d.policy_id)
    {}
};

/**
 * CyberArmorClient — RAII C++ wrapper around the C API.
 *
 * Usage (from environment):
 *   cyberarmor::CyberArmorClient client;          // reads env vars
 *   auto decision = client.checkPolicy(prompt, "gpt-4o", "openai", tenant);
 *   if (!decision.allowed) { ... }
 *
 * Usage (explicit config):
 *   ca_config_t cfg{};
 *   std::strncpy(cfg.url, "https://ca.example.com", sizeof(cfg.url));
 *   std::strncpy(cfg.agent_id, "agt-abc123", sizeof(cfg.agent_id));
 *   std::strncpy(cfg.agent_secret, "secret", sizeof(cfg.agent_secret));
 *   cyberarmor::CyberArmorClient client(cfg);
 */
class CyberArmorClient {
public:
    /**
     * Construct from environment variables.
     * Throws std::runtime_error if required env vars are missing.
     */
    CyberArmorClient()
        : handle_(ca_client_from_env())
    {
        if (!handle_) {
            throw std::runtime_error(
                std::string("CyberArmorClient: failed to initialise from environment. ") +
                "Ensure CYBERARMOR_URL, CYBERARMOR_AGENT_ID and "
                "CYBERARMOR_AGENT_SECRET are set."
            );
        }
    }

    /**
     * Construct from an explicit ca_config_t.
     * Throws std::runtime_error on failure.
     */
    explicit CyberArmorClient(const ca_config_t& config)
        : handle_(ca_client_create(&config))
    {
        if (!handle_) {
            throw std::runtime_error(
                "CyberArmorClient: failed to create client from config."
            );
        }
    }

    /* Non-copyable */
    CyberArmorClient(const CyberArmorClient&)            = delete;
    CyberArmorClient& operator=(const CyberArmorClient&) = delete;

    /* Movable */
    CyberArmorClient(CyberArmorClient&& other) noexcept
        : handle_(other.handle_)
    {
        other.handle_ = nullptr;
    }
    CyberArmorClient& operator=(CyberArmorClient&& other) noexcept {
        if (this != &other) {
            ca_client_destroy(handle_);
            handle_       = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~CyberArmorClient() {
        ca_client_destroy(handle_);
    }

    /**
     * checkPolicy — Evaluate a prompt against the tenant policy.
     *
     * @param prompt     Input prompt string.
     * @param model      Target model name (e.g. "gpt-4o"), empty string for none.
     * @param provider   Provider name (e.g. "openai"), empty string for none.
     * @param tenantId   Tenant identifier, empty string to use agent default.
     * @return           PolicyDecision value object.
     * @throws           std::runtime_error on hard error (network, etc.)
     *                   unless fail_open is set, in which case returns an
     *                   allow decision with a warning in reason.
     */
    PolicyDecision checkPolicy(
        const std::string& prompt,
        const std::string& model      = "",
        const std::string& provider   = "",
        const std::string& tenantId   = ""
    ) {
        ca_decision_t d{};
        int rc = ca_check_policy(
            handle_,
            prompt.c_str(),
            model.empty()    ? nullptr : model.c_str(),
            provider.empty() ? nullptr : provider.c_str(),
            tenantId.empty() ? nullptr : tenantId.c_str(),
            &d
        );
        if (rc != CA_OK && rc != CA_ERR_POLICY_DENIED) {
            throw std::runtime_error(
                std::string("CyberArmorClient::checkPolicy failed: ") +
                ca_last_error(handle_)
            );
        }
        return PolicyDecision(d);
    }

    /**
     * emitAudit — Emit an audit event.
     *
     * @param event  Populated audit event struct.
     * @return       true on success.
     * @throws       std::runtime_error on network error.
     */
    bool emitAudit(const ca_audit_event_t& event) {
        int rc = ca_emit_audit(handle_, &event);
        if (rc != CA_OK) {
            throw std::runtime_error(
                std::string("CyberArmorClient::emitAudit failed: ") +
                ca_last_error(handle_)
            );
        }
        return true;
    }

    /**
     * version — Return the SDK version string.
     */
    static std::string version() {
        return std::string(ca_version());
    }

    /**
     * lastError — Return a description of the most recent error.
     */
    std::string lastError() const {
        return std::string(ca_last_error(handle_));
    }

    /**
     * rawHandle — Access the underlying C handle (advanced use).
     */
    ca_client_t* rawHandle() noexcept { return handle_; }

private:
    ca_client_t* handle_;
};

} /* namespace cyberarmor */

#endif /* __cplusplus */

#endif /* CYBERARMOR_H */
