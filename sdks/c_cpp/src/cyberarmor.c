/*
 * CyberArmor AI Identity Control Plane — C SDK Implementation
 * Copyright (c) 2026 CyberArmor / CyberArmor. All rights reserved.
 *
 * File:    cyberarmor.c
 * Version: 2.0.0
 *
 * Depends on: libcurl
 * Build:      See CMakeLists.txt
 */

#define CYBERARMOR_BUILDING_DLL 1

#include "cyberarmor/cyberarmor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>

#include <curl/curl.h>

/* =========================================================================
 * Internal constants
 * ========================================================================= */
#define CA_DEFAULT_TIMEOUT_MS   5000
#define CA_MAX_RESPONSE_SIZE    (512 * 1024)  /* 512 KB */
#define CA_ERROR_BUF_SIZE       512
#define CA_URL_BUF_SIZE         1024

/* =========================================================================
 * Internal types
 * ========================================================================= */

/* Dynamic response buffer used by libcurl write callback */
typedef struct {
    char*  data;
    size_t size;
    size_t capacity;
} ca_response_buf_t;

/* Full internal client structure */
struct ca_client_s {
    ca_config_t  config;
    CURL*        curl;
    char         error_buf[CA_ERROR_BUF_SIZE];
};

/* =========================================================================
 * Utility — error formatting
 * ========================================================================= */
static void ca_set_error(ca_client_t* client, const char* fmt, ...) {
    if (!client) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(client->error_buf, CA_ERROR_BUF_SIZE, fmt, args);
    va_end(args);
}

/* =========================================================================
 * Utility — lightweight JSON helpers (no external dependency)
 *
 * These helpers extract simple scalar values from a flat or slightly nested
 * JSON string.  They are intentionally minimal; for complex structures the
 * full response is available as raw text.
 * ========================================================================= */

/**
 * ca_json_str — Extract the string value of a JSON key from a flat object.
 * Writes at most out_size-1 bytes (plus NUL) into out.
 * Returns 1 on success, 0 if key not found or value is not a string.
 *
 * Handles only simple string values (no escaped quotes within value).
 */
static int ca_json_str(const char* json, const char* key,
                        char* out, size_t out_size) {
    char needle[256];
    /* Build: "key": */
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char* p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);

    /* Skip whitespace and colon */
    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;

    if (*p != '"') return 0;
    p++; /* skip opening quote */

    size_t i = 0;
    while (*p && *p != '"' && i < out_size - 1) {
        if (*p == '\\' && *(p + 1)) {
            /* Basic escape handling */
            p++;
            switch (*p) {
                case 'n':  out[i++] = '\n'; break;
                case 't':  out[i++] = '\t'; break;
                case 'r':  out[i++] = '\r'; break;
                case '"':  out[i++] = '"';  break;
                case '\\': out[i++] = '\\'; break;
                default:   out[i++] = *p;  break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return 1;
}

/**
 * ca_json_int — Extract an integer value from a JSON key.
 * Returns 1 on success, 0 if not found.
 */
static int ca_json_int(const char* json, const char* key, int* out) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char* p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);

    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;

    /* Handle boolean true/false */
    if (strncmp(p, "true", 4) == 0)  { *out = 1; return 1; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return 1; }

    if (!isdigit((unsigned char)*p) && *p != '-') return 0;
    *out = (int)strtol(p, NULL, 10);
    return 1;
}

/**
 * ca_json_double — Extract a floating-point value from a JSON key.
 * Returns 1 on success, 0 if not found.
 */
static int ca_json_double(const char* json, const char* key, double* out) {
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char* p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);

    while (*p && (isspace((unsigned char)*p) || *p == ':')) p++;
    if (!isdigit((unsigned char)*p) && *p != '-' && *p != '.') return 0;
    *out = strtod(p, NULL);
    return 1;
}

/* =========================================================================
 * Utility — ISO-8601 timestamp
 * ========================================================================= */
static void ca_utc_timestamp(char* buf, size_t sz) {
    time_t now = time(NULL);
    struct tm utc;
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    strftime(buf, sz, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

/* =========================================================================
 * Utility — JSON string escaping
 * ========================================================================= */
static void ca_json_escape(const char* src, char* dst, size_t dst_sz) {
    size_t i = 0;
    while (*src && i + 2 < dst_sz) {
        char c = *src++;
        if (c == '"' || c == '\\') {
            if (i + 3 >= dst_sz) break;
            dst[i++] = '\\';
            dst[i++] = c;
        } else if (c == '\n') {
            if (i + 3 >= dst_sz) break;
            dst[i++] = '\\'; dst[i++] = 'n';
        } else if (c == '\r') {
            if (i + 3 >= dst_sz) break;
            dst[i++] = '\\'; dst[i++] = 'r';
        } else if (c == '\t') {
            if (i + 3 >= dst_sz) break;
            dst[i++] = '\\'; dst[i++] = 't';
        } else {
            dst[i++] = c;
        }
    }
    dst[i] = '\0';
}

/* =========================================================================
 * libcurl write callback
 * ========================================================================= */
static size_t ca_write_callback(char* ptr, size_t size, size_t nmemb,
                                 void* userdata) {
    ca_response_buf_t* buf = (ca_response_buf_t*)userdata;
    size_t incoming = size * nmemb;

    if (buf->size + incoming + 1 > CA_MAX_RESPONSE_SIZE) {
        /* Refuse oversized response */
        return 0;
    }

    if (buf->size + incoming + 1 > buf->capacity) {
        size_t new_cap = buf->capacity * 2 + incoming + 1;
        char*  new_data = (char*)realloc(buf->data, new_cap);
        if (!new_data) return 0;
        buf->data     = new_data;
        buf->capacity = new_cap;
    }

    memcpy(buf->data + buf->size, ptr, incoming);
    buf->size += incoming;
    buf->data[buf->size] = '\0';
    return incoming;
}

/* =========================================================================
 * Internal — perform an HTTP POST with libcurl
 * Returns HTTP status code, or 0 on error.
 * response_buf must be free()'d by caller.
 * ========================================================================= */
static long ca_http_post(ca_client_t* client,
                          const char*  url,
                          const char*  body,
                          char**       response_buf_out,
                          size_t*      response_len_out) {
    ca_response_buf_t rbuf;
    rbuf.data     = (char*)malloc(4096);
    rbuf.size     = 0;
    rbuf.capacity = 4096;
    if (!rbuf.data) {
        ca_set_error(client, "out of memory allocating response buffer");
        return 0;
    }
    rbuf.data[0] = '\0';

    CURL* curl = client->curl;
    curl_easy_reset(curl);

    /* URL */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* POST body */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));

    /* Headers */
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    /* Build Authorization header */
    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr),
             "X-API-Key: %s", client->config.agent_secret);
    headers = curl_slist_append(headers, auth_hdr);

    /* Build X-Agent-ID header */
    char agent_hdr[256];
    snprintf(agent_hdr, sizeof(agent_hdr),
             "X-Agent-ID: %s", client->config.agent_id);
    headers = curl_slist_append(headers, agent_hdr);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* Write callback */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ca_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rbuf);

    /* Timeout */
    long timeout_ms = (client->config.timeout_ms > 0)
                      ? (long)client->config.timeout_ms
                      : (long)CA_DEFAULT_TIMEOUT_MS;
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);

    /* TLS */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (client->config.ca_cert_path[0]) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, client->config.ca_cert_path);
    }

    /* Execute */
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        ca_set_error(client, "curl error: %s", curl_easy_strerror(res));
        free(rbuf.data);
        return 0;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    *response_buf_out = rbuf.data;
    *response_len_out = rbuf.size;
    return http_code;
}

/* =========================================================================
 * Public API — ca_client_create
 * ========================================================================= */
CA_EXPORT ca_client_t* ca_client_create(const ca_config_t* config) {
    if (!config || config->url[0] == '\0') return NULL;

    ca_client_t* client = (ca_client_t*)calloc(1, sizeof(ca_client_t));
    if (!client) return NULL;

    memcpy(&client->config, config, sizeof(ca_config_t));

    /* Default enforce mode */
    if (client->config.enforce_mode[0] == '\0') {
        strncpy(client->config.enforce_mode, "enforce",
                sizeof(client->config.enforce_mode) - 1);
    }

    /* Init curl */
    client->curl = curl_easy_init();
    if (!client->curl) {
        free(client);
        return NULL;
    }

    return client;
}

/* =========================================================================
 * Public API — ca_client_from_env
 * ========================================================================= */
CA_EXPORT ca_client_t* ca_client_from_env(void) {
    ca_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    /* URL */
    const char* url = getenv("CYBERARMOR_URL");
    if (!url || url[0] == '\0') return NULL;  /* Required */
    strncpy(cfg.url, url, sizeof(cfg.url) - 1);

    /* Agent ID — required */
    const char* agent_id = getenv("CYBERARMOR_AGENT_ID");
    if (!agent_id || agent_id[0] == '\0') return NULL;
    strncpy(cfg.agent_id, agent_id, sizeof(cfg.agent_id) - 1);

    /* Agent secret — required */
    const char* agent_secret = getenv("CYBERARMOR_AGENT_SECRET");
    if (!agent_secret || agent_secret[0] == '\0') return NULL;
    strncpy(cfg.agent_secret, agent_secret, sizeof(cfg.agent_secret) - 1);

    /* Enforce mode — optional, default "enforce" */
    const char* mode = getenv("CYBERARMOR_ENFORCE_MODE");
    if (mode && mode[0]) {
        strncpy(cfg.enforce_mode, mode, sizeof(cfg.enforce_mode) - 1);
    } else {
        strncpy(cfg.enforce_mode, "enforce", sizeof(cfg.enforce_mode) - 1);
    }

    /* Fail open — optional, default 0 (fail-closed) */
    const char* fail_open = getenv("CYBERARMOR_FAIL_OPEN");
    cfg.fail_open = (fail_open && strcmp(fail_open, "1") == 0) ? 1 : 0;

    /* Timeout — optional */
    const char* timeout_str = getenv("CYBERARMOR_TIMEOUT_MS");
    if (timeout_str && timeout_str[0]) {
        cfg.timeout_ms = (int)strtol(timeout_str, NULL, 10);
    }

    /* CA cert — optional */
    const char* ca_cert = getenv("CYBERARMOR_CA_CERT");
    if (ca_cert && ca_cert[0]) {
        strncpy(cfg.ca_cert_path, ca_cert, sizeof(cfg.ca_cert_path) - 1);
    }

    return ca_client_create(&cfg);
}

/* =========================================================================
 * Public API — ca_client_destroy
 * ========================================================================= */
CA_EXPORT void ca_client_destroy(ca_client_t* client) {
    if (!client) return;
    if (client->curl) {
        curl_easy_cleanup(client->curl);
        client->curl = NULL;
    }
    free(client);
}

/* =========================================================================
 * Public API — ca_check_policy
 * ========================================================================= */
CA_EXPORT int ca_check_policy(
    ca_client_t*   client,
    const char*    prompt,
    const char*    model,
    const char*    provider,
    const char*    tenant_id,
    ca_decision_t* decision_out)
{
    if (!client || !prompt || !decision_out) return CA_ERR_INVALID_ARGUMENT;

    /* Zero out output */
    memset(decision_out, 0, sizeof(ca_decision_t));

    /* Determine tenant */
    const char* tid = (tenant_id && tenant_id[0]) ? tenant_id : "default";

    /* Build URL: {base}/policies/{tenant_id}/evaluate */
    char url[CA_URL_BUF_SIZE];
    snprintf(url, sizeof(url), "%s/policies/%s/evaluate",
             client->config.url, tid);

    /* Escape prompt for JSON */
    size_t prompt_len  = strlen(prompt);
    size_t escaped_sz  = prompt_len * 2 + 4;
    char*  escaped_prompt = (char*)malloc(escaped_sz);
    if (!escaped_prompt) {
        ca_set_error(client, "out of memory");
        if (client->config.fail_open) { decision_out->allowed = 1; return CA_OK; }
        return CA_ERR_INTERNAL;
    }
    ca_json_escape(prompt, escaped_prompt, escaped_sz);

    /* Build JSON body */
    size_t body_sz = escaped_sz + 1024;
    char*  body    = (char*)malloc(body_sz);
    if (!body) {
        free(escaped_prompt);
        ca_set_error(client, "out of memory");
        if (client->config.fail_open) { decision_out->allowed = 1; return CA_OK; }
        return CA_ERR_INTERNAL;
    }

    snprintf(body, body_sz,
        "{"
        "\"agent_id\":\"%s\","
        "\"tenant_id\":\"%s\","
        "\"prompt\":\"%s\","
        "\"model\":\"%s\","
        "\"provider\":\"%s\","
        "\"enforce_mode\":\"%s\""
        "}",
        client->config.agent_id,
        tid,
        escaped_prompt,
        model    ? model    : "",
        provider ? provider : "",
        client->config.enforce_mode
    );
    free(escaped_prompt);

    /* HTTP POST */
    char*  resp_buf  = NULL;
    size_t resp_len  = 0;
    long   http_code = ca_http_post(client, url, body, &resp_buf, &resp_len);
    free(body);

    if (http_code == 0) {
        /* Network error */
        if (client->config.fail_open) {
            decision_out->allowed = 1;
            strncpy(decision_out->decision_type, "ALLOW",
                    sizeof(decision_out->decision_type) - 1);
            strncpy(decision_out->reason,
                    "fail-open: network error reaching policy service",
                    sizeof(decision_out->reason) - 1);
            return CA_OK;
        }
        decision_out->allowed = 0;
        strncpy(decision_out->decision_type, "DENY",
                sizeof(decision_out->decision_type) - 1);
        strncpy(decision_out->reason,
                "fail-closed: network error reaching policy service",
                sizeof(decision_out->reason) - 1);
        return CA_ERR_NETWORK;
    }

    if (http_code == 401 || http_code == 403) {
        if (resp_buf) free(resp_buf);
        ca_set_error(client, "HTTP %ld: unauthorized", http_code);
        decision_out->allowed = 0;
        strncpy(decision_out->decision_type, "DENY",
                sizeof(decision_out->decision_type) - 1);
        strncpy(decision_out->reason, "unauthorized: invalid agent credentials",
                sizeof(decision_out->reason) - 1);
        return CA_ERR_UNAUTHORIZED;
    }

    if (!resp_buf) {
        ca_set_error(client, "empty response from policy service");
        if (client->config.fail_open) { decision_out->allowed = 1; return CA_OK; }
        decision_out->allowed = 0;
        return CA_ERR_PARSE;
    }

    /* Parse JSON response */
    int allowed_val = 1;
    ca_json_int(resp_buf, "allowed", &allowed_val);
    decision_out->allowed = allowed_val;

    ca_json_str(resp_buf, "decision_type",
                decision_out->decision_type,
                sizeof(decision_out->decision_type));
    if (decision_out->decision_type[0] == '\0') {
        strncpy(decision_out->decision_type,
                allowed_val ? "ALLOW" : "DENY",
                sizeof(decision_out->decision_type) - 1);
    }

    ca_json_str(resp_buf, "reason",
                decision_out->reason, sizeof(decision_out->reason));

    ca_json_str(resp_buf, "redacted_prompt",
                decision_out->redacted_prompt,
                sizeof(decision_out->redacted_prompt));

    ca_json_double(resp_buf, "risk_score", &decision_out->risk_score);

    {
        int lms = 0;
        if (ca_json_int(resp_buf, "latency_ms", &lms))
            decision_out->latency_ms = (long)lms;
    }

    ca_json_str(resp_buf, "policy_id",
                decision_out->policy_id, sizeof(decision_out->policy_id));

    free(resp_buf);

    if (http_code >= 500) {
        ca_set_error(client, "policy service returned HTTP %ld", http_code);
        if (client->config.fail_open) return CA_OK;
        return CA_ERR_NETWORK;
    }

    return decision_out->allowed ? CA_OK : CA_ERR_POLICY_DENIED;
}

/* =========================================================================
 * Public API — ca_emit_audit
 * ========================================================================= */
CA_EXPORT int ca_emit_audit(
    ca_client_t*            client,
    const ca_audit_event_t* event)
{
    if (!client || !event) return CA_ERR_INVALID_ARGUMENT;

    /* Build audit service URL: {base}/events */
    char url[CA_URL_BUF_SIZE];
    snprintf(url, sizeof(url), "%s/events", client->config.url);

    /* Timestamp — fill if empty */
    char ts[32];
    if (event->timestamp[0]) {
        strncpy(ts, event->timestamp, sizeof(ts) - 1);
        ts[sizeof(ts) - 1] = '\0';
    } else {
        ca_utc_timestamp(ts, sizeof(ts));
    }

    /* Escape metadata_json: use as-is if non-empty and starts with '{',
       otherwise use "{}" */
    const char* meta = (event->metadata_json[0] == '{')
                       ? event->metadata_json
                       : "{}";

    /* Build JSON body — all fields escaped inline */
    #define CA_AUDIT_BODY_SZ (8192)
    char* body = (char*)malloc(CA_AUDIT_BODY_SZ);
    if (!body) {
        ca_set_error(client, "out of memory");
        return CA_ERR_INTERNAL;
    }

    /* Escape only the potentially user-supplied fields */
    char esc_action[256]   = {0};
    char esc_model[256]    = {0};
    char esc_meta[2200]    = {0};

    ca_json_escape(event->action,        esc_action, sizeof(esc_action));
    ca_json_escape(event->model,         esc_model,  sizeof(esc_model));
    ca_json_escape(meta,                 esc_meta,   sizeof(esc_meta));

    snprintf(body, CA_AUDIT_BODY_SZ,
        "{"
        "\"event_id\":\"%s\","
        "\"trace_id\":\"%s\","
        "\"span_id\":\"%s\","
        "\"agent_id\":\"%s\","
        "\"human_id\":\"%s\","
        "\"action\":\"%s\","
        "\"model\":\"%s\","
        "\"provider\":\"%s\","
        "\"tenant_id\":\"%s\","
        "\"timestamp\":\"%s\","
        "\"risk_score\":%.4f,"
        "\"blocked\":%s,"
        "\"prompt_hash\":\"%s\","
        "\"response_hash\":\"%s\","
        "\"metadata\":%s"
        "}",
        event->event_id,
        event->trace_id,
        event->span_id,
        event->agent_id,
        event->human_id,
        esc_action,
        esc_model,
        event->provider,
        event->tenant_id,
        ts,
        event->risk_score,
        event->blocked ? "true" : "false",
        event->prompt_hash,
        event->response_hash,
        esc_meta
    );

    char*  resp_buf  = NULL;
    size_t resp_len  = 0;
    long   http_code = ca_http_post(client, url, body, &resp_buf, &resp_len);
    free(body);
    if (resp_buf) free(resp_buf);

    if (http_code == 0) {
        /* Network error — audit failures are non-fatal by default */
        ca_set_error(client, "audit emit: network error (event may be lost)");
        return CA_ERR_NETWORK;
    }

    if (http_code == 401 || http_code == 403) {
        ca_set_error(client, "audit emit: unauthorized (HTTP %ld)", http_code);
        return CA_ERR_UNAUTHORIZED;
    }

    if (http_code < 200 || http_code >= 300) {
        ca_set_error(client, "audit emit: unexpected HTTP %ld", http_code);
        return CA_ERR_NETWORK;
    }

    return CA_OK;
}

/* =========================================================================
 * Public API — ca_version / ca_last_error
 * ========================================================================= */
CA_EXPORT const char* ca_version(void) {
    return CA_VERSION_STRING;
}

CA_EXPORT const char* ca_last_error(ca_client_t* client) {
    if (!client) return "invalid client handle (NULL)";
    if (client->error_buf[0] == '\0') return "no error";
    return client->error_buf;
}
