/**
 * CyberArmor RASP — C/C++ Runtime Application Self-Protection
 * LD_PRELOAD-based interception for AI/LLM API calls.
 *
 * Usage: LD_PRELOAD=libcyberarmor_rasp.so ./your_application
 */

#ifndef CYBERARMOR_RASP_H
#define CYBERARMOR_RASP_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Configuration ──────────────────────────────────────── */

typedef enum {
    CYBERARMOR_MODE_MONITOR = 0,
    CYBERARMOR_MODE_BLOCK   = 1,
} cyberarmor_mode_t;

typedef struct {
    const char      *control_plane_url;
    const char      *api_key;
    const char      *tenant_id;
    cyberarmor_mode_t mode;
    bool             dlp_enabled;
    bool             prompt_injection_enabled;
} cyberarmor_config_t;

/* ── Inspection Result ──────────────────────────────────── */

typedef struct {
    bool        allowed;
    const char *reason;    /* NULL if allowed, static string if blocked */
} cyberarmor_result_t;

/* ── Lifecycle ──────────────────────────────────────────── */

/**
 * Initialize the RASP library.
 * If config is NULL, reads from environment variables:
 *   CYBERARMOR_URL, CYBERARMOR_API_KEY, CYBERARMOR_TENANT, CYBERARMOR_MODE
 * Returns 0 on success, -1 on failure.
 */
int cyberarmor_init(const cyberarmor_config_t *config);

/**
 * Shut down the RASP library and flush pending events.
 */
void cyberarmor_shutdown(void);

/* ── Inspection ─────────────────────────────────────────── */

/**
 * Check if a hostname is a known AI/LLM API endpoint.
 */
bool cyberarmor_is_ai_endpoint(const char *hostname);

/**
 * Inspect an HTTP request body for AI security threats.
 * @param url  The full URL (e.g., "https://api.openai.com/v1/chat/completions")
 * @param body The request body (may be NULL)
 * @param body_len Length of body
 * @return Inspection result (stack-allocated, no need to free)
 */
cyberarmor_result_t cyberarmor_inspect(const char *url, const char *body, size_t body_len);

/* ── Callback Registration ──────────────────────────────── */

typedef void (*cyberarmor_event_cb)(const char *event_type, const char *url,
                                    const char *detail, void *userdata);

/**
 * Register a callback for security events.
 */
void cyberarmor_on_event(cyberarmor_event_cb callback, void *userdata);

/* ── Statistics ─────────────────────────────────────────── */

typedef struct {
    unsigned long ai_requests;
    unsigned long prompt_injections;
    unsigned long dlp_findings;
    unsigned long blocked;
} cyberarmor_stats_t;

/**
 * Get current statistics.
 */
cyberarmor_stats_t cyberarmor_get_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* CYBERARMOR_RASP_H */
