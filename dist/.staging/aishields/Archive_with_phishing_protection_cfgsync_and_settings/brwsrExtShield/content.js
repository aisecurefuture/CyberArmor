if (window.__aishields_loaded) {
    console.warn("[AiShields] content.js already loaded, skipping duplicate init");
} else {
    window.__aishields_loaded = true;
    console.log("[AiShields] content.js loaded");

    // Config is stored in chrome.storage.sync and managed by options.js/background.js.
    // Keep defaults aligned with background.js DEFAULT_CONFIG.
    const DEFAULTS = {
        tenantId: "demo",
        telemetryEnabled: true,
        redactPIIEnabled: true,
    };
    let CFG = { ...DEFAULTS };

    // A stable, pseudonymous user identifier for telemetry.
    // Stored in chrome.storage.local so it persists across sessions but stays device-scoped.
    async function ensureUserId() {
        try {
            const existing = await new Promise((resolve) => {
                chrome.storage.local.get({ userId: null }, (res) => resolve(res.userId));
            });
            if (existing) return existing;
            const generated = (globalThis.crypto && crypto.randomUUID)
                ? crypto.randomUUID()
                : `uid_${Math.random().toString(16).slice(2)}_${Date.now()}`;
            await new Promise((resolve) => chrome.storage.local.set({ userId: generated }, () => resolve(true)));
            return generated;
        } catch (e) {
            return null;
        }
    }

    async function loadConfig() {
        try {
            chrome.storage.sync.get(DEFAULTS, async (cfg) => {
                CFG = { ...CFG, ...cfg };
                // Make sure we always have a user id available.
                CFG.userId = await ensureUserId();
            });
        } catch (e) {
            // storage might be unavailable in some contexts; fall back to defaults
        }
    }

    // Initial load
    loadConfig();

    // Live updates when options change
    try {
        chrome.storage.onChanged.addListener((changes, areaName) => {
            if (areaName !== "sync") return;
            for (const [k, v] of Object.entries(changes)) {
                CFG[k] = v?.newValue;
            }
        });
    } catch (e) {
        // ignore
    }


    function sendTelemetry(eventType, payload) {
        if (CFG.telemetryEnabled === false) {
            return;
        }
        const body = {
            tenant_id: CFG.tenantId || DEFAULTS.tenantId,
            user_id: CFG.userId || null,
            event_type: eventType,
            payload: payload || {},
            source: "browser_extension",
            occurred_at: new Date().toISOString()
        };
        try {
            chrome.runtime.sendMessage({ type: "telemetry", body });
        } catch (err) {
            console.warn("telemetry send failed", err);
        }
    }

function redactPII(text) {
    if (!text) {
        return text;
    }
    const patterns = [
        ["SSN", /\b\d{3}-\d{2}-\d{4}\b/g],
        ["Phone-Number", /\b\d{10}\b/g],
        ["Email", /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi],
        ["ZIP-Code", /\b\d{5}(?:-\d{4})?\b/g],
        ["Bank-Account|SSN", /\b\d{9}\b/g],
        ["Credit-Card-Number", /\b(?:\d{4}[-\s]?){3}\d{4}\b/g],
        ["Drivers-License", /\b[A-Z]{1,2}\d{4,8}\b/g],
        ["Drivers-License", /\b(?:[A-Za-z]{1}\d{3})[-\d{4}]{2}\b/g],
        ["IBAN", /\b[A-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{14}\b/g]
    ];
    let redacted = text;
    if (typeof redacted !== 'string') {
        redacted = redacted == null ? '' : String(redacted);
    }
    patterns.forEach(([label,regex]) => {
        redacted = redacted.replace(regex, `[REDACTED-${label}]`);
    });
    return redacted;
}

function applyRedactionToInput(input) {
    if (CFG.redactPIIEnabled === false) {
        return;
    }
    const original = input.value;
    //console.log("input is ", original);
    const redacted = redactPII(original);
    //console.log("redacted = ", redacted);
    if (original !== redacted) {
       // console.log('original is not = to redacted');
        sendTelemetry("pii_detected", { redacted_value: redacted, field: input.name || "unknown" });
        if (!input.dataset.redactedAlerted){
            alert(' \n We detected: \n ' + redacted + ' \n may have been included in the input text you just typed. \n are you sure you mean to include this input?');
            input.dataset.redactedAlerted = true;
        }
    }
    else {
        input.dataset.redactedAlerted = "";
    }
}

function applyRedactionToEditable(el) {
    if (CFG.redactPIIEnabled === false) {
        return;
    }
    const original = el.innerText;
    const redacted = redactPII(original);
    if (!el.dataset.redactedAlerted){
    if (original !== redacted){
        sendTelemetry("pii_detected", { redacted_value: redacted, field: el.getAttribute("name") || "contenteditable" });
        alert(' \n We detected: \n ' + redacted + ' \n may have been included in the input text you just typed. \n are you sure you mean to include this input?');
        el.dataset.redactedAlerted = true;
    }
    else {
        el.dataset.redactedAlerted = "";
    }
    }
}

function scanQueryStringForPII() {
    if (CFG.redactPIIEnabled === false) {
        return;
    }
    if (!window.location.search || window.__queryStringRedactedAlerted) {
        return;
    }

    const params = new URLSearchParams(window.location.search);
    const findings = [];

    params.forEach((value, key) => {
        const stringValue = value == null ? '' : String(value);
        const redacted = redactPII(stringValue);
        if (redacted !== stringValue) {
            findings.push(`${key}=${redacted}`);
        }
    });

    if (!findings.length) {
        return;
    }

    sendTelemetry("pii_detected", { location: "query_string", findings: findings });
    alert(' \n We detected possible sensitive data in the query string: \n ' + findings.join('\n'));
    window.__queryStringRedactedAlerted = true;
}

function setupListeners() {
    if (CFG.redactPIIEnabled === false) {
        return;
    }
    const inputs = document.querySelectorAll('input[type="text"], textarea');
    inputs.forEach(input => {
        input.addEventListener('input', () => {
            applyRedactionToInput(input);
        });
        input.addEventListener('blur', () => applyRedactionToInput(input));
        input.addEventListener('keyup', () => applyRedactionToInput(input));
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText= e.clipboardData.getData('text');
            applyRedactionToInput(input);
        });
    });

    const editables = document.querySelectorAll('[contenteditable="true"],input[type="text"], textarea');
    editables.forEach(el => {
        el.addEventListener('input', () => applyRedactionToEditable(el));
        el.addEventListener('blur', () => applyRedactionToEditable(el));
        el.addEventListener('keyup', () => applyRedactionToEditable(el));
        el.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedText = e.clipboardData.getData('text');
            document.execCommand('insertText', false, redactPII(pastedText));
            applyRedactionToEditable(el);
    });
    });
    //Form Submission
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit',() => {
            inputs.forEach(input => applyRedactionToInput(input));
            editables.forEach(el => applyRedactionToEditable(el));
            sendTelemetry("form_detected", { action: form.action || window.location.href });
        });
    });
    }
window.addEventListener('DOMContentLoaded', () => {
    // Always emit page visit telemetry (if enabled) regardless of PII setting.
    sendTelemetry("page_visit", { url: window.location.href });

    // PII detection/warnings are optional.
    if (CFG.redactPIIEnabled !== false) {
        scanQueryStringForPII();
        setupListeners();
    }
});

// Notify background/service worker that the content script is active.
try {
    chrome.runtime.sendMessage({ type: "content_loaded", url: window.location.href });
} catch (err) {
    console.warn("[AiShields] failed to notify background", err);
}

} // end singleton guard
if (!window.__observer2pkInitialized) {
    window.__observer2pkInitialized = true;
    const observer2pk = new MutationObserver((mutationsList, observer) => {
        for (const mutation of mutationsList){
            if (mutation.type === 'childList' || mutation.type === 'subtree'){
                setupListeners();
                console.log('listeners loaded');
                break;
            }
        }
    });

observer2pk.observe(document.body, {
    childList: true,
    subtree: true
});
}
// Telemetry helpers replace old SIEM logger to align with CyberArmor ingest API.
