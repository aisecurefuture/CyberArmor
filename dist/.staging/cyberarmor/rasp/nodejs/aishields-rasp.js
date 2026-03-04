/**
 * CyberArmor.ai RASP — Node.js Runtime Application Self-Protection
 * Supports: Express/Koa/Fastify middleware, http/https monkey-patching
 */

'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');

// ── Config ───────────────────────────────────────────────
const config = {
  controlPlaneUrl: process.env.CYBERARMOR_URL || 'http://localhost:8000',
  apiKey: process.env.CYBERARMOR_API_KEY || '',
  tenantId: process.env.CYBERARMOR_TENANT || 'default',
  mode: process.env.CYBERARMOR_MODE || 'monitor', // monitor | block
  dlpEnabled: true,
  promptInjectionEnabled: true,
};

// ── AI Endpoints ─────────────────────────────────────────
const AI_DOMAINS = new Set([
  'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com',
  'api.cohere.ai', 'api.mistral.ai', 'api-inference.huggingface.co',
  'api.together.xyz', 'api.replicate.com', 'api.groq.com',
]);

function isAiEndpoint(hostname) {
  return AI_DOMAINS.has(hostname) ||
    /\.openai\.azure\.com$/.test(hostname) ||
    /\.cognitiveservices\.azure\.com$/.test(hostname);
}

// ── Detection ────────────────────────────────────────────
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+(a|an|in)/i,
  /system\s*:\s*you\s+are/i,
  /<\s*(system|prompt|instruction)\s*>/i,
  /jailbreak|DAN\s+mode|bypass\s+filter/i,
  /forget\s+(everything|all|your)/i,
];

const DLP_PATTERNS = [
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'credit_card', pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/ },
  { name: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'github_token', pattern: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/ },
  { name: 'private_key', pattern: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/ },
];

function detectPromptInjection(text) {
  for (const p of PROMPT_INJECTION_PATTERNS) {
    if (p.test(text)) return p.source;
  }
  return null;
}

function scanDlp(text) {
  return DLP_PATTERNS.filter(d => d.pattern.test(text)).map(d => d.name);
}

// ── Telemetry ────────────────────────────────────────────
const eventBuffer = [];
function recordEvent(type, url, detail = '') {
  eventBuffer.push({ ts: Date.now(), type, url, detail: detail.slice(0, 200), tenant: config.tenantId });
  if (eventBuffer.length >= 50) {
    const batch = eventBuffer.splice(0);
    flushTelemetry(batch).catch(() => {});
  }
}

async function flushTelemetry(batch) {
  if (!config.controlPlaneUrl) return;
  try {
    const body = JSON.stringify(batch);
    const u = new URL('/telemetry/ingest', config.controlPlaneUrl);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': config.apiKey } });
    req.write(body);
    req.end();
  } catch {}
}

// ── Core Inspection ──────────────────────────────────────
function inspect(url, body = '') {
  const hostname = typeof url === 'string' ? new URL(url).hostname : (url.hostname || '');
  if (!isAiEndpoint(hostname)) return { allowed: true };

  recordEvent('ai_request', String(url));

  if (config.promptInjectionEnabled && body) {
    const pattern = detectPromptInjection(body);
    if (pattern) {
      recordEvent('prompt_injection', String(url), pattern);
      if (config.mode === 'block') return { allowed: false, reason: `Prompt injection: ${pattern}` };
    }
  }

  if (config.dlpEnabled && body) {
    const findings = scanDlp(body);
    if (findings.length) {
      recordEvent('sensitive_data', String(url), findings.join(','));
      if (config.mode === 'block') return { allowed: false, reason: `Sensitive data: ${findings.join(',')}` };
    }
  }

  return { allowed: true };
}

// ── Express Middleware ────────────────────────────────────
function expressMiddleware() {
  return (req, res, next) => {
    if (req.method !== 'POST') return next();
    const host = req.headers['x-forwarded-host'] || req.headers.host || '';
    if (!isAiEndpoint(host)) return next();

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const result = inspect(`https://${host}${req.path}`, body);
      if (!result.allowed) {
        return res.status(403).json({ error: result.reason, policy: 'aishields-rasp' });
      }
      next();
    });
  };
}

// ── Koa Middleware ────────────────────────────────────────
function koaMiddleware() {
  return async (ctx, next) => {
    if (ctx.method === 'POST') {
      const host = ctx.headers['x-forwarded-host'] || ctx.host || '';
      if (isAiEndpoint(host)) {
        const body = typeof ctx.request.body === 'string' ? ctx.request.body : JSON.stringify(ctx.request.body || '');
        const result = inspect(`https://${host}${ctx.path}`, body);
        if (!result.allowed) {
          ctx.status = 403;
          ctx.body = { error: result.reason, policy: 'aishields-rasp' };
          return;
        }
      }
    }
    await next();
  };
}

// ── HTTP Monkey-Patch ────────────────────────────────────
let patched = false;
function patch() {
  if (patched) return;
  patched = true;

  [http, https].forEach(mod => {
    const origRequest = mod.request;
    mod.request = function(urlOrOpts, optsOrCb, cb) {
      const opts = typeof urlOrOpts === 'string' ? new URL(urlOrOpts) : urlOrOpts;
      const hostname = opts.hostname || opts.host || '';
      if (isAiEndpoint(hostname)) {
        recordEvent('ai_request_outbound', `${hostname}${opts.path || ''}`);
      }
      return origRequest.call(mod, urlOrOpts, optsOrCb, cb);
    };
  });

  console.log('[CyberArmor.ai RASP] HTTP modules patched');
}

// ── Init ─────────────────────────────────────────────────
function init(opts = {}) {
  Object.assign(config, opts);
  patch();
  console.log(`[CyberArmor.ai RASP] Initialized (mode=${config.mode})`);
}

module.exports = { init, config, inspect, expressMiddleware, koaMiddleware, patch, isAiEndpoint, detectPromptInjection, scanDlp };
