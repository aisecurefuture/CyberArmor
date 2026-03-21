// CyberArmor Protect — Enterprise Admin Dashboard (vanilla JS SPA, no build step)
// Hash routing: #/overview, #/tenants, #/policies, #/policy-builder, #/proxy,
//   #/scan, #/audit, #/compliance, #/siem, #/identity, #/endpoints, #/dlp,
//   #/incidents, #/telemetry, #/api-keys, #/reports

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ─── Navigation ──────────────────────────────────────────
const NAV = [
  { id: "overview",       label: "Overview",          icon: "📊", hash: "#/overview" },
  { id: "tenants",        label: "Tenants",           icon: "🏢", hash: "#/tenants" },
  { id: "policies",       label: "Policies",          icon: "📋", hash: "#/policies" },
  { id: "policy-builder", label: "Policy Builder",    icon: "🔧", hash: "#/policy-builder" },
  { id: "api-keys",       label: "API Keys",          icon: "🔑", hash: "#/api-keys" },
  { id: "proxy",          label: "Proxy Controls",    icon: "🔀", hash: "#/proxy" },
  { id: "scan",           label: "Scan Tools",        icon: "🔍", hash: "#/scan" },
  { id: "endpoints",      label: "Endpoints",         icon: "💻", hash: "#/endpoints" },
  { id: "shadow-ai",      label: "Shadow AI",         icon: "👁️", hash: "#/shadow-ai" },
  { id: "compliance",     label: "Compliance",        icon: "✅", hash: "#/compliance" },
  { id: "siem",           label: "SIEM Config",       icon: "📡", hash: "#/siem" },
  { id: "identity",       label: "Identity / SSO",    icon: "🪪", hash: "#/identity" },
  { id: "dlp",            label: "DLP & Data Class.", icon: "🛡️", hash: "#/dlp" },
  { id: "incidents",      label: "Incidents",         icon: "🚨", hash: "#/incidents" },
  { id: "telemetry",      label: "Telemetry",         icon: "📈", hash: "#/telemetry" },
  { id: "audit",          label: "Audit Logs",        icon: "📝", hash: "#/audit" },
  { id: "reports",        label: "Reports",           icon: "📄", hash: "#/reports" },
  // ── AI Identity Control Plane ──────────────────────────
  { id: "agents",        label: "Agent Directory",    icon: "🤖", hash: "#/agents" },
  { id: "providers",     label: "AI Providers",       icon: "⚡", hash: "#/providers" },
  { id: "policy-studio", label: "Policy Studio",      icon: "🎯", hash: "#/policy-studio" },
  { id: "graph",         label: "Action Graph",       icon: "🕸️", hash: "#/graph" },
  { id: "risk",          label: "AI Risk Dashboard",  icon: "⚠️", hash: "#/risk" },
  { id: "delegations",   label: "Delegation Manager", icon: "🔗", hash: "#/delegations" },
  { id: "onboarding",    label: "SDK & Onboarding",   icon: "📦", hash: "#/onboarding" },
];

// ─── Service Configuration ───────────────────────────────
const SERVICES = [
  { key: "cp",         name: "Control Plane",    defaultUrl: "http://localhost:8000", defaultKey: "ChangeMe_GenerateSecureKey_Here", healthPath: "/health" },
  { key: "pol",        name: "Policy",           defaultUrl: "http://localhost:8001", defaultKey: "change-me-policy",     healthPath: "/health" },
  { key: "det",        name: "Detection",        defaultUrl: "http://localhost:8002", defaultKey: "change-me-detection",  healthPath: "/health" },
  { key: "rsp",        name: "Response",         defaultUrl: "http://localhost:8003", defaultKey: "change-me-response",   healthPath: "/health" },
  { key: "identity",   name: "Identity",         defaultUrl: "http://localhost:8004", defaultKey: "change-me-identity",   healthPath: "/health" },
  { key: "siem",       name: "SIEM Connector",   defaultUrl: "http://localhost:8005", defaultKey: "change-me-siem",       healthPath: "/health" },
  { key: "compliance", name: "Compliance",       defaultUrl: "http://localhost:8006", defaultKey: "change-me-compliance", healthPath: "/health" },
  { key: "px",         name: "Proxy Agent",      defaultUrl: "http://localhost:8010", defaultKey: "change-me-proxy",      healthPath: "/health" },
  // AI Identity Control Plane services
  { key: "agentId",    name: "Agent Identity",   defaultUrl: "http://localhost:8008", defaultKey: "change-me-agent-identity", healthPath: "/health" },
  { key: "aiRouter",   name: "AI Router",        defaultUrl: "http://localhost:8009", defaultKey: "change-me-router", healthPath: "/health" },
  { key: "auditGraph", name: "Audit Graph",      defaultUrl: "http://localhost:8011", defaultKey: "change-me-audit",  healthPath: "/health" },
];

// ─── Settings ────────────────────────────────────────────
function buildDefaults() {
  const d = { tenantScope: "" };
  SERVICES.forEach(s => { d[s.key + "Url"] = s.defaultUrl; d[s.key + "Key"] = s.defaultKey; });
  return d;
}
const DEFAULTS = buildDefaults();

const INTERNAL_SERVICE_HOSTS = new Set([
  "control-plane",
  "policy",
  "detection",
  "response",
  "identity",
  "siem-connector",
  "compliance",
  "proxy-agent",
  "agent-identity",
  "ai-router",
  "audit",
]);

function normalizeServiceUrl(url, fallbackUrl) {
  try {
    const parsed = new URL(String(url || "").trim());
    const host = parsed.hostname.toLowerCase();
    if (INTERNAL_SERVICE_HOSTS.has(host)) return fallbackUrl;
    if (host === "0.0.0.0") {
      parsed.hostname = "localhost";
      return parsed.toString().replace(/\/$/, "");
    }
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return fallbackUrl;
  }
}

function loadSettings() {
  const raw = localStorage.getItem("cyberarmor_settings");
  const merged = raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
  SERVICES.forEach(s => {
    const k = s.key + "Url";
    merged[k] = normalizeServiceUrl(merged[k], s.defaultUrl);
  });
  return merged;
}
function saveSettingsToStorage(s) { localStorage.setItem("cyberarmor_settings", JSON.stringify(s)); }
let settings = loadSettings();
let pendingApiKeyReveal = null;

// ─── Utilities ───────────────────────────────────────────
function esc(str = "") {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

function actionText(val) {
  if (typeof val === "string") return val;
  if (val == null) return "";
  if (typeof val === "number" || typeof val === "boolean") return String(val);
  if (typeof val === "object") {
    if (typeof val.action === "string") return val.action;
    return "";
  }
  return "";
}

function isBlockAction(val) {
  return actionText(val).toLowerCase().includes("block");
}

function badge(text, tone = "slate") {
  const m = {
    slate: "bg-slate-800 text-slate-100 border-slate-700",
    green: "bg-emerald-900/40 text-emerald-200 border-emerald-900",
    red: "bg-rose-900/40 text-rose-200 border-rose-900",
    amber: "bg-amber-900/40 text-amber-200 border-amber-900",
    indigo: "bg-indigo-900/40 text-indigo-200 border-indigo-900",
    cyan: "bg-cyan-900/40 text-cyan-200 border-cyan-900",
  };
  return `<span class="inline-flex items-center px-2 py-0.5 rounded-lg text-xs border ${m[tone]||m.slate}">${esc(text)}</span>`;
}

function card(html, cls = "") {
  return `<div class="view-card rounded-2xl border border-slate-800 bg-slate-950 shadow-sm ${cls}"><div class="p-5">${html}</div></div>`;
}

function metricCard(label, value, tone = "slate", subtitle = "") {
  const colors = { slate: "text-slate-100", green: "text-emerald-400", red: "text-rose-400", amber: "text-amber-400", indigo: "text-indigo-400" };
  return card(`
    <div class="text-xs text-slate-400 mb-1">${esc(label)}</div>
    <div class="text-2xl font-bold ${colors[tone] || colors.slate}">${esc(String(value))}</div>
    ${subtitle ? `<div class="text-xs text-slate-500 mt-1">${esc(subtitle)}</div>` : ""}
  `);
}

function tableWrap(headersHtml, rowsHtml) {
  return `<div class="overflow-x-auto"><table class="w-full text-sm">
    <thead><tr class="text-left text-xs text-slate-400 border-b border-slate-800">${headersHtml}</tr></thead>
    <tbody class="divide-y divide-slate-800/50">${rowsHtml}</tbody>
  </table></div>`;
}

function th(label) { return `<th class="py-2 px-3 font-medium">${esc(label)}</th>`; }
function td(content, raw = false) { return `<td class="py-2 px-3">${raw ? content : esc(content)}</td>`; }

function emptyState(msg) { return `<div class="text-center py-12 text-slate-500">${esc(msg)}</div>`; }
function loading() { return `<div class="flex items-center justify-center py-12 gap-2"><div class="spinner"></div><span class="text-slate-400 text-sm">Loading...</span></div>`; }

function toast(msg, type = "info") {
  const el = document.createElement("div");
  const bg = type === "error" ? "bg-rose-900 border-rose-700" : type === "success" ? "bg-emerald-900 border-emerald-700" : "bg-slate-800 border-slate-700";
  el.className = `toast px-4 py-3 rounded-xl border text-sm ${bg}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

async function apiFetch(url, { headers = {}, ...opts } = {}) {
  try {
    const res = await fetch(url, { ...opts, headers });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }
    if (!res.ok) throw new Error(typeof data === "object" ? (data.detail || JSON.stringify(data)) : data);
    return data;
  } catch (e) {
    throw e;
  }
}

function svcUrl(svcKey) { return settings[svcKey + "Url"]; }
function svcHeaders(svcKey) {
  const key = settings[svcKey + "Key"];
  return key ? { "x-api-key": key, "Content-Type": "application/json" } : { "Content-Type": "application/json" };
}

function getTenant() { return settings.tenantScope || "default"; }
let activeViewCleanup = null;

function setViewCleanup(fn) {
  if (typeof activeViewCleanup === "function") {
    try { activeViewCleanup(); } catch {}
  }
  activeViewCleanup = fn;
}

function clearViewCleanup() {
  if (typeof activeViewCleanup === "function") {
    try { activeViewCleanup(); } catch {}
  }
  activeViewCleanup = null;
}

// ─── Confirm dialog ──────────────────────────────────────
let _confirmResolve;
function confirm(title, message) {
  return new Promise(resolve => {
    _confirmResolve = resolve;
    $("#confirmTitle").textContent = title;
    $("#confirmMessage").textContent = message;
    $("#confirmModal").classList.remove("hidden");
    $("#confirmModal").classList.add("flex");
  });
}
$("#confirmOk").onclick = () => { _confirmResolve?.(true); $("#confirmModal").classList.add("hidden"); $("#confirmModal").classList.remove("flex"); };
$("#confirmCancel").onclick = () => { _confirmResolve?.(false); $("#confirmModal").classList.add("hidden"); $("#confirmModal").classList.remove("flex"); };

// ─── Build UI ────────────────────────────────────────────
function buildNav() {
  const nav = $("#nav");
  nav.innerHTML = "";
  const AI_ICP_IDS = new Set(["agents","providers","policy-studio","graph","risk","delegations","onboarding"]);
  let dividerAdded = false;
  for (const item of NAV) {
    if (AI_ICP_IDS.has(item.id) && !dividerAdded) {
      // Section header divider
      const divider = document.createElement("div");
      divider.className = "pt-3 pb-1 px-3";
      divider.innerHTML = `<div class="text-xs font-semibold text-indigo-400 uppercase tracking-widest">AI Identity</div>`;
      nav.appendChild(divider);
      dividerAdded = true;
    }
    const a = document.createElement("a");
    a.href = item.hash;
    a.className = "nav-item flex items-center gap-2 px-3 py-2 rounded-xl text-sm border border-transparent hover:bg-slate-900 hover:border-slate-800 text-slate-300";
    a.dataset.nav = item.id;
    a.innerHTML = `<span class="text-base">${item.icon}</span> ${esc(item.label)}`;
    nav.appendChild(a);
  }
}

function setActiveNav(id) {
  $$("[data-nav]").forEach(el => {
    const active = el.dataset.nav === id;
    el.classList.toggle("bg-slate-900", active);
    el.classList.toggle("border-slate-800", active);
    el.classList.toggle("text-white", active);
    el.classList.toggle("text-slate-300", !active);
  });
}

function buildServiceStatus() {
  const el = $("#serviceStatus");
  el.innerHTML = SERVICES.map(s =>
    `<div class="flex items-center justify-between"><span class="text-slate-300">${s.name}:</span><span id="svc_${s.key}" class="flex items-center gap-1"><span class="pulse-dot bg-slate-600"></span> —</span></div>`
  ).join("");
}

function buildSettingsFields() {
  const el = $("#settingsFields");
  el.innerHTML = SERVICES.map(s => `
    <div class="space-y-2">
      <label class="text-xs text-slate-300">${s.name} URL</label>
      <input id="set_${s.key}Url" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="${esc(settings[s.key+'Url'])}" />
    </div>
    <div class="space-y-2">
      <label class="text-xs text-slate-300">${s.name} API Key</label>
      <input id="set_${s.key}Key" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="${esc(settings[s.key+'Key'])}" type="password" />
    </div>
  `).join("");
}

// ─── Health Check ────────────────────────────────────────
async function pingAll() {
  for (const s of SERVICES) {
    const el = $(`#svc_${s.key}`);
    el.innerHTML = `<div class="spinner"></div>`;
    try {
      await apiFetch(svcUrl(s.key) + s.healthPath, { headers: svcHeaders(s.key) });
      el.innerHTML = `<span class="pulse-dot bg-emerald-500"></span> OK`;
    } catch {
      el.innerHTML = `<span class="pulse-dot bg-rose-500"></span> Down`;
    }
  }
}

// ─── VIEWS ───────────────────────────────────────────────

// ---------- Overview ----------
async function viewOverview() {
  const app = $("#app");
  app.innerHTML = loading();

  let tenantCount = "—", policyCount = "—", auditCount = "—", alertCount = "—", agentCount = "—", providerCount = "—";
  try {
    const tenants = await apiFetch(`${svcUrl("cp")}/tenants`, { headers: svcHeaders("cp") });
    tenantCount = Array.isArray(tenants) ? tenants.length : "?";
  } catch {}
  try {
    const tenant = getTenant();
    const policies = await apiFetch(`${svcUrl("pol")}/policies/${tenant}`, { headers: svcHeaders("pol") });
    policyCount = Array.isArray(policies) ? policies.length : "?";
  } catch {}
  try {
    const audit = await apiFetch(`${svcUrl("cp")}/audit?limit=1000`, { headers: svcHeaders("cp") });
    auditCount = Array.isArray(audit) ? audit.length : "?";
    alertCount = Array.isArray(audit) ? audit.filter(a => isBlockAction(a.action)).length : "?";
  } catch {}
  try {
    const agents = await apiFetch(`${svcUrl("agentId")}/agents?tenant_id=${getTenant()}&limit=1000`, { headers: svcHeaders("agentId") });
    const al = Array.isArray(agents) ? agents : (agents.agents||[]);
    agentCount = al.length;
  } catch {}
  try {
    const providers = await apiFetch(`${svcUrl("aiRouter")}/ai/providers`, { headers: svcHeaders("aiRouter") });
    providerCount = (providers.providers||[]).length;
  } catch {}

  app.innerHTML = `
    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
      ${metricCard("Tenants",          tenantCount,  "indigo")}
      ${metricCard("Policies",         policyCount,  "cyan")}
      ${metricCard("AI Agents",        agentCount,   "indigo",  "registered identities")}
      ${metricCard("AI Providers",     providerCount,"green",   "configured")}
      ${metricCard("Audit Events",     auditCount,   "slate",   "last 1000")}
      ${metricCard("Blocked Threats",  alertCount,   "red")}
    </div>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      ${card(`
        <div class="font-semibold mb-3">Quick Actions</div>
        <div class="grid grid-cols-2 gap-2 text-sm">
          <a href="#/agents"        class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>🤖</span>Agent Directory</a>
          <a href="#/providers"     class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>⚡</span>AI Providers</a>
          <a href="#/policy-studio" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>🎯</span>Policy Studio</a>
          <a href="#/graph"         class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>🕸️</span>Action Graph</a>
          <a href="#/risk"          class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>⚠️</span>Risk Dashboard</a>
          <a href="#/onboarding"    class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>📦</span>SDK & Onboarding</a>
          <a href="#/compliance"    class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>✅</span>Compliance</a>
          <a href="#/scan"          class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 flex items-center gap-2"><span>🔍</span>Detection Scan</a>
        </div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Platform Info</div>
        <div class="space-y-2 text-sm text-slate-300">
          <div class="flex justify-between"><span>Version</span><span class="text-slate-100">2.0.0-aip</span></div>
          <div class="flex justify-between"><span>Mode</span>${badge("AI Identity Control Plane","indigo")}</div>
          <div class="flex justify-between"><span>Crypto</span>${badge("PQC ML-KEM-1024","indigo")} ${badge("ML-DSA-87","indigo")}</div>
          <div class="flex justify-between"><span>Architecture</span>${badge("Zero Trust","green")} ${badge("SPIFFE/SPIRE","cyan")}</div>
          <div class="flex justify-between"><span>Compliance</span>${badge("NIST CSF","cyan")} ${badge("SOC 2","cyan")} ${badge("GDPR","cyan")}</div>
          <div class="flex justify-between"><span>AI Providers</span>${badge("8 providers","green")}</div>
          <div class="flex justify-between"><span>SDK Languages</span>${badge("9 languages","amber")}</div>
        </div>
      `)}
    </div>
  `;
}

// ---------- Tenants ----------
async function viewTenants() {
  const app = $("#app");
  app.innerHTML = loading();
  try {
    const tenants = await apiFetch(`${svcUrl("cp")}/tenants`, { headers: svcHeaders("cp") });
    const rows = (Array.isArray(tenants) ? tenants : []).map(t => `
      <tr class="hover:bg-slate-900/50"><td class="py-2 px-3 font-mono text-xs">${esc(t.tenant_id||t.id||"")}</td><td class="py-2 px-3">${esc(t.name||"")}</td><td class="py-2 px-3">${esc(t.created_at||"")}</td><td class="py-2 px-3">${badge(t.status||"active","green")}</td></tr>
    `).join("");
    app.innerHTML = card(`
      <div class="flex items-center justify-between mb-4">
        <div class="font-semibold">Tenants</div>
        <button onclick="document.dispatchEvent(new Event('createTenant'))" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ New Tenant</button>
      </div>
      ${tableWrap(th("Tenant ID")+th("Name")+th("Created")+th("Status"), rows || `<tr><td colspan="4">${emptyState("No tenants found")}</td></tr>`)}
    `);
  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Policies ----------
async function viewPolicies() {
  const app = $("#app");
  app.innerHTML = loading();
  try {
    const tenant = getTenant();
    const polBase = svcUrl("pol");
    const polHdrs = svcHeaders("pol");

    // Fetch policies and OPA health in parallel
    const [policies, opaHealth] = await Promise.all([
      apiFetch(`${polBase}/policies/${tenant}`, { headers: polHdrs }),
      apiFetch(`${polBase}/opa/health`, { headers: polHdrs }).catch(() => null),
    ]);

    const opaUp = opaHealth?.opa === "ok";
    const opaEngine = opaUp ? "opa" : "python";
    const opaBadge = opaUp
      ? `<span class="text-xs px-2 py-1 rounded-lg bg-emerald-900/40 text-emerald-200 border border-emerald-900" title="OPA is active — policies evaluated via Rego">OPA</span>`
      : `<span class="text-xs px-2 py-1 rounded-lg bg-amber-900/40 text-amber-200 border border-amber-900" title="OPA unreachable — falling back to Python engine">Python fallback</span>`;

    const rows = (Array.isArray(policies) ? policies : []).map(p => {
      const enabled = p.enabled !== false;
      const action = p.action || "monitor";
      const actionBadge = action === "block" ? badge(action,"red") : action === "warn" ? badge(action,"amber") : badge(action,"green");
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc(p.name||p.id||"")}</td>
        <td class="py-2 px-3 text-xs">${esc(p.description||"")}</td>
        <td class="py-2 px-3">${actionBadge}</td>
        <td class="py-2 px-3">${badge(String(p.priority||0),"slate")}</td>
        <td class="py-2 px-3"><button class="text-xs px-2 py-1 rounded-lg ${enabled?"bg-emerald-900/40 text-emerald-200 border border-emerald-900":"bg-slate-800 text-slate-400 border border-slate-700"}" data-toggle-policy="${esc(p.name||p.id)}">${enabled?"Enabled":"Disabled"}</button></td>
        <td class="py-2 px-3">${(p.compliance_frameworks||[]).map(f=>badge(f,"cyan")).join(" ")}</td>
      </tr>`;
    }).join("");

    app.innerHTML = card(`
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-3">
          <div class="font-semibold">Policies for ${esc(tenant)}</div>
          <div class="flex items-center gap-1 text-xs text-slate-400">Engine: ${opaBadge}</div>
        </div>
        <div class="flex gap-2">
          <button id="reloadOpa" class="text-xs px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700" title="Re-upload base Rego policy to OPA">Reload OPA</button>
          <a href="#/policy-builder" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ New Policy</a>
          <button id="exportPolicies" class="text-xs px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Export JSON</button>
        </div>
      </div>
      ${tableWrap(th("Name")+th("Description")+th("Action")+th("Priority")+th("Status")+th("Frameworks"), rows || `<tr><td colspan="6">${emptyState("No policies")}</td></tr>`)}
    `);

    // Toggle handlers — policy_id is the policy name (no tenant in path)
    $$("[data-toggle-policy]").forEach(btn => {
      btn.onclick = async () => {
        const name = btn.dataset.togglePolicy;
        try {
          await apiFetch(`${polBase}/policies/${name}/toggle`, { method: "PATCH", headers: polHdrs });
          toast("Policy toggled", "success");
          viewPolicies();
        } catch (e) { toast(e.message, "error"); }
      };
    });

    // Reload OPA base Rego
    const reloadBtn = $("#reloadOpa");
    if (reloadBtn) reloadBtn.onclick = async () => {
      try {
        await apiFetch(`${polBase}/opa/reload-base`, { method: "POST", headers: polHdrs });
        toast("OPA base policy reloaded", "success");
        viewPolicies();
      } catch (e) { toast(e.message, "error"); }
    };

    // Export
    const expBtn = $("#exportPolicies");
    if (expBtn) expBtn.onclick = async () => {
      try {
        const data = await apiFetch(`${polBase}/policies/${tenant}/export`, { headers: polHdrs });
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `policies_${tenant}.json`;
        a.click();
        toast("Exported", "success");
      } catch (e) { toast(e.message, "error"); }
    };
  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Policy Builder (AND/OR condition groups) ----------
function viewPolicyBuilder() {
  const app = $("#app");
  let conditionState = { operator: "AND", conditions: [] };

  function renderConditionGroup(group, path = "") {
    const isOr = group.operator === "OR";
    const cls = isOr ? "or-group" : "";
    let html = `<div class="condition-group ${cls} mb-3 py-2">
      <div class="flex items-center gap-2 mb-2">
        <select class="text-xs px-2 py-1 rounded-lg bg-slate-900 border border-slate-800" data-path="${path}" data-field="operator">
          <option value="AND" ${!isOr?"selected":""}>AND</option>
          <option value="OR" ${isOr?"selected":""}>OR</option>
        </select>
        <button class="text-xs px-2 py-1 rounded-lg bg-indigo-900/40 text-indigo-200 border border-indigo-900" data-add-rule="${path}">+ Rule</button>
        <button class="text-xs px-2 py-1 rounded-lg bg-amber-900/40 text-amber-200 border border-amber-900" data-add-group="${path}">+ Group</button>
        ${path ? `<button class="text-xs px-2 py-1 rounded-lg bg-rose-900/40 text-rose-200 border border-rose-900" data-remove-group="${path}">Remove</button>` : ""}
      </div>`;

    (group.conditions || []).forEach((cond, i) => {
      const cp = path ? `${path}.${i}` : String(i);
      if (cond.operator) {
        html += renderConditionGroup(cond, cp);
      } else {
        html += `<div class="flex items-center gap-2 mb-1 ml-4">
          <input class="w-32 text-xs px-2 py-1 rounded-lg bg-slate-900 border border-slate-800" placeholder="field" value="${esc(cond.field||"")}" data-path="${cp}" data-field="field" />
          <select class="text-xs px-2 py-1 rounded-lg bg-slate-900 border border-slate-800" data-path="${cp}" data-field="op">
            ${["equals","not_equals","contains","not_contains","matches","regex","in","not_in","gt","gte","lt","lte","exists","not_exists"].map(o=>`<option ${cond.op===o?"selected":""}>${o}</option>`).join("")}
          </select>
          <input class="w-40 text-xs px-2 py-1 rounded-lg bg-slate-900 border border-slate-800" placeholder="value" value="${esc(cond.value||"")}" data-path="${cp}" data-field="value" />
          <button class="text-xs text-rose-400 hover:text-rose-300" data-remove-rule="${cp}">✕</button>
        </div>`;
      }
    });

    html += `</div>`;
    return html;
  }

  function getGroupAtPath(path) {
    if (!path) return conditionState;
    const parts = path.split(".");
    let node = conditionState;
    for (const p of parts) node = node.conditions[parseInt(p)];
    return node;
  }

  function render() {
    app.innerHTML = card(`
      <div class="font-semibold mb-4">Policy Builder</div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div class="space-y-2">
          <label class="text-xs text-slate-300">Policy Name</label>
          <input id="pb_name" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="e.g. block-prompt-injection" />
        </div>
        <div class="space-y-2">
          <label class="text-xs text-slate-300">Description</label>
          <input id="pb_desc" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="Description" />
        </div>
        <div class="space-y-2">
          <label class="text-xs text-slate-300">Action</label>
          <select id="pb_action" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800">
            <option value="monitor">Monitor</option><option value="warn">Warn</option><option value="block">Block</option><option value="allow">Allow</option>
          </select>
        </div>
        <div class="space-y-2">
          <label class="text-xs text-slate-300">Priority (0=highest)</label>
          <input id="pb_priority" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="100" />
        </div>
      </div>
      <div class="mb-4">
        <label class="text-xs text-slate-300 mb-2 block">Compliance Frameworks (comma-separated)</label>
        <input id="pb_frameworks" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="NIST-CSF, PCI-DSS, SOC2, GDPR" />
      </div>
      <div class="font-semibold mb-2 text-sm">Conditions</div>
      <div id="conditionTree">${renderConditionGroup(conditionState)}</div>
      <div class="mt-4 flex gap-2">
        <button id="pb_save" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Create Policy</button>
        <button id="pb_preview" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm">Preview JSON</button>
      </div>
      <pre id="pb_json" class="mt-4 p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono overflow-x-auto hidden"></pre>
    `);

    // Bind events
    $$("[data-add-rule]").forEach(btn => {
      btn.onclick = () => {
        const group = getGroupAtPath(btn.dataset.addRule);
        group.conditions.push({ field: "", op: "equals", value: "" });
        render();
      };
    });
    $$("[data-add-group]").forEach(btn => {
      btn.onclick = () => {
        const group = getGroupAtPath(btn.dataset.addGroup);
        group.conditions.push({ operator: "AND", conditions: [] });
        render();
      };
    });
    $$("[data-remove-rule]").forEach(btn => {
      btn.onclick = () => {
        const parts = btn.dataset.removeRule.split(".");
        const idx = parseInt(parts.pop());
        const parent = getGroupAtPath(parts.join("."));
        parent.conditions.splice(idx, 1);
        render();
      };
    });
    $$("[data-remove-group]").forEach(btn => {
      btn.onclick = () => {
        const parts = btn.dataset.removeGroup.split(".");
        const idx = parseInt(parts.pop());
        const parent = getGroupAtPath(parts.join("."));
        parent.conditions.splice(idx, 1);
        render();
      };
    });

    // Field change handlers
    $$("[data-path][data-field]").forEach(input => {
      const handler = () => {
        const path = input.dataset.path;
        const field = input.dataset.field;
        if (field === "operator") {
          const group = getGroupAtPath(path);
          group.operator = input.value;
        } else {
          const parts = path.split(".");
          const idx = parseInt(parts.pop());
          const parent = getGroupAtPath(parts.join("."));
          parent.conditions[idx][field] = input.value;
        }
      };
      input.oninput = handler;
      input.onchange = handler;
    });

    const previewBtn = $("#pb_preview");
    if (previewBtn) previewBtn.onclick = () => {
      const json = buildPolicyJson();
      const pre = $("#pb_json");
      pre.textContent = JSON.stringify(json, null, 2);
      pre.classList.toggle("hidden");
    };

    const saveBtn = $("#pb_save");
    if (saveBtn) saveBtn.onclick = async () => {
      const json = buildPolicyJson();
      if (!json.name) { toast("Policy name required", "error"); return; }
      try {
        await apiFetch(`${svcUrl("pol")}/policies`, {
          method: "POST", headers: svcHeaders("pol"), body: JSON.stringify(json),
        });
        toast("Policy created!", "success");
        location.hash = "#/policies";
      } catch (e) { toast(e.message, "error"); }
    };
  }

  function buildPolicyJson() {
    // Policy service expects condition trees under `rules` (not `conditions`).
    function toEngineTree(node) {
      const next = { operator: node?.operator || "AND", rules: [] };
      const children = Array.isArray(node?.conditions) ? node.conditions : [];
      for (const child of children) {
        if (Array.isArray(child?.conditions)) {
          next.rules.push(toEngineTree(child));
        } else {
          next.rules.push({
            field: child?.field || "",
            operator: child?.op || child?.operator || "equals",
            value: child?.value ?? "",
          });
        }
      }
      return next;
    }

    return {
      tenant_id: getTenant(),
      name: ($("#pb_name")?.value || "").trim(),
      description: ($("#pb_desc")?.value || "").trim(),
      action: $("#pb_action")?.value || "monitor",
      priority: parseInt($("#pb_priority")?.value || "100"),
      conditions: toEngineTree(conditionState),
      compliance_frameworks: ($("#pb_frameworks")?.value || "").split(",").map(s=>s.trim()).filter(Boolean),
      enabled: true,
    };
  }

  render();
}

// ---------- API Keys ----------
async function viewApiKeys() {
  const app = $("#app");
  app.innerHTML = loading();
  const cpBase = svcUrl("cp");
  const cpHdrs = svcHeaders("cp");

  function showKeyReveal(keyValue, label = "New API Key") {
    const panel = $("#apiKeyRevealPanel");
    if (!panel) return;
    panel.innerHTML = card(`
      <div class="font-semibold mb-2">${esc(label)} (shown once)</div>
      <div class="text-xs text-slate-400 mb-3">Copy now. The table only shows masked prefixes.</div>
      <pre class="text-xs font-mono bg-slate-900 p-3 rounded-xl overflow-x-auto whitespace-pre-wrap break-all border border-slate-800">${esc(keyValue || "")}</pre>
      <div class="mt-3 flex gap-2">
        <button id="copyNewApiKey" class="text-xs px-3 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500">Copy Key</button>
        <button id="hideNewApiKey" class="text-xs px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700">Hide</button>
      </div>
    `);

    const copyBtn = $("#copyNewApiKey");
    if (copyBtn) {
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(String(keyValue || ""));
          toast("API key copied to clipboard", "success");
        } catch {
          toast("Copy failed; select and copy manually", "error");
        }
      };
    }
    const hideBtn = $("#hideNewApiKey");
    if (hideBtn) hideBtn.onclick = () => { panel.innerHTML = ""; };
  }

  try {
    const tenant = getTenant();
    const keys = await apiFetch(`${cpBase}/apikeys`, { headers: cpHdrs });
    const rows = (Array.isArray(keys) ? keys : []).map(k => {
      const masked = k.key ? k.key.substring(0, 8) + "..." : "***";
      const active = k.active !== false;
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc(masked)}</td>
        <td class="py-2 px-3">${esc(k.role || "")}</td>
        <td class="py-2 px-3">${esc(k.tenant_id || "global")}</td>
        <td class="py-2 px-3">${badge(active ? "Active" : "Revoked", active ? "green" : "red")}</td>
        <td class="py-2 px-3">
          ${active ? `<button class="text-xs px-2 py-1 rounded-lg bg-amber-900/40 text-amber-200 border border-amber-900 mr-1" data-rotate-key="${esc(k.key)}" data-rotate-role="${esc(k.role||"analyst")}" data-rotate-tenant="${esc(k.tenant_id||"")}">Rotate</button>` : ""}
          ${active ? `<button class="text-xs px-2 py-1 rounded-lg bg-rose-900/40 text-rose-200 border border-rose-900" data-revoke-key="${esc(k.key)}">Revoke</button>` : ""}
        </td>
      </tr>`;
    }).join("");

    app.innerHTML = card(`
      <div class="flex items-center justify-between mb-4">
        <div class="font-semibold">API Keys</div>
        <button id="genApiKey" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ Generate Key</button>
      </div>
      <div class="text-xs text-slate-400 mb-4">Rotation creates a new key and immediately revokes the old one.</div>
      ${tableWrap(th("Key (prefix)")+th("Role")+th("Tenant")+th("Status")+th("Actions"), rows || `<tr><td colspan="5">${emptyState("No API keys")}</td></tr>`)}
    `) + `<div id="apiKeyRevealPanel" class="mt-4"></div>`;

    if (pendingApiKeyReveal && pendingApiKeyReveal.key) {
      showKeyReveal(pendingApiKeyReveal.key, pendingApiKeyReveal.label || "New API Key");
      pendingApiKeyReveal = null;
    }

    // Generate new key
    $("#genApiKey").onclick = async () => {
      try {
        const created = await apiFetch(`${cpBase}/apikeys`, {
          method: "POST", headers: cpHdrs,
          body: JSON.stringify({ tenant_id: tenant, role: "analyst" }),
        });
        toast(`Key created: ${created.key.substring(0, 8)}...`, "success");
        pendingApiKeyReveal = { key: created.key, label: "Generated API Key" };
        viewApiKeys();
      } catch (e) { toast(e.message, "error"); }
    };

    // Rotate key: create a new one with same role/tenant, then disable the old one
    $$("[data-rotate-key]").forEach(btn => {
      btn.onclick = async () => {
        const oldKey = btn.dataset.rotateKey;
        const role = btn.dataset.rotateRole || "analyst";
        const tenantId = btn.dataset.rotateTenant || tenant;
        try {
          const created = await apiFetch(`${cpBase}/apikeys`, {
            method: "POST", headers: cpHdrs,
            body: JSON.stringify({ tenant_id: tenantId, role }),
          });
          await apiFetch(`${cpBase}/apikeys/${oldKey}/disable`, { method: "PATCH", headers: cpHdrs });
          toast(`Rotated — new key: ${created.key.substring(0, 8)}...`, "success");
          pendingApiKeyReveal = { key: created.key, label: "Rotated API Key" };
          viewApiKeys();
        } catch (e) { toast(e.message, "error"); }
      };
    });

    // Revoke key
    $$("[data-revoke-key]").forEach(btn => {
      btn.onclick = async () => {
        const key = btn.dataset.revokeKey;
        try {
          await apiFetch(`${cpBase}/apikeys/${key}/disable`, { method: "PATCH", headers: cpHdrs });
          toast("Key revoked", "success");
          viewApiKeys();
        } catch (e) { toast(e.message, "error"); }
      };
    });

  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Proxy Controls ----------
async function viewProxy() {
  const app = $("#app");
  app.innerHTML = loading();
  try {
    const policies = await apiFetch(`${svcUrl("px")}/policies/cached/${getTenant()}`, { headers: svcHeaders("px") });
    const list = Array.isArray(policies) ? policies : (policies.policies || []);
    const rows = list.map(r => `
      <tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3">${esc(r.name||"")}</td>
        <td class="py-2 px-3">${badge(r.action||"monitor", r.action==="block"?"red":r.action==="warn"?"yellow":"green")}</td>
        <td class="py-2 px-3 text-xs">${r.enabled===false ? '<span class="text-slate-500">disabled</span>' : '<span class="text-emerald-400">enabled</span>'}</td>
      </tr>
    `).join("");
    app.innerHTML = card(`
      <div class="font-semibold mb-4">Cached Proxy Policies</div>
      ${tableWrap(th("Policy Name")+th("Action")+th("Status"), rows || `<tr><td colspan="3">${emptyState("No cached policies")}</td></tr>`)}
    `) + `<div class="mt-4">${card(`
      <div class="font-semibold mb-3">Test URL</div>
      <div class="flex gap-2">
        <input id="testUrl" class="flex-1 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="https://api.openai.com/v1/chat/completions" />
        <button id="testUrlBtn" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Check</button>
      </div>
      <div id="testResult" class="mt-3 text-sm"></div>
    `)}</div>`;

    const testBtn = $("#testUrlBtn");
    if (testBtn) testBtn.onclick = async () => {
      try {
        const url = $("#testUrl").value;
        const r = await apiFetch(`${svcUrl("px")}/decision`, {
          method: "POST", headers: svcHeaders("px"),
          body: JSON.stringify({ url, method: "POST", tenant_id: getTenant() }),
        });
        $("#testResult").innerHTML = `<div>${badge(r.decision||r.action||"unknown", r.decision==="allow"||r.action==="allow"?"green":"red")} ${esc(r.reason||"")}</div>`;
      } catch (e) { $("#testResult").innerHTML = `<span class="text-rose-400">${esc(e.message)}</span>`; }
    };
  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Scan Tools ----------
function viewScan() {
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      ${card(`
        <div class="font-semibold mb-3">Prompt Injection Scan</div>
        <textarea id="scanPrompt" rows="4" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="Enter text to scan for prompt injection..."></textarea>
        <button id="runPromptScan" class="mt-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Scan</button>
        <div id="promptResult" class="mt-3"></div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Sensitive Data Scan</div>
        <textarea id="scanData" rows="4" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="Enter text to scan for PII/secrets..."></textarea>
        <button id="runDataScan" class="mt-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Scan</button>
        <div id="dataResult" class="mt-3"></div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Output Safety Scan</div>
        <textarea id="scanOutput" rows="4" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="Enter AI output to scan for safety..."></textarea>
        <button id="runOutputScan" class="mt-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Scan</button>
        <div id="outputResult" class="mt-3"></div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Full Pipeline Scan</div>
        <textarea id="scanFull" rows="4" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="Enter text for full pipeline scan..."></textarea>
        <button id="runFullScan" class="mt-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Scan All</button>
        <div id="fullResult" class="mt-3"></div>
      `)}
    </div>
  `;

  async function runScan(inputId, resultId, endpoint, bodyKey) {
    const text = $(inputId).value;
    if (!text) return;
    $(resultId).innerHTML = `<div class="spinner"></div>`;
    try {
      const r = await apiFetch(`${svcUrl("det")}${endpoint}`, {
        method: "POST", headers: svcHeaders("det"),
        body: JSON.stringify({ [bodyKey]: text }),
      });
      $(resultId).innerHTML = `<pre class="text-xs p-3 rounded-xl bg-slate-900 border border-slate-800 overflow-x-auto">${esc(JSON.stringify(r, null, 2))}</pre>`;
    } catch (e) { $(resultId).innerHTML = `<span class="text-rose-400 text-sm">${esc(e.message)}</span>`; }
  }

  $("#runPromptScan").onclick = () => runScan("#scanPrompt", "#promptResult", "/scan/prompt-injection", "text");
  $("#runDataScan").onclick = () => runScan("#scanData", "#dataResult", "/scan/sensitive-data", "text");
  $("#runOutputScan").onclick = () => runScan("#scanOutput", "#outputResult", "/scan/output-safety", "text");
  $("#runFullScan").onclick = () => runScan("#scanFull", "#fullResult", "/scan/all", "text");
}

// ---------- Endpoints ----------
async function viewEndpoints() {
  const app = $("#app");
  app.innerHTML = loading();

  let agents = [];
  try {
    // No tenant_id filter — Endpoints is an admin view; show all registered agents.
    const resp = await apiFetch(
      `${svcUrl("cp")}/agents?limit=500`,
      { headers: svcHeaders("cp") }
    );
    agents = Array.isArray(resp) ? resp : [];
  } catch (_) { /* fall through to empty state */ }

  const now = Date.now();
  // "online" = last heartbeat within 2 minutes
  const isOnline = a => a.last_seen && (now - new Date(a.last_seen).getTime()) < 120_000;
  const onlineCount  = agents.filter(isOnline).length;
  const desktopCount = agents.filter(a => {
    const os = a.os || (a.platform && typeof a.platform === "object" ? a.platform.os : a.platform) || "";
    return os !== "";
  }).length;

  const rows = agents.map(a => {
    const ls = a.last_seen ? new Date(a.last_seen) : null;
    const lastSeenStr = ls
      ? ls.toLocaleDateString() + " " + ls.toLocaleTimeString()
      : "—";
    const online = isOnline(a);
    // platform may be a flat string (from heartbeat) or a nested dict (from register)
    const tenant = a.tenant_id || "—";
    const osStr   = a.os || (a.platform && typeof a.platform === "object" ? a.platform.os : a.platform) || "—";
    const hostname = a.hostname || (a.platform && typeof a.platform === "object" ? a.platform.hostname : "") || "";
    const username = a.username || (a.platform && typeof a.platform === "object" ? a.platform.username : "") || a.user_id || "—";
    const version  = a.version || a.agent_version || "—";
    return `<tr>
      <td class="py-2 px-3 font-mono text-xs" title="${esc(hostname)}">${esc(a.agent_id||a.id||"")}</td>
      <td class="py-2 px-3 text-xs">${esc(tenant)}</td>
      <td class="py-2 px-3 text-xs">Desktop Agent</td>
      <td class="py-2 px-3 text-xs">${esc(hostname || "—")}</td>
      <td class="py-2 px-3 text-xs">${esc(username)}</td>
      <td class="py-2 px-3 text-xs">${esc(osStr)}</td>
      <td class="py-2 px-3 text-xs font-mono">${esc(version)}</td>
      <td class="py-2 px-3 text-xs">${esc(lastSeenStr)}</td>
      <td class="py-2 px-3">${badge(online ? "online" : "offline", online ? "green" : "rose")}</td>
    </tr>`;
  }).join("");

  app.innerHTML = card(`
    <div class="flex items-center justify-between mb-4">
      <div class="font-semibold">Registered Endpoints</div>
      <button id="endpointRefreshBtn" class="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700">↻ Refresh</button>
    </div>
    <div class="text-xs text-slate-400 mb-4">Endpoints register automatically on agent startup. Online = heartbeat within last 2 min.</div>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
      ${metricCard("Desktop Agents",   desktopCount,               "indigo", "macOS / Windows / Linux")}
      ${metricCard("Online Now",       onlineCount,                "green",  "heartbeat < 2 min")}
      ${metricCard("Total Registered", agents.length,              "cyan",   "all tenants")}
      ${metricCard("Offline",          agents.length - onlineCount,"rose",   "no recent heartbeat")}
    </div>
    ${tableWrap(
      th("Agent ID") + th("Tenant") + th("Type") + th("Hostname") + th("Username") + th("Platform") + th("Agent Version") + th("Last Seen") + th("Status"),
      rows || `<tr><td colspan="9">${emptyState("No endpoints registered yet. Deploy the agent installer and point it at this control plane.")}</td></tr>`
    )}
  `);
  // Attach refresh — inline onclick="..." fails when app.js is type="module"
  $("#endpointRefreshBtn")?.addEventListener("click", viewEndpoints);
}

// ---------- Shadow AI ----------
async function viewShadowAi() {
  const app = $("#app");
  app.innerHTML = loading();

  try {
    const explainSeverity = (event) => {
      const payload = event.payload || {};
      const severity = String(payload.severity || event.severity || "medium").toLowerCase();
      const eventType = String(event.event_type || "").toLowerCase();
      const toolName = payload.tool_name || payload.service || payload.domain || payload.process_name || payload.exe || "AI tool";

      if (eventType === "ai_tool_process_detected") {
        return `${severity}: live AI process detected on the endpoint (${toolName})`;
      }
      if (eventType === "ai_service_connection_detected") {
        const domain = payload.domain || payload.remote_ip || "unknown destination";
        return `${severity}: active connection to AI service (${domain})`;
      }
      if (eventType === "unauthorized_ai_tool_detected") {
        return `${severity}: installed tool is marked unauthorized by policy`;
      }
      if (eventType === "ai_tool_installed") {
        return `${severity}: installed AI tool inventory finding`;
      }
      if (eventType === "mcp_connection_detected") {
        return `${severity}: possible MCP traffic on a known MCP port`;
      }
      if (eventType === "suspicious_cmdline_detected") {
        const patterns = Array.isArray(payload.matched_patterns) ? payload.matched_patterns.join(", ") : "suspicious command-line match";
        return `${severity}: ${patterns}`;
      }
      return `${severity}: detector-assigned severity`;
    };

    const eventSummary = (event) => {
      const payload = event.payload || {};
      const parts = [];
      if (payload.process_name) parts.push(`process=${payload.process_name}`);
      if (payload.username || payload.user_id) parts.push(`user=${payload.username || payload.user_id}`);
      if (payload.domain) parts.push(`domain=${payload.domain}`);
      if (payload.remote_ip) parts.push(`remote_ip=${payload.remote_ip}`);
      if (payload.pid) parts.push(`pid=${payload.pid}`);
      if (payload.detection_method) parts.push(`method=${payload.detection_method}`);
      if (payload.detail) parts.push(`detail=${payload.detail}`);
      if (Array.isArray(payload.matched_patterns) && payload.matched_patterns.length) {
        parts.push(`patterns=${payload.matched_patterns.join(", ")}`);
      }
      return parts.join(" | ") || "No additional details";
    };

    const tenant = getTenant();
    const [eventsResp, agentsResp] = await Promise.all([
      apiFetch(`${svcUrl("cp")}/telemetry/${encodeURIComponent(tenant)}?source=endpoint&limit=500`, { headers: svcHeaders("cp") }),
      apiFetch(`${svcUrl("cp")}/agents?tenant_id=${encodeURIComponent(tenant)}&limit=500`, { headers: svcHeaders("cp") }),
    ]);

    const events = Array.isArray(eventsResp) ? eventsResp : [];
    const agents = Array.isArray(agentsResp) ? agentsResp : [];
    const agentById = new Map(agents.map(a => [a.agent_id || a.id, a]));
    const interesting = events.filter(e => {
      const eventType = String(e.event_type || "").toLowerCase();
      return eventType.includes("ai_") || eventType.includes("genai") || eventType.includes("shadow");
    });

    const appMap = new Map();
    interesting.forEach(e => {
      const payload = e.payload || {};
      const agentId = e.agent_id || payload.agent_id || "unknown-agent";
      const agent = agentById.get(agentId) || {};
      const hostname = e.hostname || payload.hostname || agent.hostname || "unknown-host";
      const userId = e.user_id || payload.username || payload.user_id || "unknown-user";
      const toolName = payload.tool_name || payload.service || payload.domain || payload.process_name || payload.exe || "Unknown AI Tool";
      const severity = String(payload.severity || "medium").toLowerCase();
      const key = `${hostname}:${toolName}:${userId}`;
      const ts = Date.parse(e.occurred_at || payload.timestamp || "") || 0;
      const current = appMap.get(key) || {
        hostname,
        toolName,
        userId,
        severity,
        agentId,
        count: 0,
        firstSeen: ts,
        lastSeen: ts,
        eventTypes: new Set(),
        reasons: new Set(),
      };
      current.count += 1;
      current.firstSeen = current.firstSeen ? Math.min(current.firstSeen, ts) : ts;
      current.lastSeen = Math.max(current.lastSeen, ts);
      current.eventTypes.add(e.event_type || "endpoint_event");
      current.reasons.add(explainSeverity(e));
      if (severity === "high" || (severity === "medium" && current.severity !== "high")) current.severity = severity;
      appMap.set(key, current);
    });

    const severityTone = (v) => v === "high" ? "red" : v === "medium" ? "amber" : "green";
    const fmtTs = (ts) => ts ? new Date(ts).toLocaleString() : "unknown";

    const rows = Array.from(appMap.values())
      .sort((a, b) => b.lastSeen - a.lastSeen)
      .map(item => `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 text-xs">${esc(item.hostname)}</td>
        <td class="py-2 px-3">
          <div class="font-medium">${esc(item.toolName)}</div>
          <div class="mt-2">
            <div class="inline-flex items-center rounded-md border border-slate-700 bg-slate-800 px-2 py-1 text-[11px] leading-4 text-slate-200">
              <span class="mr-1 font-semibold text-slate-100">Severity basis:</span>
              <span>${esc(Array.from(item.reasons).join(" ; ") || "Detector-assigned severity")}</span>
            </div>
          </div>
        </td>
        <td class="py-2 px-3 text-xs">${esc(item.userId)}</td>
        <td class="py-2 px-3">${badge(item.severity, severityTone(item.severity))}</td>
        <td class="py-2 px-3 text-xs">${esc(String(item.count))}</td>
        <td class="py-2 px-3 text-xs">${esc(fmtTs(item.firstSeen))}</td>
        <td class="py-2 px-3 text-xs">${esc(fmtTs(item.lastSeen))}</td>
      </tr>`).join("");

    const recentRows = interesting
      .sort((a, b) => (Date.parse(b.occurred_at || "") || 0) - (Date.parse(a.occurred_at || "") || 0))
      .slice(0, 50)
      .map(e => {
        const payload = e.payload || {};
        const toolName = payload.tool_name || payload.service || payload.domain || payload.process_name || payload.exe || "Unknown AI Tool";
        const hostname = e.hostname || payload.hostname || "unknown-host";
        const summary = eventSummary(e);
        return `<tr class="hover:bg-slate-900/50">
          <td class="py-2 px-3 text-xs">${esc(new Date(Date.parse(e.occurred_at || "") || 0).toLocaleString())}</td>
          <td class="py-2 px-3 text-xs">${esc(hostname)}</td>
          <td class="py-2 px-3">${esc(toolName)}</td>
          <td class="py-2 px-3">${badge(String(payload.severity || e.severity || "medium").toLowerCase(), severityTone(String(payload.severity || e.severity || "medium").toLowerCase()))}</td>
          <td class="py-2 px-3">${badge(e.event_type || "endpoint_event", "indigo")}</td>
          <td class="py-2 px-3 text-xs max-w-xs truncate">${esc(summary)}</td>
          <td class="py-2 px-3 text-xs max-w-sm">${esc(explainSeverity(e))}</td>
        </tr>`;
      }).join("");

    const highRiskCount = Array.from(appMap.values()).filter(x => x.severity === "high").length;
    const hostCount = new Set(Array.from(appMap.values()).map(x => x.hostname)).size;

    app.innerHTML = `
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
        ${metricCard("Detected Apps", appMap.size, "indigo", "unique host/tool/user combinations")}
        ${metricCard("Affected Hosts", hostCount, "cyan", "endpoints with detections")}
        ${metricCard("High Risk", highRiskCount, highRiskCount ? "red" : "green", "severity=high")}
        ${metricCard("Raw Events", interesting.length, "slate", "endpoint AI telemetry")}
      </div>
      ${card(`
        <div class="flex items-center justify-between gap-3 mb-3">
          <div class="font-semibold">Severity Guide</div>
          <div class="text-xs text-slate-500">How endpoint detections are currently classified</div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div class="rounded-xl border border-emerald-900 bg-emerald-950/30 p-3">
            <div class="mb-2">${badge("Info / Low", "green")}</div>
            <div class="text-slate-300">Inventory or lifecycle signals with limited immediate risk, such as process exit or low-confidence tool presence.</div>
          </div>
          <div class="rounded-xl border border-amber-900 bg-amber-950/30 p-3">
            <div class="mb-2">${badge("Medium", "amber")}</div>
            <div class="text-slate-300">Suspicious but indirect signals, such as MCP-port traffic, suspicious command-line patterns, or allowed installed-tool findings.</div>
          </div>
          <div class="rounded-xl border border-rose-900 bg-rose-950/30 p-3">
            <div class="mb-2">${badge("High / Critical", "red")}</div>
            <div class="text-slate-300">Active AI usage or unauthorized tooling, such as a live AI process, a connection to a known AI service, or an unauthorized installed AI tool.</div>
          </div>
        </div>
      `)}
      ${card(`
        <div class="flex items-center justify-between mb-4">
          <div class="font-semibold">Detected Shadow AI On Endpoints</div>
          <button id="shadowAiRefreshBtn" class="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700">Refresh</button>
        </div>
        <div class="text-xs text-slate-400 mb-4">Aggregated from endpoint telemetry events such as AI tool process detection and AI service connections.</div>
        ${tableWrap(
          th("Host") + th("Tool / Service") + th("User") + th("Severity") + th("Events") + th("First Seen") + th("Last Seen"),
          rows || `<tr><td colspan="7">${emptyState("No shadow AI detections yet. Endpoint agents need to post telemetry to the control plane.")}</td></tr>`
        )}
      `)}
      <div class="mt-4">
        ${card(`
          <div class="font-semibold mb-3">Recent Endpoint AI Events</div>
          ${tableWrap(
            th("Time") + th("Host") + th("Tool / Service") + th("Severity") + th("Event Type") + th("Summary") + th("Why This Severity"),
            recentRows || `<tr><td colspan="7">${emptyState("No recent endpoint AI events")}</td></tr>`
          )}
        `)}
      </div>
    `;

    $("#shadowAiRefreshBtn")?.addEventListener("click", viewShadowAi);
  } catch (e) {
    app.innerHTML = card(`<div class="text-rose-400">Error loading shadow AI: ${esc(e.message)}</div>`);
  }
}

// ---------- Compliance ----------
async function viewCompliance() {
  const app = $("#app");
  app.innerHTML = loading();

  const frameworks = [
    { id: "nist-csf", name: "NIST CSF 2.0", category: "Federal" },
    { id: "nist-800-53", name: "NIST 800-53 Rev 5", category: "Federal" },
    { id: "nist-ai-rmf", name: "NIST AI RMF 1.0", category: "AI" },
    { id: "cmmc-l3", name: "CMMC Level 3", category: "Defense" },
    { id: "pci-dss", name: "PCI-DSS v4.0", category: "Financial" },
    { id: "soc2", name: "SOC 2 Type II", category: "Trust" },
    { id: "gdpr", name: "EU GDPR", category: "Privacy" },
    { id: "ccpa", name: "CCPA/CPRA", category: "Privacy" },
    { id: "iso27001", name: "ISO 27001:2022", category: "International" },
    { id: "cis-controls", name: "CIS Controls v8", category: "Best Practice" },
    { id: "csa-ccm", name: "CSA CCM v4", category: "Cloud" },
    { id: "owasp", name: "OWASP Combined", category: "AppSec" },
    { id: "sans-top25", name: "SANS/CWE Top 25", category: "Vulnerability" },
    { id: "nydfs", name: "NYDFS 23 NYCRR 500", category: "Financial" },
  ];

  const frameworkCards = frameworks.map(f => `
    <div class="view-card rounded-xl border border-slate-800 bg-slate-900/50 p-4 hover:bg-slate-900">
      <div class="flex items-center justify-between mb-2">
        <div class="font-semibold text-sm">${esc(f.name)}</div>
        ${badge(f.category, "cyan")}
      </div>
      <div class="flex items-center gap-2 mb-3">
        <div class="flex-1 h-2 rounded-full bg-slate-800"><div class="h-2 rounded-full bg-indigo-500" style="width: 0%"></div></div>
        <span class="text-xs text-slate-400">—%</span>
      </div>
      <button class="text-xs px-3 py-1.5 rounded-lg bg-indigo-900/40 text-indigo-200 border border-indigo-900" data-assess="${f.id}">Run Assessment</button>
    </div>
  `).join("");

  app.innerHTML = `
    <div class="mb-6">${card(`
      <div class="flex items-center justify-between mb-4">
        <div class="font-semibold">Compliance Frameworks (${frameworks.length})</div>
        <button id="assessAll" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">Assess All</button>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">${frameworkCards}</div>
    `)}</div>
  `;

  $$("[data-assess]").forEach(btn => {
    btn.onclick = async () => {
      const fwId = btn.dataset.assess;
      toast(`Running ${fwId} assessment...`);
      try {
        const r = await apiFetch(`${svcUrl("compliance")}/assess/${getTenant()}`, {
          method: "POST", headers: svcHeaders("compliance"),
          body: JSON.stringify({ framework: fwId }),
        });
        toast(`${fwId}: ${r.controls_passed||0}/${r.controls_assessed||0} passed`, "success");
      } catch (e) { toast(e.message, "error"); }
    };
  });

  const assessAllBtn = $("#assessAll");
  if (assessAllBtn) assessAllBtn.onclick = () => {
    frameworks.forEach(f => {
      const btn = $(`[data-assess="${f.id}"]`);
      if (btn) btn.click();
    });
  };
}

// ---------- SIEM Config ----------
function viewSiem() {
  const app = $("#app");
  const siemTypes = [
    { id: "splunk", name: "Splunk", fields: ["hec_url", "hec_token", "index", "source_type"] },
    { id: "sentinel", name: "Microsoft Sentinel", fields: ["workspace_id", "shared_key", "log_type"] },
    { id: "qradar", name: "IBM QRadar", fields: ["syslog_host", "syslog_port", "api_url", "api_token"] },
    { id: "elastic", name: "Elastic SIEM", fields: ["elasticsearch_url", "api_key", "index_prefix"] },
    { id: "google_secops", name: "Google SecOps", fields: ["customer_id", "credentials_json", "region"] },
    { id: "syslog_cef", name: "Syslog / CEF", fields: ["host", "port", "protocol", "facility"] },
  ];

  const siemCards = siemTypes.map(s => `
    <div class="view-card rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <div class="font-semibold text-sm mb-3">${esc(s.name)}</div>
      ${s.fields.map(f => `
        <div class="mb-2">
          <label class="text-xs text-slate-400">${esc(f)}</label>
          <input class="w-full mt-1 px-3 py-1.5 text-sm rounded-lg bg-slate-900 border border-slate-800" placeholder="${esc(f)}" data-siem="${s.id}" data-siem-field="${f}" />
        </div>
      `).join("")}
      <div class="flex gap-2 mt-3">
        <button class="text-xs px-3 py-1.5 rounded-lg bg-emerald-900/40 text-emerald-200 border border-emerald-900" data-siem-test="${s.id}">Test</button>
        <button class="text-xs px-3 py-1.5 rounded-lg bg-indigo-900/40 text-indigo-200 border border-indigo-900" data-siem-save="${s.id}">Save</button>
      </div>
    </div>
  `).join("");

  app.innerHTML = card(`
    <div class="font-semibold mb-4">SIEM Integrations</div>
    <div class="text-xs text-slate-400 mb-4">Configure one or more SIEM outputs. Events will be forwarded in real-time.</div>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">${siemCards}</div>
  `);
}

// ---------- Identity / SSO ----------
function viewIdentity() {
  const app = $("#app");
  const providers = [
    { id: "entra", name: "Microsoft Entra ID", fields: ["tenant_id", "client_id", "client_secret", "authority"] },
    { id: "okta", name: "Okta", fields: ["domain", "api_token"] },
    { id: "ping", name: "Ping Identity", fields: ["environment_id", "client_id", "client_secret"] },
    { id: "aws_iam", name: "AWS IAM Identity Center", fields: ["instance_arn", "region", "access_key", "secret_key"] },
  ];

  const providerCards = providers.map(p => `
    <div class="view-card rounded-xl border border-slate-800 bg-slate-900/50 p-4">
      <div class="flex items-center justify-between mb-3">
        <div class="font-semibold text-sm">${esc(p.name)}</div>
        ${badge("Not Connected","slate")}
      </div>
      ${p.fields.map(f => `
        <div class="mb-2">
          <label class="text-xs text-slate-400">${esc(f)}</label>
          <input class="w-full mt-1 px-3 py-1.5 text-sm rounded-lg bg-slate-900 border border-slate-800" placeholder="${esc(f)}" type="${f.includes("secret")||f.includes("key")||f.includes("token")?"password":"text"}" />
        </div>
      `).join("")}
      <div class="flex gap-2 mt-3">
        <button class="text-xs px-3 py-1.5 rounded-lg bg-emerald-900/40 text-emerald-200 border border-emerald-900">Test Connection</button>
        <button class="text-xs px-3 py-1.5 rounded-lg bg-indigo-900/40 text-indigo-200 border border-indigo-900">Save</button>
      </div>
    </div>
  `).join("");

  app.innerHTML = card(`
    <div class="font-semibold mb-4">Identity Provider Configuration</div>
    <div class="text-xs text-slate-400 mb-4">Configure SSO/identity providers. The system works without any provider (local API key auth) or with multiple providers simultaneously.</div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">${providerCards}</div>
  `);
}

// ---------- DLP & Data Classification ----------
function viewDlp() {
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      ${card(`
        <div class="font-semibold mb-3">Data Classification Labels</div>
        <div class="text-xs text-slate-400 mb-3">Default classification levels. Custom labels override auto-detection.</div>
        <div class="space-y-2">
          ${[
            { label: "PUBLIC", color: "green", desc: "No restrictions" },
            { label: "INTERNAL", color: "slate", desc: "Internal use only" },
            { label: "CONFIDENTIAL", color: "amber", desc: "Business sensitive" },
            { label: "RESTRICTED", color: "red", desc: "Highly sensitive (PII, PHI, PCI)" },
          ].map(l => `
            <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900">
              <div class="flex items-center gap-2">${badge(l.label, l.color)}<span class="text-xs text-slate-400">${l.desc}</span></div>
            </div>
          `).join("")}
        </div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Custom Classification Rules</div>
        <div class="text-xs text-slate-400 mb-3">Override auto-classification for specific patterns or file paths.</div>
        <div class="space-y-2">
          <div class="flex gap-2">
            <input id="dlpPattern" class="flex-1 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="Pattern (regex or path glob)" />
            <select id="dlpLabel" class="px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm">
              <option>PUBLIC</option><option>INTERNAL</option><option selected>CONFIDENTIAL</option><option>RESTRICTED</option>
            </select>
            <button id="addDlpRule" class="px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Add</button>
          </div>
        </div>
        <div id="dlpRules" class="mt-3 space-y-1"></div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">DLP Detection Patterns</div>
        <div class="space-y-1 text-xs">
          ${["SSN","Credit Card","Email","Phone","AWS Key","GitHub Token","JWT","API Key","Private Key","IP Address","IBAN","Passport"].map(p =>
            `<div class="flex items-center justify-between p-2 rounded-lg bg-slate-900"><span>${p}</span>${badge("Active","green")}</div>`
          ).join("")}
        </div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Scan Content</div>
        <textarea id="dlpScanInput" rows="4" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-sm" placeholder="Paste content to classify..."></textarea>
        <button id="runDlpScan" class="mt-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Classify</button>
        <div id="dlpScanResult" class="mt-3"></div>
      `)}
    </div>
  `;
}

// ---------- Incidents ----------
async function viewIncidents() {
  const app = $("#app");
  app.innerHTML = loading();
  try {
    const incidents = await apiFetch(`${svcUrl("cp")}/incidents/${getTenant()}`, { headers: svcHeaders("cp") });
    const rows = (Array.isArray(incidents) ? incidents : []).map(i => {
      const sev = i.severity || "medium";
      const sevBadge = sev === "critical" ? badge(sev,"red") : sev === "high" ? badge(sev,"amber") : badge(sev,"slate");
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc(i.id||i.request_id||"")}</td>
        <td class="py-2 px-3">${esc(i.type||i.event_type||i.title||"")}</td>
        <td class="py-2 px-3">${sevBadge}</td>
        <td class="py-2 px-3">${badge(i.status||"open", i.status==="resolved"?"green":"amber")}</td>
        <td class="py-2 px-3 text-xs">${esc(i.created_at||i.received_at||"")}</td>
      </tr>`;
    }).join("");
    app.innerHTML = card(`
      <div class="font-semibold mb-4">Incidents</div>
      ${tableWrap(th("ID")+th("Type")+th("Severity")+th("Status")+th("Created"), rows || `<tr><td colspan="5">${emptyState("No incidents")}</td></tr>`)}
    `);
  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Telemetry ----------
function viewTelemetry() {
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
      ${card(`<div class="text-xs text-slate-400 mb-1">Events/min</div><div id="telemetryEventsMin" class="text-2xl font-bold text-indigo-400">—</div>`)}
      ${card(`<div class="text-xs text-slate-400 mb-1">Active Agents</div><div id="telemetryAgents" class="text-2xl font-bold text-emerald-400">—</div>`)}
      ${card(`<div class="text-xs text-slate-400 mb-1">AI Requests/hr</div><div id="telemetryAiReqHr" class="text-2xl font-bold text-cyan-400">—</div>`)}
      ${card(`<div class="text-xs text-slate-400 mb-1">Blocked/hr</div><div id="telemetryBlockedHr" class="text-2xl font-bold text-rose-400">—</div>`)}
    </div>
    ${card(`
      <div class="flex items-center justify-between mb-3">
        <div class="font-semibold">Live Event Stream</div>
        <div id="telemetryLastUpdated" class="text-xs text-slate-500">Updating...</div>
      </div>
      <div class="text-xs text-slate-400 mb-3">Real-time telemetry from all connected endpoints.</div>
      <div id="eventStream" class="h-64 overflow-y-auto bg-slate-900 rounded-xl p-3 font-mono text-xs text-slate-300 space-y-1">
        <div class="text-slate-500">Waiting for events... Connect endpoints and configure telemetry.</div>
      </div>
    `)}
  `;

  const seen = new Set();
  let stream = [];
  let stopped = false;

  const parseTs = (v) => {
    if (typeof v === "number" && Number.isFinite(v)) return v;
    const t = Date.parse(v || "");
    return Number.isFinite(t) ? t : 0;
  };
  const shortTs = (v) => {
    const t = parseTs(v);
    if (!t) return "unknown-time";
    return new Date(t).toLocaleTimeString();
  };

  const renderStream = () => {
    const box = $("#eventStream");
    if (!box) return;
    if (!stream.length) {
      box.innerHTML = `<div class="text-slate-500">Waiting for events... Connect endpoints and configure telemetry.</div>`;
      return;
    }
    box.innerHTML = stream.slice(0, 150).map(e =>
      `<div><span class="text-slate-500">[${esc(shortTs(e.ts))}]</span> <span class="text-cyan-300">${esc(e.source)}</span> ${esc(e.message)}</div>`
    ).join("");
  };

  const updateMetrics = (eventsMin, activeAgents, aiReqHr, blockedHr) => {
    const setText = (id, value) => { const n = $(id); if (n) n.textContent = String(value); };
    setText("#telemetryEventsMin", eventsMin);
    setText("#telemetryAgents", activeAgents);
    setText("#telemetryAiReqHr", aiReqHr);
    setText("#telemetryBlockedHr", blockedHr);
    const stamp = $("#telemetryLastUpdated");
    if (stamp) stamp.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  };

  const refresh = async () => {
    if (stopped) return;
    const tenant = getTenant();
    const cpHeaders = svcHeaders("cp");
    const [agentsRes, auditRes, incidentsRes] = await Promise.allSettled([
      apiFetch(`${svcUrl("cp")}/agents?tenant_id=${encodeURIComponent(tenant)}&limit=200`, { headers: cpHeaders }),
      apiFetch(`${svcUrl("cp")}/audit?tenant_id=${encodeURIComponent(tenant)}&limit=200`, { headers: cpHeaders }),
      apiFetch(`${svcUrl("cp")}/incidents/${encodeURIComponent(tenant)}?limit=200`, { headers: cpHeaders }),
    ]);

    const agents = agentsRes.status === "fulfilled" && Array.isArray(agentsRes.value) ? agentsRes.value : [];
    const logs = auditRes.status === "fulfilled" && Array.isArray(auditRes.value) ? auditRes.value : [];
    const incidents = incidentsRes.status === "fulfilled" && Array.isArray(incidentsRes.value) ? incidentsRes.value : [];

    const now = Date.now();
    const oneMin = now - 60 * 1000;
    const oneHr = now - 60 * 60 * 1000;

    const eventsMin = logs.filter(l => parseTs(l.created_at || l.timestamp) >= oneMin).length;
    const aiReqHr = logs.filter(l => {
      const ts = parseTs(l.created_at || l.timestamp);
      if (ts < oneHr) return false;
      const p = String(l.path || "").toLowerCase();
      const a = String(l.action || "").toLowerCase();
      return p.includes("/ai/") || p.includes("chat/completions") || a.includes("ai");
    }).length;
    const blockedHr = incidents.filter(i => {
      const ts = parseTs(i.received_at || i.created_at || i.ts);
      if (ts < oneHr) return false;
      const d = String(i.decision || "").toLowerCase();
      return d === "block" || d === "deny";
    }).length;
    updateMetrics(eventsMin, agents.length, aiReqHr, blockedHr);

    const nextEntries = [];
    logs.forEach(l => {
      const key = `audit:${l.id || `${l.created_at}:${l.path}:${l.method}`}`;
      if (seen.has(key)) return;
      seen.add(key);
      nextEntries.push({
        key,
        ts: parseTs(l.created_at || l.timestamp),
        source: "audit",
        message: `${(l.method || "GET").toUpperCase()} ${l.path || ""} -> ${l.status || ""} (${l.tenant_id || "n/a"})`,
      });
    });
    agents.forEach(a => {
      const key = `agent:${a.agent_id || a.hostname || "unknown"}:${a.last_seen || ""}`;
      if (seen.has(key)) return;
      seen.add(key);
      nextEntries.push({
        key,
        ts: parseTs(a.last_seen || a.registered_at),
        source: "agent",
        message: `${a.agent_id || "unknown-agent"} heartbeat status=${a.status || "running"} host=${a.hostname || "n/a"}`,
      });
    });
    incidents.forEach(i => {
      const key = `incident:${i.request_id || i.id || `${i.received_at}:${i.event_type}`}`;
      if (seen.has(key)) return;
      seen.add(key);
      nextEntries.push({
        key,
        ts: parseTs(i.received_at || i.created_at || i.ts),
        source: "incident",
        message: `${i.event_type || "runtime_decision"} decision=${i.decision || "unknown"} req=${i.request_id || i.id || "n/a"}`,
      });
    });

    if (nextEntries.length) {
      stream = [...nextEntries, ...stream]
        .sort((a, b) => (b.ts || 0) - (a.ts || 0))
        .slice(0, 250);
      renderStream();
    } else if (!stream.length) {
      renderStream();
    }
  };

  refresh().catch(e => {
    const box = $("#eventStream");
    if (box) box.innerHTML = `<div class="text-rose-400">Telemetry error: ${esc(e.message || String(e))}</div>`;
  });
  const timer = setInterval(() => { refresh().catch(() => {}); }, 4000);
  setViewCleanup(() => { stopped = true; clearInterval(timer); });
}

// ---------- Audit Logs ----------
async function viewAudit() {
  const app = $("#app");
  app.innerHTML = loading();
  try {
    const logs = await apiFetch(`${svcUrl("cp")}/audit?limit=100`, { headers: svcHeaders("cp") });
    const rows = (Array.isArray(logs) ? logs : []).map(l => `
      <tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 text-xs">${esc(l.timestamp||l.created_at||"")}</td>
        <td class="py-2 px-3">${esc(l.tenant_id||"")}</td>
        <td class="py-2 px-3">${esc(l.action||l.event||"")}</td>
        <td class="py-2 px-3 text-xs max-w-xs truncate">${esc(JSON.stringify(l.details||l.metadata||""))}</td>
        <td class="py-2 px-3">${esc(l.user||l.actor||"")}</td>
      </tr>
    `).join("");
    app.innerHTML = card(`
      <div class="flex items-center justify-between mb-4">
        <div class="font-semibold">Audit Logs</div>
        <button id="refreshAudit" class="text-xs px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Refresh</button>
      </div>
      ${tableWrap(th("Timestamp")+th("Tenant")+th("Action")+th("Details")+th("Actor"), rows || `<tr><td colspan="5">${emptyState("No audit logs")}</td></tr>`)}
    `);
    const refreshBtn = $("#refreshAudit");
    if (refreshBtn) refreshBtn.onclick = viewAudit;
  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Reports ----------
function viewReports() {
  const app = $("#app");
  const reportTypes = [
    { id: "executive", name: "Executive Summary", desc: "High-level security posture for leadership" },
    { id: "compliance", name: "Compliance Report", desc: "Framework assessment results and gaps" },
    { id: "incident", name: "Incident Report", desc: "Incident timeline and response actions" },
    { id: "dlp", name: "DLP Activity Report", desc: "Data loss prevention events and trends" },
    { id: "endpoint", name: "Endpoint Health Report", desc: "Agent status and security posture per endpoint" },
    { id: "ai-usage", name: "AI Usage Report", desc: "AI tool usage, prompts monitored, blocked requests" },
    { id: "policy", name: "Policy Effectiveness", desc: "Policy hit rates and coverage analysis" },
    { id: "risk", name: "Risk Assessment", desc: "Aggregated risk scores and recommendations" },
  ];

  app.innerHTML = card(`
    <div class="font-semibold mb-4">Reports</div>
    <div class="text-xs text-slate-400 mb-4">Generate and download security reports.</div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
      ${reportTypes.map(r => `
        <div class="view-card rounded-xl border border-slate-800 bg-slate-900/50 p-4 flex items-center justify-between">
          <div>
            <div class="font-semibold text-sm">${esc(r.name)}</div>
            <div class="text-xs text-slate-400">${esc(r.desc)}</div>
          </div>
          <button class="text-xs px-3 py-1.5 rounded-lg bg-indigo-900/40 text-indigo-200 border border-indigo-900" data-report="${r.id}">Generate</button>
        </div>
      `).join("")}
    </div>
  `);

  $$("[data-report]").forEach(btn => {
    btn.onclick = () => toast(`Generating ${btn.dataset.report} report...`);
  });
}

// ─── AI Identity Control Plane Views ─────────────────────

// ---------- Agent Directory ----------
async function viewAgents() {
  const app = $("#app");
  app.innerHTML = loading();
  const base = svcUrl("agentId");
  const hdrs = svcHeaders("agentId");
  try {
    const resp = await apiFetch(`${base}/agents?tenant_id=${getTenant()}&limit=100`, { headers: hdrs });
    const list = Array.isArray(resp) ? resp : (resp.agents || []);

    const rows = list.map(a => {
      const statusBadge = a.status === "active" ? badge("active","green") : badge(a.status||"unknown","slate");
      const caps = a.capabilities || a.allowed_tools || [];
      const capsBadges  = caps.slice(0,3).map(c => badge(c,"indigo")).join(" ");
      const displayName = a.display_name || a.name || "—";
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc(a.agent_id||a.id||"")}</td>
        <td class="py-2 px-3 font-medium">${esc(displayName)}</td>
        <td class="py-2 px-3">${statusBadge}</td>
        <td class="py-2 px-3">${badge(a.trust_level||"standard","amber")}</td>
        <td class="py-2 px-3">${capsBadges}</td>
        <td class="py-2 px-3 text-xs text-slate-400">${a.created_at ? new Date(a.created_at).toLocaleString() : ""}</td>
        <td class="py-2 px-3">
          <div class="flex gap-1">
            <button class="text-xs px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700" data-agent-token="${esc(a.agent_id||a.id)}">Token</button>
            <button class="text-xs px-2 py-1 rounded-lg bg-rose-900/40 text-rose-200 border border-rose-900" data-agent-delete="${esc(a.agent_id||a.id)}">Revoke</button>
          </div>
        </td>
      </tr>`;
    }).join("");

    app.innerHTML = `
      <div class="flex items-center justify-between mb-4">
        <div class="text-sm text-slate-400">${list.length} agent${list.length !== 1 ? "s" : ""} registered</div>
        <div class="flex gap-2">
          <input id="agentSearch" placeholder="Search agents..." class="text-sm px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 w-48 focus:outline-none focus:ring-2 focus:ring-indigo-600" />
          <button id="registerAgent" class="text-sm px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ Register Agent</button>
        </div>
      </div>
      ${card(`
        <div class="font-semibold mb-3">Agent Registry</div>
        ${tableWrap(
          th("Agent ID")+th("Name")+th("Status")+th("Trust Level")+th("Capabilities")+th("Created")+th("Actions"),
          rows || `<tr><td colspan="7">${emptyState("No agents registered yet")}</td></tr>`
        )}
      `)}
      <div id="agentPanel" class="mt-4"></div>
    `;

    // Live search
    const si = $("#agentSearch");
    if (si) si.oninput = () => {
      const q = si.value.toLowerCase();
      $$("[data-agent-token]").forEach(btn => {
        const row = btn.closest("tr");
        if (row) row.style.display = row.textContent.toLowerCase().includes(q) ? "" : "none";
      });
    };

    // Issue token
    $$("[data-agent-token]").forEach(btn => {
      btn.onclick = async () => {
        const agentId = btn.dataset.agentToken;
        try {
          const tok = await apiFetch(`${base}/agents/${agentId}/tokens/issue`, {
            method: "POST", headers: hdrs,
            body: JSON.stringify({ tenant_id: getTenant(), scopes: ["ai:inference","ai:audit"], expires_in: 3600 })
          });
          const panel = $("#agentPanel");
          if (panel) panel.innerHTML = card(`
            <div class="font-semibold mb-2">Access Token — ${esc(agentId)}</div>
            <pre class="text-xs font-mono bg-slate-900 p-3 rounded-xl overflow-x-auto whitespace-pre-wrap break-all border border-slate-800">${esc(tok.access_token || tok.token || JSON.stringify(tok,null,2))}</pre>
            <div class="mt-2 text-xs text-slate-400">Expires: ${tok.expires_at ? new Date(tok.expires_at).toLocaleString() : "—"} · Scopes: ${(tok.scopes||[]).join(", ")}</div>
          `);
        } catch(e) { toast(e.message, "error"); }
      };
    });

    // Revoke agent
    $$("[data-agent-delete]").forEach(btn => {
      btn.onclick = async () => {
        const agentId = btn.dataset.agentDelete;
        const ok = await confirm("Revoke Agent", `Permanently revoke agent ${agentId}? This cannot be undone.`);
        if (!ok) return;
        try {
          await apiFetch(`${base}/agents/${agentId}`, { method: "DELETE", headers: hdrs });
          toast("Agent revoked", "success");
          viewAgents();
        } catch(e) { toast(e.message, "error"); }
      };
    });

    // Register form
    const regBtn = $("#registerAgent");
    if (regBtn) regBtn.onclick = () => {
      const panel = $("#agentPanel");
      if (!panel) return;
      panel.innerHTML = card(`
        <div class="font-semibold mb-4">Register New Agent</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="space-y-2"><label class="text-xs text-slate-300">Agent Name *</label>
            <input id="ra_name" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="e.g. finance-bot-prod" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Description</label>
            <input id="ra_desc" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="What this agent does" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Trust Level</label>
            <select id="ra_trust" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800">
              <option value="standard">Standard</option><option value="privileged">Privileged</option><option value="restricted">Restricted</option>
            </select></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Max Requests / Min</label>
            <input id="ra_rate" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="100" /></div>
          <div class="space-y-2 md:col-span-2"><label class="text-xs text-slate-300">Capabilities (comma-separated)</label>
            <input id="ra_caps" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="ai:inference, ai:tools, ai:memory, ai:audit" /></div>
        </div>
        <div class="mt-4 flex gap-2">
          <button id="ra_submit" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Register</button>
          <button onclick="document.getElementById('agentPanel').innerHTML=''" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm">Cancel</button>
        </div>
      `);
      const sub = $("#ra_submit");
      if (sub) sub.onclick = async () => {
        const name = $("#ra_name")?.value.trim();
        if (!name) { toast("Agent name required", "error"); return; }
        const caps = ($("#ra_caps")?.value||"").split(",").map(c=>c.trim()).filter(Boolean);
        try {
          const displayName = name;
          const res = await apiFetch(`${base}/agents/register`, {
            method: "POST", headers: hdrs,
            body: JSON.stringify({ tenant_id: getTenant(), name, display_name: displayName,
              owner_team: "dashboard", application: "admin-dashboard",
              description: $("#ra_desc")?.value, trust_level: $("#ra_trust")?.value,
              capabilities: caps, allowed_tools: caps,
              max_requests_per_minute: parseInt($("#ra_rate")?.value||"100") })
          });
          toast(`Agent registered: ${res.agent_id}`, "success");
          viewAgents();
        } catch(e) { toast(e.message, "error"); }
      };
    };
  } catch(e) {
    app.innerHTML = card(`<div class="text-rose-400">Error loading agents: ${esc(e.message)}</div>`);
  }
}

// ---------- AI Provider Management ----------
async function viewProviders() {
  const app = $("#app");
  const PROVIDERS = [
    { id: "openai",     name: "OpenAI",         icon: "🤖", models: ["gpt-4o","gpt-4o-mini","gpt-4-turbo","o1","o3-mini"],                color: "green"  },
    { id: "anthropic",  name: "Anthropic",       icon: "🧠", models: ["claude-opus-4-5","claude-sonnet-4-5","claude-haiku-3-5"],           color: "amber"  },
    { id: "google",     name: "Google AI",       icon: "🔵", models: ["gemini-2.0-flash","gemini-1.5-pro","gemini-1.5-flash"],             color: "cyan"   },
    { id: "amazon",     name: "Amazon Bedrock",  icon: "☁️",  models: ["amazon.titan-text-express-v1","meta.llama3-70b"],                   color: "slate"  },
    { id: "microsoft",  name: "Microsoft Azure", icon: "🪟", models: ["gpt-4o-azure","gpt-35-turbo"],                                      color: "indigo" },
    { id: "xai",        name: "xAI Grok",        icon: "✖️",  models: ["grok-3","grok-3-mini"],                                            color: "slate"  },
    { id: "meta",       name: "Meta LLaMA",      icon: "🦙", models: ["llama-3.3-70b-instruct","llama-3.1-405b"],                         color: "indigo" },
    { id: "perplexity", name: "Perplexity",      icon: "🔍", models: ["sonar-pro","sonar","sonar-reasoning"],                              color: "cyan"   },
  ];

  const base = svcUrl("aiRouter");
  const hdrs = svcHeaders("aiRouter");
  let configuredMap = {};
  try {
    const pl = await apiFetch(`${base}/ai/providers`, { headers: hdrs });
    (pl.providers||[]).forEach(p => { configuredMap[p.id||p.provider] = p; });
  } catch {}

  const providerCards = PROVIDERS.map(p => {
    const cfg = !!configuredMap[p.id];
    return `
      <div class="view-card rounded-2xl border border-slate-800 bg-slate-950 p-5">
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-2">
            <span class="text-2xl">${p.icon}</span>
            <div><div class="font-semibold">${esc(p.name)}</div>
              <div class="text-xs text-slate-400">${p.models.length} models</div></div>
          </div>
          ${cfg ? badge("Configured","green") : badge("Not Configured","slate")}
        </div>
        <div class="text-xs text-slate-400 mb-3">${p.models.slice(0,3).map(m=>`<code class="text-indigo-300 bg-slate-900 px-1 rounded">${esc(m)}</code>`).join(" ")}</div>
        <div class="flex gap-2">
          <button class="flex-1 text-xs py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500" data-configure-provider="${esc(p.id)}" data-provider-name="${esc(p.name)}">${cfg?"Reconfigure":"Configure"}</button>
          ${cfg ? `<button class="text-xs py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700" data-test-provider="${esc(p.id)}">Test</button>` : ""}
        </div>
      </div>`;
  }).join("");

  app.innerHTML = `
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">${providerCards}</div>
    <div id="providerPanel"></div>
  `;

  $$("[data-configure-provider]").forEach(btn => {
    btn.onclick = () => {
      const pid = btn.dataset.configureProvider;
      const pname = btn.dataset.providerName;
      const panel = $("#providerPanel");
      if (!panel) return;
      panel.innerHTML = card(`
        <div class="font-semibold mb-4">Configure ${esc(pname)}</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="space-y-2 md:col-span-2"><label class="text-xs text-slate-300">API Key *</label>
            <input id="prov_key" type="password" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 font-mono text-sm" placeholder="sk-..." /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Base URL (optional)</label>
            <input id="prov_url" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="https://api.example.com/v1" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Default Model</label>
            <input id="prov_model" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="e.g. gpt-4o" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Rate Limit (req/min)</label>
            <input id="prov_rate" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="60" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Monthly Budget ($)</label>
            <input id="prov_budget" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="500" /></div>
        </div>
        <div class="mt-4 flex gap-2">
          <button id="prov_save" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Save Credentials</button>
          <button onclick="document.getElementById('providerPanel').innerHTML=''" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm">Cancel</button>
        </div>
      `);
      const saveBtn = $("#prov_save");
      if (saveBtn) saveBtn.onclick = async () => {
        const apiKey = $("#prov_key")?.value.trim();
        if (!apiKey) { toast("API key required", "error"); return; }
        try {
          await apiFetch(`${base}/credentials/providers/${pid}/configure`, {
            method: "POST", headers: hdrs,
            body: JSON.stringify({ tenant_id: getTenant(), api_key: apiKey,
              base_url: $("#prov_url")?.value||null, default_model: $("#prov_model")?.value||null,
              rate_limit_per_minute: parseInt($("#prov_rate")?.value||"60"),
              monthly_budget_usd: parseFloat($("#prov_budget")?.value||"500") })
          });
          toast(`${pname} configured!`, "success");
          viewProviders();
        } catch(e) { toast(e.message, "error"); }
      };
    };
  });

  $$("[data-test-provider]").forEach(btn => {
    btn.onclick = async () => {
      const orig = btn.textContent;
      btn.textContent = "Testing...";
      try {
        await apiFetch(`${base}/ai/chat/completions`, {
          method: "POST", headers: hdrs,
          body: JSON.stringify({ tenant_id: getTenant(), provider: btn.dataset.testProvider,
            messages: [{ role: "user", content: "Say OK." }], max_tokens: 10 })
        });
        toast(`${btn.dataset.testProvider} connection OK`, "success");
      } catch(e) { toast(`Test failed: ${e.message}`, "error"); }
      btn.textContent = orig;
    };
  });
}

// ---------- Policy Studio (AI-Aware Decision Types) ----------
async function viewPolicyStudio() {
  const app = $("#app");
  app.innerHTML = loading();
  const polBase = svcUrl("pol");
  const polHdrs = svcHeaders("pol");
  const tenant = getTenant();

  const DECISION_TYPES = ["ALLOW","DENY","ALLOW_WITH_REDACTION","ALLOW_WITH_LIMITS","REQUIRE_APPROVAL","ALLOW_WITH_AUDIT_ONLY","QUARANTINE"];
  const DECISION_COLORS = { ALLOW:"green", DENY:"red", ALLOW_WITH_REDACTION:"amber", ALLOW_WITH_LIMITS:"cyan", REQUIRE_APPROVAL:"indigo", ALLOW_WITH_AUDIT_ONLY:"slate", QUARANTINE:"red" };

  function legacyToDecision(action) {
    return { block:"DENY", warn:"ALLOW_WITH_AUDIT_ONLY", monitor:"ALLOW_WITH_AUDIT_ONLY", allow:"ALLOW" }[action] || "ALLOW";
  }
  function policyToDecisionType(policy) {
    if (policy?.ai_decision_type) return policy.ai_decision_type;
    const action = String(policy?.action || "monitor").toLowerCase();
    if (action === "allow") {
      const tags = Array.isArray(policy?.tags) ? policy.tags.map(t => String(t).toLowerCase()) : [];
      const desc = String(policy?.description || "").toLowerCase();
      // Demo/operator hint: policies explicitly marked for redaction should surface as such.
      if (tags.includes("redact") || tags.includes("redaction") || desc.includes("redact")) {
        return "ALLOW_WITH_REDACTION";
      }
    }
    return legacyToDecision(action);
  }
  function riskBar(score) {
    if (score === undefined || score === null) return "—";
    const pct = Math.round(score * 100);
    const col = score > 0.7 ? "bg-rose-500" : score > 0.4 ? "bg-amber-500" : "bg-emerald-500";
    return `<div class="flex items-center gap-2"><div class="w-20 bg-slate-800 rounded-full h-1.5"><div class="${col} h-1.5 rounded-full" style="width:${pct}%"></div></div><span class="text-xs">${pct}%</span></div>`;
  }

  try {
    const policies = await apiFetch(`${polBase}/policies/${tenant}`, { headers: polHdrs });
    const list = Array.isArray(policies) ? policies : [];

    const counts = {};
    DECISION_TYPES.forEach(dt => { counts[dt] = 0; });
    list.forEach(p => { const dt = policyToDecisionType(p); counts[dt] = (counts[dt]||0)+1; });

    const rows = list.map(p => {
      const dt = policyToDecisionType(p);
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-medium text-sm">${esc(p.name||p.id||"")}</td>
        <td class="py-2 px-3">${badge(dt.replace(/_/g," "), DECISION_COLORS[dt]||"slate")}</td>
        <td class="py-2 px-3">${riskBar(p.risk_score)}</td>
        <td class="py-2 px-3">${badge(String(p.priority||0),"slate")}</td>
        <td class="py-2 px-3">${(p.ai_providers||[]).map(pr=>badge(pr,"indigo")).join(" ")||badge("all","slate")}</td>
        <td class="py-2 px-3">${p.enabled !== false ? badge("enabled","green") : badge("disabled","slate")}</td>
        <td class="py-2 px-3">
          <button class="text-xs px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700" data-policy-test="${esc(p.name||p.id)}">Test</button>
        </td>
      </tr>`;
    }).join("");

    app.innerHTML = `
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        ${["ALLOW","DENY","ALLOW_WITH_REDACTION","REQUIRE_APPROVAL"].map(dt =>
          metricCard(dt.replace(/_/g," "), counts[dt]||0, DECISION_COLORS[dt]||"slate")
        ).join("")}
      </div>
      ${card(`
        <div class="flex items-center justify-between mb-4">
          <div class="font-semibold">AI-Aware Policies — ${esc(tenant)}</div>
          <a href="#/policy-builder" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ New Policy</a>
        </div>
        ${tableWrap(
          th("Name")+th("Decision Type")+th("Risk Score")+th("Priority")+th("AI Providers")+th("Status")+th("Test"),
          rows || `<tr><td colspan="7">${emptyState("No policies found")}</td></tr>`
        )}
      `)}
      <div id="policyTestPanel" class="mt-4"></div>
    `;

    $$("[data-policy-test]").forEach(btn => {
      btn.onclick = () => {
        const pname = btn.dataset.policyTest;
        const panel = $("#policyTestPanel");
        if (!panel) return;
        panel.innerHTML = card(`
          <div class="font-semibold mb-4">Evaluate Policy: ${esc(pname)}</div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="space-y-2"><label class="text-xs text-slate-300">Provider</label>
              <select id="pt_prov" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800">
                <option>openai</option><option>anthropic</option><option>google</option><option>xai</option><option>perplexity</option>
              </select></div>
            <div class="space-y-2"><label class="text-xs text-slate-300">Model</label>
              <input id="pt_model" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="gpt-4o" /></div>
            <div class="space-y-2 md:col-span-2"><label class="text-xs text-slate-300">Test Prompt</label>
              <textarea id="pt_prompt" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 h-24 resize-none" placeholder="Enter a prompt to evaluate against this policy..."></textarea></div>
          </div>
          <div class="mt-4 flex gap-2">
            <button id="pt_run" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Evaluate</button>
          </div>
          <div id="pt_result" class="mt-4"></div>
        `);
        const runBtn = $("#pt_run");
        if (runBtn) runBtn.onclick = async () => {
          try {
            const res = await apiFetch(`${polBase}/policies/${tenant}/evaluate`, {
              method: "POST", headers: polHdrs,
              body: JSON.stringify({ policy_name: pname, context: {
                provider: $("#pt_prov")?.value, model: $("#pt_model")?.value,
                prompt: $("#pt_prompt")?.value, tenant_id: tenant }})
            });
            const el = $("#pt_result");
            if (el) el.innerHTML = `<div class="p-4 rounded-xl border ${res.allowed !== false ? 'border-emerald-900 bg-emerald-900/20' : 'border-rose-900 bg-rose-900/20'}">
              <div class="font-semibold mb-2">${res.allowed !== false ? '✓ Allowed' : '✗ Denied'}</div>
              <pre class="text-xs font-mono overflow-x-auto">${esc(JSON.stringify(res,null,2))}</pre></div>`;
          } catch(e) { toast(e.message, "error"); }
        };
      };
    });
  } catch(e) {
    app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`);
  }
}

// ---------- Action Graph ----------
async function viewGraph() {
  const app = $("#app");
  app.innerHTML = loading();
  const base = svcUrl("auditGraph");
  const hdrs = svcHeaders("auditGraph");
  try {
    const evResp = await apiFetch(`${base}/events?tenant_id=${getTenant()}&limit=200`, { headers: hdrs });
    const events = Array.isArray(evResp) ? evResp : (evResp.events||[]);

    const nodeMap = {};
    const edges = [];
    events.forEach(ev => {
      const aid = ev.agent_id, model = ev.model||(ev.details?.model),
            tool = ev.details?.tool_name, hid = ev.human_id||(ev.details?.human_id);
      if (aid)   nodeMap[aid]   = { id: aid,   type: "agent",  color: "#6366f1" };
      if (model) nodeMap[model] = { id: model, type: "model",  color: "#06b6d4" };
      if (tool)  nodeMap[tool]  = { id: tool,  type: "tool",   color: "#f59e0b" };
      if (hid)   nodeMap[hid]   = { id: hid,   type: "human",  color: "#10b981" };
      if (aid && model) edges.push({ from: aid,   to: model, label: actionText(ev.action) || "call", ts: ev.timestamp });
      if (aid && tool)  edges.push({ from: aid,   to: tool,  label: "invoke",             ts: ev.timestamp });
      if (hid && aid)   edges.push({ from: hid,   to: aid,   label: "delegate",           ts: ev.timestamp });
    });

    const nodes = Object.values(nodeMap);
    const W = 800, H = 480, cx = W/2, cy = H/2;
    const posMap = {};
    nodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1) - Math.PI/2;
      const r = Math.min(W, H) * 0.36;
      posMap[n.id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    });

    const ICONS = { agent:"🤖", model:"🧠", tool:"🔧", human:"👤" };
    const svgEdges = edges.slice(0,60).map(e => {
      const f = posMap[e.from], t = posMap[e.to];
      if (!f || !t) return "";
      return `<line x1="${f.x}" y1="${f.y}" x2="${t.x}" y2="${t.y}" stroke="#334155" stroke-width="1.2" marker-end="url(#arrow)" />
        <text x="${(f.x+t.x)/2}" y="${(f.y+t.y)/2-4}" fill="#475569" font-size="9" text-anchor="middle">${esc(e.label)}</text>`;
    }).join("");

    const svgNodes = nodes.map(n => {
      const p = posMap[n.id];
      if (!p) return "";
      return `<g transform="translate(${p.x},${p.y})">
        <circle r="22" fill="${n.color}" fill-opacity="0.18" stroke="${n.color}" stroke-width="1.5"/>
        <text y="6" text-anchor="middle" font-size="15">${ICONS[n.type]||"⬤"}</text>
        <text y="38" text-anchor="middle" fill="#94a3b8" font-size="9" font-family="monospace">${esc(n.id.slice(0,16))}</text>
      </g>`;
    }).join("");

    const agentCnt = nodes.filter(n=>n.type==="agent").length;
    const modelCnt = nodes.filter(n=>n.type==="model").length;
    const toolCnt  = nodes.filter(n=>n.type==="tool").length;

    app.innerHTML = `
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
        ${metricCard("Agents",  agentCnt, "indigo")}
        ${metricCard("Models",  modelCnt, "cyan")}
        ${metricCard("Tools",   toolCnt,  "amber")}
        ${metricCard("Edges",   edges.length, "slate")}
      </div>
      ${card(`
        <div class="flex items-center justify-between mb-3">
          <div class="font-semibold">Agent Action Graph</div>
          <div class="flex items-center gap-3 text-xs text-slate-400">
            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-indigo-500 inline-block"></span>Agent</span>
            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-cyan-500 inline-block"></span>Model</span>
            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-amber-500 inline-block"></span>Tool</span>
            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-emerald-500 inline-block"></span>Human</span>
          </div>
        </div>
        ${nodes.length > 0 ? `
          <div class="overflow-x-auto">
            <svg viewBox="0 0 ${W} ${H}" style="width:100%;min-height:340px;background:#0f172a;border-radius:12px;">
              <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569"/></marker></defs>
              ${svgEdges}${svgNodes}
            </svg>
          </div>` : emptyState("No graph data yet — start emitting audit events via the SDK")}
      `)}
      ${card(`
        <div class="font-semibold mb-3">Recent Actions (${Math.min(edges.length,25)} of ${edges.length})</div>
        ${tableWrap(
          th("From")+th("To")+th("Action")+th("Timestamp"),
          edges.slice(0,25).map(e=>`<tr class="hover:bg-slate-900/50">
            <td class="py-2 px-3 font-mono text-xs">${esc(e.from.slice(0,22))}</td>
            <td class="py-2 px-3 font-mono text-xs">${esc(e.to.slice(0,22))}</td>
            <td class="py-2 px-3">${badge(e.label||"call","slate")}</td>
            <td class="py-2 px-3 text-xs text-slate-400">${e.ts ? new Date(e.ts).toLocaleString() : "—"}</td>
          </tr>`).join("") || `<tr><td colspan="4">${emptyState("No actions yet")}</td></tr>`
        )}
      `,"mt-4")}
    `;
  } catch(e) {
    app.innerHTML = card(`<div class="text-rose-400">Error loading graph: ${esc(e.message)}</div>`);
  }
}

// ---------- AI Risk Dashboard ----------
async function viewRisk() {
  const app = $("#app");
  app.innerHTML = loading();
  const base = svcUrl("auditGraph");
  const hdrs = svcHeaders("auditGraph");
  try {
    const evResp = await apiFetch(`${base}/events?tenant_id=${getTenant()}&limit=500`, { headers: hdrs });
    const events = Array.isArray(evResp) ? evResp : (evResp.events||[]);

    const agentRisk = {};
    let blocked = 0, highRisk = 0;
    events.forEach(ev => {
      const aid = ev.agent_id || "unknown";
      if (!agentRisk[aid]) agentRisk[aid] = { events: 0, blocked: 0, riskSum: 0 };
      agentRisk[aid].events++;
      const rs = ev.risk_score || ev.details?.risk_score || 0;
      agentRisk[aid].riskSum += rs;
      if (ev.blocked || isBlockAction(ev.action)) { agentRisk[aid].blocked++; blocked++; }
      if (rs > 0.7) highRisk++;
    });

    const avgRisk = events.length > 0
      ? events.reduce((s,e) => s + (e.risk_score||e.details?.risk_score||0), 0) / events.length : 0;

    function riskGauge(score) {
      const pct = Math.round(score * 100);
      const col = score > 0.7 ? "bg-rose-500" : score > 0.4 ? "bg-amber-500" : "bg-emerald-500";
      return `<div class="flex items-center gap-2">
        <div class="flex-1 bg-slate-800 rounded-full h-2"><div class="${col} h-2 rounded-full" style="width:${pct}%"></div></div>
        <span class="text-xs font-mono w-8 text-right">${pct}%</span>
      </div>`;
    }

    const agentRows = Object.entries(agentRisk)
      .sort(([,a],[,b]) => (b.riskSum/b.events)-(a.riskSum/a.events)).slice(0,10)
      .map(([id, r]) => {
        const avg = r.events ? r.riskSum/r.events : 0;
        return `<tr class="hover:bg-slate-900/50">
          <td class="py-2 px-3 font-mono text-xs">${esc(id.slice(0,26))}</td>
          <td class="py-2 px-3 w-36">${riskGauge(avg)}</td>
          <td class="py-2 px-3 text-center text-sm">${r.events}</td>
          <td class="py-2 px-3 text-center">${r.blocked > 0 ? `<span class="text-rose-400">${r.blocked}</span>` : "0"}</td>
        </tr>`;
      }).join("");

    const highRiskItems = events.filter(e => (e.risk_score||e.details?.risk_score||0) > 0.5).slice(0,8)
      .map(e => `
        <div class="flex items-start gap-3 p-3 rounded-xl border border-slate-800 bg-slate-900/40">
          <span class="text-lg">${e.blocked ? "🚫" : "⚠️"}</span>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-medium">${esc(e.action||e.event_type||"unknown")}</div>
            <div class="text-xs text-slate-400 truncate">${esc(e.agent_id||"—")} → ${esc(e.model||e.details?.model||"—")}</div>
            <div class="text-xs text-slate-500">${e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</div>
          </div>
          ${badge(Math.round(((e.risk_score||e.details?.risk_score||0))*100)+"%", (e.risk_score||0)>0.7?"red":"amber")}
        </div>`
      ).join("") || emptyState("No high-risk events detected — system is clean ✓");

    const recs = [];
    if (blocked > 5)       recs.push(`<div class="flex items-start gap-2 p-3 rounded-xl border border-rose-900/50 bg-rose-900/10"><span>🚨</span><div class="text-sm">${blocked} blocked actions detected. Review agent capabilities and tighten policies.</div></div>`);
    if (avgRisk > 0.5)     recs.push(`<div class="flex items-start gap-2 p-3 rounded-xl border border-amber-900/50 bg-amber-900/10"><span>⚠️</span><div class="text-sm">Average risk ${(avgRisk*100).toFixed(0)}% is elevated. Consider enabling REQUIRE_APPROVAL for high-risk agents.</div></div>`);
    if (events.length===0) recs.push(`<div class="flex items-start gap-2 p-3 rounded-xl border border-slate-800 bg-slate-900/50"><span>ℹ️</span><div class="text-sm">No audit events yet. Integrate the CyberArmor SDK to start monitoring AI actions.</div></div>`);
    if (avgRisk<=0.3 && events.length>0) recs.push(`<div class="flex items-start gap-2 p-3 rounded-xl border border-emerald-900/50 bg-emerald-900/10"><span>✅</span><div class="text-sm">Risk posture is healthy. Average risk ${(avgRisk*100).toFixed(0)}%. Continue monitoring.</div></div>`);

    app.innerHTML = `
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        ${metricCard("Avg Risk Score", (avgRisk*100).toFixed(1)+"%", avgRisk>0.7?"red":avgRisk>0.4?"amber":"green")}
        ${metricCard("Total Events",   events.length, "slate")}
        ${metricCard("Blocked Actions",blocked, blocked>0?"red":"green")}
        ${metricCard("High-Risk Events",highRisk, highRisk>0?"amber":"green")}
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        ${card(`<div class="font-semibold mb-3">Agent Risk Scores</div>
          ${Object.keys(agentRisk).length > 0
            ? tableWrap(th("Agent")+th("Risk")+th("Events")+th("Blocked"), agentRows)
            : emptyState("No agent data yet")}`)}
        ${card(`<div class="font-semibold mb-3">High-Risk Events</div><div class="space-y-2">${highRiskItems}</div>`)}
      </div>
      ${card(`<div class="font-semibold mb-3">Recommendations</div><div class="space-y-2">${recs.join("")||emptyState("No recommendations")}</div>`,"mt-4")}
    `;
  } catch(e) {
    app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`);
  }
}

// ---------- Delegation Manager ----------
async function viewDelegations() {
  const app = $("#app");
  app.innerHTML = loading();
  const base = svcUrl("agentId");
  const hdrs = svcHeaders("agentId");
  try {
    const resp = await apiFetch(`${base}/delegations?tenant_id=${getTenant()}&limit=100`, { headers: hdrs });
    const list = Array.isArray(resp) ? resp : (resp.delegations||[]);

    const rows = list.map(d => {
      const exp = d.expires_at ? new Date(d.expires_at) : null;
      const expired = exp && exp < new Date();
      const sb = d.revoked ? badge("revoked","red") : expired ? badge("expired","amber") : badge("active","green");
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc((d.chain_id||d.id||"").slice(0,22))}</td>
        <td class="py-2 px-3 font-mono text-xs">${esc((d.delegator_id||"").slice(0,20))}</td>
        <td class="py-2 px-3 font-mono text-xs">${esc((d.delegate_id||"").slice(0,20))}</td>
        <td class="py-2 px-3 text-xs">${(d.scopes||[]).map(s=>badge(s,"indigo")).join(" ")}</td>
        <td class="py-2 px-3 text-xs text-slate-400">${exp ? exp.toLocaleString() : "—"}</td>
        <td class="py-2 px-3">${sb}</td>
        <td class="py-2 px-3">
          ${!d.revoked && !expired
            ? `<button class="text-xs px-2 py-1 rounded-lg bg-rose-900/40 text-rose-200 border border-rose-900" data-revoke-delegation="${esc(d.chain_id||d.id)}">Revoke</button>`
            : ""}
        </td>
      </tr>`;
    }).join("");

    app.innerHTML = `
      ${card(`
        <div class="flex items-center justify-between mb-4">
          <div class="font-semibold">Delegation Chains</div>
          <button id="createDelegation" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ New Delegation</button>
        </div>
        ${tableWrap(
          th("Chain ID")+th("Delegator")+th("Delegate")+th("Scopes")+th("Expires")+th("Status")+th(""),
          rows || `<tr><td colspan="7">${emptyState("No delegations yet")}</td></tr>`
        )}
      `)}
      <div id="delegationPanel" class="mt-4"></div>
    `;

    $$("[data-revoke-delegation]").forEach(btn => {
      btn.onclick = async () => {
        const cid = btn.dataset.revokeDelegation;
        const ok = await confirm("Revoke Delegation", `Revoke chain ${cid}?`);
        if (!ok) return;
        try {
          await apiFetch(`${base}/delegations/${cid}`, { method: "DELETE", headers: hdrs });
          toast("Delegation revoked", "success"); viewDelegations();
        } catch(e) { toast(e.message, "error"); }
      };
    });

    const createBtn = $("#createDelegation");
    if (createBtn) createBtn.onclick = () => {
      const panel = $("#delegationPanel");
      if (!panel) return;
      panel.innerHTML = card(`
        <div class="font-semibold mb-4">Create New Delegation</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="space-y-2"><label class="text-xs text-slate-300">Delegator Agent ID *</label>
            <input id="del_from" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 font-mono text-sm" placeholder="agt_..." /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Delegate Agent ID *</label>
            <input id="del_to" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 font-mono text-sm" placeholder="agt_..." /></div>
          <div class="space-y-2 md:col-span-2"><label class="text-xs text-slate-300">Scopes (comma-separated)</label>
            <input id="del_scopes" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="ai:inference" placeholder="ai:inference, ai:tools, ai:memory" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Expires In (hours)</label>
            <input id="del_expires" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="24" /></div>
          <div class="space-y-2"><label class="text-xs text-slate-300">Max Chain Depth</label>
            <input id="del_depth" type="number" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="3" min="1" max="10" /></div>
        </div>
        <div class="mt-4 flex gap-2">
          <button id="del_submit" class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-sm">Create</button>
          <button onclick="document.getElementById('delegationPanel').innerHTML=''" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-sm">Cancel</button>
        </div>
      `);
      const sub = $("#del_submit");
      if (sub) sub.onclick = async () => {
        const from = $("#del_from")?.value.trim(), to = $("#del_to")?.value.trim();
        if (!from || !to) { toast("Both agent IDs required", "error"); return; }
        const scopes = ($("#del_scopes")?.value||"").split(",").map(s=>s.trim()).filter(Boolean);
        try {
          const res = await apiFetch(`${base}/delegations`, {
            method: "POST", headers: hdrs,
            body: JSON.stringify({ tenant_id: getTenant(), delegator_id: from, delegate_id: to,
              scopes, expires_in: parseInt($("#del_expires")?.value||"24") * 3600,
              max_depth: parseInt($("#del_depth")?.value||"3") })
          });
          toast(`Delegation created: ${res.chain_id}`, "success"); viewDelegations();
        } catch(e) { toast(e.message, "error"); }
      };
    };
  } catch(e) {
    app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`);
  }
}

// ---------- SDK & Onboarding ----------
function viewOnboarding() {
  const app = $("#app");
  const SDKs = [
    { lang: "Python",       icon: "🐍", install: "pip install cyberarmor-sdk",                        pkg: "cyberarmor-sdk" },
    { lang: "Node.js / TS", icon: "🟨", install: "npm install @cyberarmor/sdk",                       pkg: "@cyberarmor/sdk" },
    { lang: "Go",           icon: "🔵", install: "go get github.com/cyberarmor-ai/cyberarmor-go",     pkg: "cyberarmor-go" },
    { lang: ".NET / C#",    icon: "🟣", install: "dotnet add package CyberArmor.SDK",                 pkg: "CyberArmor.SDK" },
    { lang: "Java",         icon: "☕", install: "<!-- Add ai.cyberarmor:cyberarmor-sdk to pom.xml -->", pkg: "ai.cyberarmor:cyberarmor-sdk" },
    { lang: "Ruby",         icon: "💎", install: "gem install cyberarmor-sdk",                        pkg: "cyberarmor-sdk" },
    { lang: "PHP",          icon: "🐘", install: "composer require cyberarmor/sdk",                   pkg: "cyberarmor/sdk" },
    { lang: "Rust",         icon: "🦀", install: "cargo add cyberarmor-sdk",                          pkg: "cyberarmor-sdk" },
    { lang: "C / C++",      icon: "⚙️",  install: "# via CMake FetchContent / Conan / vcpkg",          pkg: "libcyberarmor" },
  ];

  const QUICKSTART =
`from cyberarmor import CyberArmorClient
from cyberarmor.providers import CyberArmorOpenAI

# Auto-reads CYBERARMOR_URL / CYBERARMOR_AGENT_ID / CYBERARMOR_AGENT_SECRET
client = CyberArmorClient()

# Drop-in replacement — same API surface as openai.OpenAI()
openai = CyberArmorOpenAI(cyberarmor_client=client)

response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello, world!"}]
)`;

  const FRAMEWORKS = {
    "LangChain (Python)": `from cyberarmor.frameworks.langchain import CyberArmorCallbackHandler
handler = CyberArmorCallbackHandler(client=client)
llm = ChatOpenAI(callbacks=[handler])`,
    "LlamaIndex": `from cyberarmor.frameworks.llamaindex import CyberArmorInstrumentation
CyberArmorInstrumentation.patch_all(client)  # global monkey-patch`,
    "Vercel AI SDK": `import { CyberArmorLanguageModel } from "@cyberarmor/sdk/vercel";
import { openai } from "@ai-sdk/openai";
const model = new CyberArmorLanguageModel({ client, model: openai("gpt-4o") });`,
    "FastAPI Middleware": `from cyberarmor.middleware.fastapi import CyberArmorMiddleware
app.add_middleware(CyberArmorMiddleware, client=client)`,
  };

  const ENV_VARS = [
    { v: "CYBERARMOR_URL",            d: "Agent Identity Service URL",                  def: "http://localhost:8008" },
    { v: "CYBERARMOR_AGENT_ID",       d: "Your registered agent ID",                    def: "agt_..." },
    { v: "CYBERARMOR_AGENT_SECRET",   d: "Agent shared secret (from registration)",     def: "(secret)" },
    { v: "CYBERARMOR_ENFORCE_MODE",   d: "enforce | monitor | off",                     def: "enforce" },
    { v: "CYBERARMOR_FAIL_OPEN",      d: "Allow requests if control plane unreachable", def: "false" },
    { v: "CYBERARMOR_AUDIT_URL",      d: "Audit Graph Service URL",                     def: "http://localhost:8011" },
    { v: "CYBERARMOR_ROUTER_URL",     d: "AI Router Service URL",                       def: "http://localhost:8009" },
    { v: "CYBERARMOR_URL",             d: "Legacy alias for CYBERARMOR_URL",             def: "(same)" },
  ];

  app.innerHTML = `
    <div class="mb-6">
      <div class="font-semibold mb-3">SDK Installation</div>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        ${SDKs.map(s => `
          <div class="view-card rounded-2xl border border-slate-800 bg-slate-950 p-4">
            <div class="flex items-center gap-2 mb-2"><span class="text-xl">${s.icon}</span><div class="font-medium text-sm">${esc(s.lang)}</div></div>
            <code class="block text-xs text-indigo-300 bg-slate-900 px-2 py-1.5 rounded-lg mb-2 font-mono overflow-x-auto">${esc(s.install)}</code>
            <div class="text-xs text-slate-500">${esc(s.pkg)}</div>
          </div>`).join("")}
      </div>
    </div>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
      ${card(`
        <div class="font-semibold mb-3">Python Quickstart</div>
        <pre class="text-xs font-mono bg-slate-900 p-4 rounded-xl overflow-x-auto border border-slate-800 text-emerald-300 leading-relaxed">${esc(QUICKSTART)}</pre>
      `)}
      ${card(`
        <div class="font-semibold mb-3">Framework Integrations</div>
        <div class="space-y-3">
          ${Object.entries(FRAMEWORKS).map(([name, code]) => `
            <div>
              <div class="text-xs font-semibold text-slate-300 mb-1">${esc(name)}</div>
              <pre class="text-xs font-mono bg-slate-900 p-3 rounded-xl overflow-x-auto border border-slate-800 text-emerald-300">${esc(code)}</pre>
            </div>`).join("")}
        </div>
      `)}
    </div>
    ${card(`
      <div class="font-semibold mb-3">Environment Variables</div>
      ${tableWrap(
        th("Variable")+th("Description")+th("Default"),
        ENV_VARS.map(e=>`<tr class="hover:bg-slate-900/50">
          <td class="py-2 px-3 font-mono text-xs text-cyan-300">${esc(e.v)}</td>
          <td class="py-2 px-3 text-xs text-slate-300">${esc(e.d)}</td>
          <td class="py-2 px-3 font-mono text-xs text-slate-400">${esc(e.def)}</td>
        </tr>`).join("")
      )}
    `)}
    ${card(`
      <div class="font-semibold mb-3">Service API Reference</div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        ${[
          { name: "Agent Identity", port: "8008", endpoints: [
            ["POST","green","/agents/register"], ["GET","amber","/agents/{id}"],
            ["POST","green","/agents/{id}/tokens/issue"], ["POST","green","/workloads/attest"],
            ["POST","green","/delegations"], ["GET","amber","/delegations"],
          ]},
          { name: "AI Router", port: "8009", endpoints: [
            ["POST","green","/ai/chat/completions"], ["GET","amber","/ai/models"],
            ["GET","amber","/ai/providers"], ["POST","green","/credentials/providers/{p}/configure"],
            ["POST","green","/credentials/providers/{p}/rotate"],
          ]},
          { name: "Audit Graph", port: "8011", endpoints: [
            ["POST","green","/events"], ["POST","green","/events/batch"],
            ["GET","amber","/events?tenant_id=..."], ["GET","amber","/graph/agent/{id}"],
            ["GET","amber","/traces/{trace_id}"], ["GET","amber","/integrity/verify/{id}"],
          ]},
        ].map(svc => `
          <div class="p-3 rounded-xl bg-slate-900 border border-slate-800">
            <div class="text-sm font-medium mb-1">${esc(svc.name)}</div>
            <div class="text-xs text-slate-400 mb-2">:${svc.port}</div>
            <div class="space-y-1">
              ${svc.endpoints.map(([method, col, path]) =>
                `<div class="text-xs font-mono"><span class="text-${col==="green"?"emerald":"amber"}-400">${method}</span> <span class="text-cyan-300">${esc(path)}</span></div>`
              ).join("")}
            </div>
          </div>`).join("")}
      </div>
    `,"mt-4")}
  `;
}

// ─── Router ──────────────────────────────────────────────
const ROUTES = {
  "overview":       { title: "Overview",           subtitle: "Security posture and operations summary",  fn: viewOverview },
  "tenants":        { title: "Tenants",            subtitle: "Multi-tenant organization management",     fn: viewTenants },
  "policies":       { title: "Policies",           subtitle: "Policy rules and enforcement configuration", fn: viewPolicies },
  "policy-builder": { title: "Policy Builder",     subtitle: "Create policies with AND/OR conditions",   fn: viewPolicyBuilder },
  "api-keys":       { title: "API Keys",           subtitle: "PQC-encrypted key management and rotation", fn: viewApiKeys },
  "proxy":          { title: "Proxy Controls",     subtitle: "URL filtering and AI traffic inspection",  fn: viewProxy },
  "scan":           { title: "Scan Tools",         subtitle: "Prompt injection, PII, and output safety scanning", fn: viewScan },
  "endpoints":      { title: "Endpoints",          subtitle: "Registered agents and extensions",         fn: viewEndpoints },
  "shadow-ai":      { title: "Shadow AI",          subtitle: "AI tools and services detected on endpoints", fn: viewShadowAi },
  "compliance":     { title: "Compliance",         subtitle: "Framework assessments and controls",       fn: viewCompliance },
  "siem":           { title: "SIEM Config",        subtitle: "Security event forwarding configuration",  fn: viewSiem },
  "identity":       { title: "Identity / SSO",     subtitle: "Identity provider and SSO configuration",  fn: viewIdentity },
  "dlp":            { title: "DLP & Data Class.",   subtitle: "Data classification and loss prevention",  fn: viewDlp },
  "incidents":      { title: "Incidents",          subtitle: "Security incident tracking and response",  fn: viewIncidents },
  "telemetry":      { title: "Telemetry",          subtitle: "Real-time event monitoring and metrics",   fn: viewTelemetry },
  "audit":          { title: "Audit Logs",         subtitle: "System audit trail",                       fn: viewAudit },
  "reports":        { title: "Reports",            subtitle: "Generate security and compliance reports",  fn: viewReports },
  // AI Identity Control Plane
  "agents":         { title: "Agent Directory",    subtitle: "Register and manage AI agent identities",   fn: viewAgents },
  "providers":      { title: "AI Providers",       subtitle: "Configure and monitor AI provider credentials", fn: viewProviders },
  "policy-studio":  { title: "Policy Studio",      subtitle: "AI-aware policy decisions and risk scoring", fn: viewPolicyStudio },
  "graph":          { title: "Action Graph",       subtitle: "Visualize agent-to-model action chains",    fn: viewGraph },
  "risk":           { title: "AI Risk Dashboard",  subtitle: "Agent risk scores, threats and recommendations", fn: viewRisk },
  "delegations":    { title: "Delegation Manager", subtitle: "Create and manage agent delegation chains", fn: viewDelegations },
  "onboarding":     { title: "SDK & Onboarding",   subtitle: "Quickstart guides and API reference",       fn: viewOnboarding },
};

function route() {
  clearViewCleanup();
  const hash = location.hash.replace("#/", "") || "overview";
  const r = ROUTES[hash];
  if (!r) { location.hash = "#/overview"; return; }
  $("#pageTitle").textContent = r.title;
  $("#pageSubtitle").textContent = r.subtitle;
  setActiveNav(hash);
  r.fn();
}

// ─── Init ────────────────────────────────────────────────
buildNav();
buildServiceStatus();
buildSettingsFields();
setConnectionLabels();

function setConnectionLabels() {
  $("#tenantScope").value = settings.tenantScope || "";
}

// Settings modal
$("#openSettings").onclick = () => { buildSettingsFields(); $("#settingsModal").classList.remove("hidden"); $("#settingsModal").classList.add("flex"); };
$("#closeSettings").onclick = () => { $("#settingsModal").classList.add("hidden"); $("#settingsModal").classList.remove("flex"); };
$("#saveSettings").onclick = () => {
  SERVICES.forEach(s => {
    settings[s.key+"Url"] = $(`#set_${s.key}Url`)?.value || s.defaultUrl;
    settings[s.key+"Key"] = $(`#set_${s.key}Key`)?.value || s.defaultKey;
  });
  saveSettingsToStorage(settings);
  buildServiceStatus();
  toast("Settings saved", "success");
  $("#settingsModal").classList.add("hidden");
  $("#settingsModal").classList.remove("flex");
};
$("#resetSettings").onclick = () => { settings = { ...DEFAULTS }; saveSettingsToStorage(settings); buildSettingsFields(); toast("Settings reset"); };

// Tenant scope
$("#applyScope").onclick = () => { settings.tenantScope = $("#tenantScope").value.trim(); saveSettingsToStorage(settings); toast(`Tenant: ${settings.tenantScope||"default"}`); route(); };
$("#tenantScope").addEventListener("keydown", e => { if (e.key === "Enter") $("#applyScope").click(); });

// Health ping
$("#pingAll").onclick = pingAll;

// Mobile menu
$("#mobileMenuBtn").onclick = () => {
  const sidebar = $("#sidebar");
  sidebar.classList.toggle("hidden");
  sidebar.classList.toggle("fixed");
  sidebar.classList.toggle("inset-0");
  sidebar.classList.toggle("z-20");
};

// Router
window.addEventListener("hashchange", route);
route();
