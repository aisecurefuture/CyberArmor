// AIShields Protect — Enterprise Admin Dashboard (vanilla JS SPA, no build step)
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
  { id: "compliance",     label: "Compliance",        icon: "✅", hash: "#/compliance" },
  { id: "siem",           label: "SIEM Config",       icon: "📡", hash: "#/siem" },
  { id: "identity",       label: "Identity / SSO",    icon: "🪪", hash: "#/identity" },
  { id: "dlp",            label: "DLP & Data Class.", icon: "🛡️", hash: "#/dlp" },
  { id: "incidents",      label: "Incidents",         icon: "🚨", hash: "#/incidents" },
  { id: "telemetry",      label: "Telemetry",         icon: "📈", hash: "#/telemetry" },
  { id: "audit",          label: "Audit Logs",        icon: "📝", hash: "#/audit" },
  { id: "reports",        label: "Reports",           icon: "📄", hash: "#/reports" },
];

// ─── Service Configuration ───────────────────────────────
const SERVICES = [
  { key: "cp",         name: "Control Plane",    defaultUrl: "http://localhost:8000", defaultKey: "change-me",        healthPath: "/health" },
  { key: "pol",        name: "Policy",           defaultUrl: "http://localhost:8001", defaultKey: "change-me-policy", healthPath: "/health" },
  { key: "det",        name: "Detection",        defaultUrl: "http://localhost:8002", defaultKey: "",                 healthPath: "/health" },
  { key: "rsp",        name: "Response",         defaultUrl: "http://localhost:8003", defaultKey: "",                 healthPath: "/health" },
  { key: "identity",   name: "Identity",         defaultUrl: "http://localhost:8004", defaultKey: "",                 healthPath: "/health" },
  { key: "siem",       name: "SIEM Connector",   defaultUrl: "http://localhost:8005", defaultKey: "",                 healthPath: "/health" },
  { key: "compliance", name: "Compliance",       defaultUrl: "http://localhost:8006", defaultKey: "",                 healthPath: "/health" },
  { key: "px",         name: "Proxy Agent",      defaultUrl: "http://localhost:8010", defaultKey: "change-me-proxy",  healthPath: "/health" },
];

// ─── Settings ────────────────────────────────────────────
function buildDefaults() {
  const d = { tenantScope: "" };
  SERVICES.forEach(s => { d[s.key + "Url"] = s.defaultUrl; d[s.key + "Key"] = s.defaultKey; });
  return d;
}
const DEFAULTS = buildDefaults();

function loadSettings() {
  const raw = localStorage.getItem("aishields_settings");
  return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
}
function saveSettingsToStorage(s) { localStorage.setItem("aishields_settings", JSON.stringify(s)); }
let settings = loadSettings();

// ─── Utilities ───────────────────────────────────────────
function esc(str = "") {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
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
  for (const item of NAV) {
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

  let tenantCount = "—", policyCount = "—", auditCount = "—", alertCount = "—";
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
    alertCount = Array.isArray(audit) ? audit.filter(a => a.action && a.action.includes("block")).length : "?";
  } catch {}

  app.innerHTML = `
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      ${metricCard("Total Tenants", tenantCount, "indigo")}
      ${metricCard("Active Policies", policyCount, "cyan")}
      ${metricCard("Audit Events (24h)", auditCount, "slate")}
      ${metricCard("Blocked Threats", alertCount, "red")}
    </div>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      ${card(`
        <div class="font-semibold mb-3">Quick Actions</div>
        <div class="grid grid-cols-2 gap-2">
          <a href="#/policies" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm">Manage Policies</a>
          <a href="#/policy-builder" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm">Policy Builder</a>
          <a href="#/compliance" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm">Compliance Assessment</a>
          <a href="#/scan" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm">Run Detection Scan</a>
          <a href="#/endpoints" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm">View Endpoints</a>
          <a href="#/siem" class="px-4 py-3 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 text-sm">SIEM Configuration</a>
        </div>
      `)}
      ${card(`
        <div class="font-semibold mb-3">System Information</div>
        <div class="space-y-2 text-sm text-slate-300">
          <div class="flex justify-between"><span>Version</span><span class="text-slate-100">1.0.0</span></div>
          <div class="flex justify-between"><span>Crypto</span>${badge("PQC ML-KEM-1024","indigo")}</div>
          <div class="flex justify-between"><span>Architecture</span>${badge("Zero Trust","green")}</div>
          <div class="flex justify-between"><span>Compliance</span>${badge("NIST CSF","cyan")} ${badge("SOC 2","cyan")} ${badge("GDPR","cyan")}</div>
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
    const policies = await apiFetch(`${svcUrl("pol")}/policies/${tenant}`, { headers: svcHeaders("pol") });
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
        <div class="font-semibold">Policies for ${esc(tenant)}</div>
        <div class="flex gap-2">
          <a href="#/policy-builder" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ New Policy</a>
          <button id="exportPolicies" class="text-xs px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Export JSON</button>
        </div>
      </div>
      ${tableWrap(th("Name")+th("Description")+th("Action")+th("Priority")+th("Status")+th("Frameworks"), rows || `<tr><td colspan="6">${emptyState("No policies")}</td></tr>`)}
    `);

    // Toggle handlers
    $$("[data-toggle-policy]").forEach(btn => {
      btn.onclick = async () => {
        const name = btn.dataset.togglePolicy;
        try {
          await apiFetch(`${svcUrl("pol")}/policies/${tenant}/${name}/toggle`, { method: "PATCH", headers: svcHeaders("pol") });
          toast("Policy toggled", "success");
          viewPolicies();
        } catch (e) { toast(e.message, "error"); }
      };
    });

    // Export
    const expBtn = $("#exportPolicies");
    if (expBtn) expBtn.onclick = async () => {
      try {
        const data = await apiFetch(`${svcUrl("pol")}/policies/${tenant}/export`, { headers: svcHeaders("pol") });
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
        await apiFetch(`${svcUrl("pol")}/policies/${getTenant()}`, {
          method: "POST", headers: svcHeaders("pol"), body: JSON.stringify(json),
        });
        toast("Policy created!", "success");
        location.hash = "#/policies";
      } catch (e) { toast(e.message, "error"); }
    };
  }

  function buildPolicyJson() {
    return {
      name: ($("#pb_name")?.value || "").trim(),
      description: ($("#pb_desc")?.value || "").trim(),
      action: $("#pb_action")?.value || "monitor",
      priority: parseInt($("#pb_priority")?.value || "100"),
      conditions: conditionState,
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
  try {
    const tenant = getTenant();
    const keys = await apiFetch(`${svcUrl("cp")}/api-keys/${tenant}`, { headers: svcHeaders("cp") });
    const rows = (Array.isArray(keys) ? keys : []).map(k => {
      const masked = k.key ? k.key.substring(0,8) + "..." : "***";
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc(k.id||k.key_id||"")}</td>
        <td class="py-2 px-3 font-mono text-xs">${esc(masked)}</td>
        <td class="py-2 px-3">${esc(k.role||k.scope||"")}</td>
        <td class="py-2 px-3">${badge(k.active!==false?"Active":"Revoked", k.active!==false?"green":"red")}</td>
        <td class="py-2 px-3 text-xs">${esc(k.created_at||"")}</td>
        <td class="py-2 px-3 text-xs">${esc(k.expires_at||"Never")}</td>
        <td class="py-2 px-3">
          <button class="text-xs px-2 py-1 rounded-lg bg-amber-900/40 text-amber-200 border border-amber-900" data-rotate-key="${esc(k.id||k.key_id||"")}">Rotate</button>
          <button class="text-xs px-2 py-1 rounded-lg bg-rose-900/40 text-rose-200 border border-rose-900" data-revoke-key="${esc(k.id||k.key_id||"")}">Revoke</button>
        </td>
      </tr>`;
    }).join("");
    app.innerHTML = card(`
      <div class="flex items-center justify-between mb-4">
        <div class="font-semibold">API Keys — ${esc(tenant)}</div>
        <button id="genApiKey" class="text-xs px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">+ Generate Key</button>
      </div>
      <div class="text-xs text-slate-400 mb-4">Keys are PQC-encrypted (ML-KEM-1024) in transit. Rotation replaces the key with a new one.</div>
      ${tableWrap(th("ID")+th("Key")+th("Role")+th("Status")+th("Created")+th("Expires")+th("Actions"), rows || `<tr><td colspan="7">${emptyState("No API keys")}</td></tr>`)}
    `);
  } catch (e) { app.innerHTML = card(`<div class="text-rose-400">Error: ${esc(e.message)}</div>`); }
}

// ---------- Proxy Controls ----------
async function viewProxy() {
  const app = $("#app");
  app.innerHTML = loading();
  try {
    const rules = await apiFetch(`${svcUrl("px")}/rules`, { headers: svcHeaders("px") });
    const rows = (Array.isArray(rules) ? rules : []).map(r => `
      <tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3">${esc(r.pattern||r.url||"")}</td>
        <td class="py-2 px-3">${badge(r.action||"allow", r.action==="deny"?"red":"green")}</td>
        <td class="py-2 px-3 text-xs">${esc(r.reason||"")}</td>
      </tr>
    `).join("");
    app.innerHTML = card(`
      <div class="font-semibold mb-4">Proxy Rules</div>
      ${tableWrap(th("Pattern")+th("Action")+th("Reason"), rows || `<tr><td colspan="3">${emptyState("No rules")}</td></tr>`)}
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
        const r = await apiFetch(`${svcUrl("px")}/decide`, {
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
        method: "POST", headers: { "Content-Type": "application/json" },
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
  app.innerHTML = card(`
    <div class="font-semibold mb-4">Registered Endpoints</div>
    <div class="text-xs text-slate-400 mb-4">Endpoints register via the agent heartbeat. Shows agents, browser extensions, RASP instances, and IDE plugins.</div>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
      ${metricCard("Desktop Agents", "—", "indigo", "macOS / Windows / Linux")}
      ${metricCard("Browser Extensions", "—", "cyan", "Chrome / Firefox / Safari")}
      ${metricCard("RASP Instances", "—", "green", "Java / .NET / Python / Node.js")}
      ${metricCard("IDE Plugins", "—", "amber", "VS Code / Visual Studio")}
    </div>
    ${tableWrap(
      th("Endpoint ID")+th("Type")+th("Platform")+th("Version")+th("Last Seen")+th("Status"),
      `<tr><td colspan="6">${emptyState("Connect endpoints to see them here. Deploy the agent and configure the control plane URL.")}</td></tr>`
    )}
  `);
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
    const incidents = await apiFetch(`${svcUrl("rsp")}/incidents`, { headers: { "Content-Type": "application/json" } });
    const rows = (Array.isArray(incidents) ? incidents : []).map(i => {
      const sev = i.severity || "medium";
      const sevBadge = sev === "critical" ? badge(sev,"red") : sev === "high" ? badge(sev,"amber") : badge(sev,"slate");
      return `<tr class="hover:bg-slate-900/50">
        <td class="py-2 px-3 font-mono text-xs">${esc(i.id||"")}</td>
        <td class="py-2 px-3">${esc(i.type||i.title||"")}</td>
        <td class="py-2 px-3">${sevBadge}</td>
        <td class="py-2 px-3">${badge(i.status||"open", i.status==="resolved"?"green":"amber")}</td>
        <td class="py-2 px-3 text-xs">${esc(i.created_at||"")}</td>
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
      ${metricCard("Events/min", "—", "indigo")}
      ${metricCard("Active Agents", "—", "green")}
      ${metricCard("AI Requests/hr", "—", "cyan")}
      ${metricCard("Blocked/hr", "—", "red")}
    </div>
    ${card(`
      <div class="font-semibold mb-3">Live Event Stream</div>
      <div class="text-xs text-slate-400 mb-3">Real-time telemetry from all connected endpoints.</div>
      <div id="eventStream" class="h-64 overflow-y-auto bg-slate-900 rounded-xl p-3 font-mono text-xs text-slate-300 space-y-1">
        <div class="text-slate-500">Waiting for events... Connect endpoints and configure telemetry.</div>
      </div>
    `)}
  `;
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
  "compliance":     { title: "Compliance",         subtitle: "Framework assessments and controls",       fn: viewCompliance },
  "siem":           { title: "SIEM Config",        subtitle: "Security event forwarding configuration",  fn: viewSiem },
  "identity":       { title: "Identity / SSO",     subtitle: "Identity provider and SSO configuration",  fn: viewIdentity },
  "dlp":            { title: "DLP & Data Class.",   subtitle: "Data classification and loss prevention",  fn: viewDlp },
  "incidents":      { title: "Incidents",          subtitle: "Security incident tracking and response",  fn: viewIncidents },
  "telemetry":      { title: "Telemetry",          subtitle: "Real-time event monitoring and metrics",   fn: viewTelemetry },
  "audit":          { title: "Audit Logs",         subtitle: "System audit trail",                       fn: viewAudit },
  "reports":        { title: "Reports",            subtitle: "Generate security and compliance reports",  fn: viewReports },
};

function route() {
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
