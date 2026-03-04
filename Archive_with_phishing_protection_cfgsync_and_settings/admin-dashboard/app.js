// CyberArmor Admin Dashboard (static, no build step)
// - Configure base URLs + API keys in Settings (localStorage)
// - Uses hash routing (#/overview, #/tenants, #/policies, #/proxy, #/scan, #/audit)

const $ = (sel) => document.querySelector(sel);

const NAV = [
  { id: "overview", label: "Overview", hash: "#/overview" },
  { id: "tenants", label: "Tenants", hash: "#/tenants" },
  { id: "policies", label: "Policies", hash: "#/policies" },
  { id: "proxy", label: "Proxy Controls", hash: "#/proxy" },
  { id: "scan", label: "Scan Tools", hash: "#/scan" },
  { id: "audit", label: "Audit Logs", hash: "#/audit" },
];

const DEFAULTS = {
  cpUrl: "http://localhost:8000",
  cpKey: "change-me",
  polUrl: "http://localhost:8001",
  polKey: "change-me-policy",
  pxUrl: "http://localhost:8010",
  pxKey: "change-me-proxy",
  detUrl: "http://localhost:8002",
  rspUrl: "http://localhost:8003",
  tenantScope: "",
};

function loadSettings() {
  const raw = localStorage.getItem("ca_admin_settings");
  return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
}
function saveSettings(s) {
  localStorage.setItem("ca_admin_settings", JSON.stringify(s));
}
let settings = loadSettings();

function setConnectionLabels() {
  $("#cpLabel").textContent = settings.cpUrl;
  $("#polLabel").textContent = settings.polUrl;
  $("#pxLabel").textContent = settings.pxUrl;
  $("#detLabel").textContent = settings.detUrl;
  $("#rspLabel").textContent = settings.rspUrl;
  $("#tenantScope").value = settings.tenantScope || "";
}

function buildNav() {
  const nav = $("#nav");
  nav.innerHTML = "";
  for (const item of NAV) {
    const a = document.createElement("a");
    a.href = item.hash;
    a.className =
      "block px-3 py-2 rounded-xl text-sm hover:bg-slate-900 border border-transparent hover:border-slate-800";
    a.dataset.nav = item.id;
    a.textContent = item.label;
    nav.appendChild(a);
  }
}

function setActiveNav(routeId) {
  document.querySelectorAll("[data-nav]").forEach((el) => {
    const active = el.dataset.nav === routeId;
    el.classList.toggle("bg-slate-900", active);
    el.classList.toggle("border-slate-800", active);
    el.classList.toggle("text-white", active);
    el.classList.toggle("text-slate-200", !active);
  });
}

function card(childrenHtml) {
  return `
    <div class="rounded-2xl border border-slate-800 bg-slate-950 shadow-sm">
      <div class="p-5">${childrenHtml}</div>
    </div>
  `;
}

function badge(text, tone="slate") {
  const map = {
    slate: "bg-slate-800 text-slate-100 border-slate-700",
    green: "bg-emerald-900/40 text-emerald-200 border-emerald-900",
    red: "bg-rose-900/40 text-rose-200 border-rose-900",
    amber: "bg-amber-900/40 text-amber-200 border-amber-900",
    indigo: "bg-indigo-900/40 text-indigo-200 border-indigo-900",
  };
  return `<span class="inline-flex items-center px-2 py-0.5 rounded-lg text-xs border ${map[tone] || map.slate}">${escapeHtml(text)}</span>`;
}

function escapeHtml(str="") {
  return String(str)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

async function apiFetch(url, { headers = {}, ...opts } = {}) {
  const res = await fetch(url, { ...opts, headers });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!res.ok) {
    const msg = (data && (data.detail || data.message)) ? (data.detail || data.message) : `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}

/* ---------- Service clients ---------- */
const client = {
  cp: {
    health: () => apiFetch(`${settings.cpUrl}/health`),
    tenants: () => apiFetch(`${settings.cpUrl}/tenants`, { headers: cpHeaders() }),
    createTenant: (id, name) => apiFetch(`${settings.cpUrl}/tenants`, {
      method: "POST",
      headers: { ...cpHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ id, name }),
    }),
    audit: (limit=50) => {
      const tenant = settings.tenantScope ? `&tenant_id=${encodeURIComponent(settings.tenantScope)}` : "";
      return apiFetch(`${settings.cpUrl}/audit?limit=${limit}${tenant}`, { headers: cpHeaders() });
    },
    apiKeys: () => apiFetch(`${settings.cpUrl}/apikeys`, { headers: cpHeaders() }),
    createApiKey: (tenant_id, role) => apiFetch(`${settings.cpUrl}/apikeys`, {
      method: "POST",
      headers: { ...cpHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id, role }),
    }),
    disableApiKey: (key) => apiFetch(`${settings.cpUrl}/apikeys/${encodeURIComponent(key)}/disable`, {
      method: "PATCH",
      headers: cpHeaders(),
    }),
  },
  pol: {
    health: () => apiFetch(`${settings.polUrl}/health`),
    listPolicies: (tenant_id) => apiFetch(`${settings.polUrl}/policies/${encodeURIComponent(tenant_id)}`, { headers: polHeaders() }),
    getPolicy: (tenant_id, name) => apiFetch(`${settings.polUrl}/policies/${encodeURIComponent(tenant_id)}/${encodeURIComponent(name)}`, { headers: polHeaders() }),
    upsertPolicy: (tenant_id, name, rules) => apiFetch(`${settings.polUrl}/policies`, {
      method: "POST",
      headers: { ...polHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id, name, rules }),
    }),
  },
  px: {
    health: () => apiFetch(`${settings.pxUrl}/health`),
    refreshPolicy: (tenant_id) => apiFetch(`${settings.pxUrl}/policy/refresh?tenant_id=${encodeURIComponent(tenant_id)}`, { method: "POST", headers: pxHeaders() }),
    decision: (tenant_id, url) => apiFetch(`${settings.pxUrl}/decision`, {
      method: "POST",
      headers: { ...pxHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id, url }),
    }),
    block: (tenant_id, target) => apiFetch(`${settings.pxUrl}/actions/block`, {
      method: "POST",
      headers: { ...pxHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id, target }),
    }),
    blocks: (tenant_id) => apiFetch(`${settings.pxUrl}/blocks/${encodeURIComponent(tenant_id)}`, { headers: pxHeaders() }),
  },
  det: {
    health: () => apiFetch(`${settings.detUrl}/health`),
    scanPrompt: (text) => apiFetch(`${settings.detUrl}/scan/prompt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, tenant_id: settings.tenantScope || null, user_id: null }),
    }),
    scanSensitive: (text) => apiFetch(`${settings.detUrl}/scan/sensitive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    }),
    scanOutput: (text) => apiFetch(`${settings.detUrl}/scan/output`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    }),
  },
  rsp: {
    health: () => apiFetch(`${settings.rspUrl}/health`),
    respond: (incident) => apiFetch(`${settings.rspUrl}/respond`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(incident),
    }),
  },
};

function cpHeaders() {
  const h = { "x-api-key": settings.cpKey };
  if (settings.tenantScope) h["x-tenant-id"] = settings.tenantScope;
  return h;
}
function polHeaders() { return { "x-api-key": settings.polKey }; }
function pxHeaders() { return { "x-api-key": settings.pxKey }; }

/* ---------- Views ---------- */

function setTitle(title, subtitle) {
  $("#pageTitle").textContent = title;
  $("#pageSubtitle").textContent = subtitle;
}

function renderError(err) {
  return `<div class="rounded-2xl border border-rose-900 bg-rose-950/30 p-4 text-rose-200">
    <div class="font-semibold">Request failed</div>
    <div class="text-sm mt-1">${escapeHtml(err.message || String(err))}</div>
  </div>`;
}

async function viewOverview() {
  setTitle("Overview", "At-a-glance system health + quick actions.");
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      ${card(`<div class="flex items-start justify-between">
        <div>
          <div class="text-sm text-slate-400">Control Plane</div>
          <div class="text-lg font-semibold" id="cpHealth">—</div>
        </div>
        ${badge("service","indigo")}
      </div>
      <div class="mt-4 text-xs text-slate-400" id="cpHealthMeta"></div>`)}
      ${card(`<div class="flex items-start justify-between">
        <div>
          <div class="text-sm text-slate-400">Policy Service</div>
          <div class="text-lg font-semibold" id="polHealth">—</div>
        </div>
        ${badge("service","indigo")}
      </div>
      <div class="mt-4 text-xs text-slate-400" id="polHealthMeta"></div>`)}
      ${card(`<div class="flex items-start justify-between">
        <div>
          <div class="text-sm text-slate-400">Proxy Agent</div>
          <div class="text-lg font-semibold" id="pxHealth">—</div>
        </div>
        ${badge("service","indigo")}
      </div>
      <div class="mt-4 text-xs text-slate-400" id="pxHealthMeta"></div>`)}
      ${card(`<div class="flex items-start justify-between">
        <div>
          <div class="text-sm text-slate-400">Detection</div>
          <div class="text-lg font-semibold" id="detHealth">—</div>
        </div>
        ${badge("service","indigo")}
      </div>
      <div class="mt-4 text-xs text-slate-400" id="detHealthMeta"></div>`)}
      ${card(`<div class="flex items-start justify-between">
        <div>
          <div class="text-sm text-slate-400">Response</div>
          <div class="text-lg font-semibold" id="rspHealth">—</div>
        </div>
        ${badge("service","indigo")}
      </div>
      <div class="mt-4 text-xs text-slate-400" id="rspHealthMeta"></div>`)}
      ${card(`<div class="text-sm font-semibold">Quick actions</div>
        <div class="mt-3 space-y-2">
          <button id="qaRefreshPolicy" class="w-full text-sm px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Refresh proxy policy cache</button>
          <button id="qaAudit" class="w-full text-sm px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Load latest audit logs</button>
        </div>
        <div class="mt-3 text-xs text-slate-400" id="qaResult"></div>`)}
    </div>
  `;

  const setOk = (id, data) => {
    $(id).textContent = "OK";
    $(id).className = "text-lg font-semibold text-emerald-300";
    const meta = id + "Meta";
    $(meta).textContent = data?.ts ? `ts: ${data.ts}` : "";
  };
  const setBad = (id, err) => {
    $(id).textContent = "DOWN";
    $(id).className = "text-lg font-semibold text-rose-300";
    const meta = id + "Meta";
    $(meta).textContent = err.message || String(err);
  };

  await Promise.allSettled([
    client.cp.health().then((d)=>setOk("#cpHealth", d)).catch((e)=>setBad("#cpHealth", e)),
    client.pol.health().then((d)=>setOk("#polHealth", d)).catch((e)=>setBad("#polHealth", e)),
    client.px.health().then((d)=>setOk("#pxHealth", d)).catch((e)=>setBad("#pxHealth", e)),
    client.det.health().then((d)=>setOk("#detHealth", d)).catch((e)=>setBad("#detHealth", e)),
    client.rsp.health().then((d)=>setOk("#rspHealth", d)).catch((e)=>setBad("#rspHealth", e)),
  ]);

  $("#qaRefreshPolicy").onclick = async () => {
    const tenant = settings.tenantScope;
    if (!tenant) { $("#qaResult").textContent = "Set a tenant scope in the header first."; return; }
    $("#qaResult").textContent = "Refreshing...";
    try {
      const r = await client.px.refreshPolicy(tenant);
      $("#qaResult").innerHTML = `<span class="text-emerald-300">Cached</span> ${escapeHtml(JSON.stringify(r.policy))}`;
    } catch (e) {
      $("#qaResult").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };
  $("#qaAudit").onclick = async () => {
    $("#qaResult").textContent = "Loading audit...";
    try {
      const logs = await client.cp.audit(10);
      $("#qaResult").innerHTML = `<span class="text-emerald-300">Loaded</span> ${logs.length} audit events.`;
    } catch (e) {
      $("#qaResult").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };
}

async function viewTenants() {
  setTitle("Tenants", "Create tenants and (optionally) scope requests.");
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
      ${card(`
        <div class="text-sm font-semibold">Create tenant</div>
        <div class="mt-3 space-y-2">
          <input id="tId" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="tenant_id (e.g., acme)" />
          <input id="tName" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="Tenant name" />
          <button id="tCreate" class="w-full px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">Create</button>
          <div id="tCreateMsg" class="text-xs mt-1 text-slate-400"></div>
        </div>
      `)}
      ${card(`
        <div class="flex items-center justify-between">
          <div class="text-sm font-semibold">Tenant list</div>
          <button id="tReload" class="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700">Reload</button>
        </div>
        <div class="mt-3 overflow-auto">
          <table class="w-full text-sm">
            <thead class="text-xs text-slate-400">
              <tr><th class="text-left py-2">ID</th><th class="text-left py-2">Name</th><th class="text-left py-2">Active</th><th class="text-left py-2">Scope</th></tr>
            </thead>
            <tbody id="tenantRows" class="divide-y divide-slate-800"></tbody>
          </table>
        </div>
      `)}
      ${card(`
        <div class="text-sm font-semibold">API Keys</div>
        <div class="text-xs text-slate-400 mt-1">Create scoped keys for agents / automation.</div>
        <div class="mt-3 space-y-2">
          <input id="kTenant" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="tenant_id (blank = global)" />
          <select id="kRole" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800">
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
          <button id="kCreate" class="w-full px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Create key</button>
          <div id="kMsg" class="text-xs text-slate-400"></div>
        </div>
        <div class="mt-4">
          <div class="flex items-center justify-between">
            <div class="text-xs text-slate-400">Existing keys</div>
            <button id="kReload" class="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700">Reload</button>
          </div>
          <div class="mt-2 overflow-auto max-h-80">
            <table class="w-full text-sm">
              <thead class="text-xs text-slate-400"><tr><th class="text-left py-2">Key</th><th class="text-left py-2">Role</th><th class="text-left py-2">Tenant</th><th class="text-left py-2">Active</th><th></th></tr></thead>
              <tbody id="keyRows" class="divide-y divide-slate-800"></tbody>
            </table>
          </div>
        </div>
      `)}
    </div>
  `;

  async function loadTenants() {
    $("#tenantRows").innerHTML = `<tr><td class="py-3 text-slate-400" colspan="4">Loading…</td></tr>`;
    try {
      const tenants = await client.cp.tenants();
      $("#tenantRows").innerHTML = tenants.map(t => `
        <tr>
          <td class="py-2 font-mono text-xs">${escapeHtml(t.id)}</td>
          <td class="py-2">${escapeHtml(t.name)}</td>
          <td class="py-2">${t.active ? badge("true","green") : badge("false","red")}</td>
          <td class="py-2">
            <button data-scope="${escapeHtml(t.id)}" class="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700">Set</button>
          </td>
        </tr>
      `).join("");
      document.querySelectorAll("[data-scope]").forEach(btn => {
        btn.onclick = () => {
          settings.tenantScope = btn.dataset.scope;
          saveSettings(settings);
          setConnectionLabels();
          location.hash = "#/overview";
        };
      });
    } catch (e) {
      $("#tenantRows").innerHTML = `<tr><td class="py-3 text-rose-300" colspan="4">${escapeHtml(e.message)}</td></tr>`;
    }
  }

  async function loadKeys() {
    $("#keyRows").innerHTML = `<tr><td class="py-3 text-slate-400" colspan="5">Loading…</td></tr>`;
    try {
      const keys = await client.cp.apiKeys();
      $("#keyRows").innerHTML = keys.map(k => `
        <tr>
          <td class="py-2 font-mono text-xs max-w-[180px] truncate" title="${escapeHtml(k.key)}">${escapeHtml(k.key)}</td>
          <td class="py-2">${escapeHtml(k.role)}</td>
          <td class="py-2">${escapeHtml(k.tenant_id || "")}</td>
          <td class="py-2">${k.active ? badge("active","green") : badge("disabled","amber")}</td>
          <td class="py-2 text-right">
            ${k.active ? `<button data-disable="${escapeHtml(k.key)}" class="text-xs px-2 py-1 rounded-lg bg-rose-900/30 border border-rose-900 text-rose-200 hover:bg-rose-900/50">Disable</button>` : ""}
          </td>
        </tr>
      `).join("");
      document.querySelectorAll("[data-disable]").forEach(btn => {
        btn.onclick = async () => {
          try {
            await client.cp.disableApiKey(btn.dataset.disable);
            await loadKeys();
          } catch (e) {
            alert(e.message);
          }
        };
      });
    } catch (e) {
      $("#keyRows").innerHTML = `<tr><td class="py-3 text-rose-300" colspan="5">${escapeHtml(e.message)}</td></tr>`;
    }
  }

  $("#tCreate").onclick = async () => {
    $("#tCreateMsg").textContent = "Creating…";
    try {
      const id = $("#tId").value.trim();
      const name = $("#tName").value.trim();
      if (!id || !name) throw new Error("Provide both tenant_id and name.");
      await client.cp.createTenant(id, name);
      $("#tCreateMsg").innerHTML = `<span class="text-emerald-300">Created.</span>`;
      $("#tId").value = ""; $("#tName").value = "";
      await loadTenants();
    } catch (e) {
      $("#tCreateMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };
  $("#tReload").onclick = loadTenants;

  $("#kCreate").onclick = async () => {
    $("#kMsg").textContent = "Creating…";
    try {
      const tenant_id = $("#kTenant").value.trim() || null;
      const role = $("#kRole").value;
      const r = await client.cp.createApiKey(tenant_id, role);
      $("#kMsg").innerHTML = `<span class="text-emerald-300">Created:</span> <span class="font-mono text-xs">${escapeHtml(r.key)}</span>`;
      await loadKeys();
    } catch (e) {
      $("#kMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };
  $("#kReload").onclick = loadKeys;

  await loadTenants();
  await loadKeys();
}

async function viewPolicies() {
  setTitle("Policies", "Edit and deploy tenant policies (proxy allowlist rules).");
  const app = $("#app");
  const tenant = settings.tenantScope;
  app.innerHTML = `
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
      ${card(`
        <div class="text-sm font-semibold">Tenant</div>
        <div class="mt-2 text-xs text-slate-400">Policies are per-tenant.</div>
        <div class="mt-3">
          <div class="text-sm">${tenant ? badge(tenant,"indigo") : badge("no tenant selected","amber")}</div>
        </div>
        <div class="mt-4 text-xs text-slate-400">Tip: set tenant scope in the header (top-right).</div>
      `)}
      ${card(`
        <div class="flex items-center justify-between">
          <div class="text-sm font-semibold">Policy list</div>
          <button id="pReload" class="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700">Reload</button>
        </div>
        <div class="mt-3 overflow-auto max-h-96">
          <table class="w-full text-sm">
            <thead class="text-xs text-slate-400"><tr><th class="text-left py-2">Name</th><th class="text-left py-2">Version</th></tr></thead>
            <tbody id="policyRows" class="divide-y divide-slate-800"></tbody>
          </table>
        </div>
      `)}
      ${card(`
        <div class="text-sm font-semibold">Edit policy</div>
        <div class="mt-2 text-xs text-slate-400">Default policy name used by proxy-agent is <span class="font-mono">proxy-default</span>.</div>
        <div class="mt-3 space-y-2">
          <input id="pName" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="proxy-default" />
          <textarea id="pRules" class="w-full h-44 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs" spellcheck="false"></textarea>
          <div class="flex gap-2">
            <button id="pLoad" class="flex-1 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Load</button>
            <button id="pSave" class="flex-1 px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">Save</button>
          </div>
          <div id="pMsg" class="text-xs text-slate-400"></div>
        </div>
      `)}
    </div>
  `;

  $("#pRules").value = JSON.stringify({ allow_hosts: ["openai.com", "api.openai.com"] }, null, 2);

  async function loadList() {
    $("#policyRows").innerHTML = `<tr><td class="py-3 text-slate-400" colspan="2">Loading…</td></tr>`;
    if (!tenant) {
      $("#policyRows").innerHTML = `<tr><td class="py-3 text-amber-200" colspan="2">Set a tenant scope first.</td></tr>`;
      return;
    }
    try {
      const list = await client.pol.listPolicies(tenant);
      $("#policyRows").innerHTML = list.map(p => `
        <tr>
          <td class="py-2">
            <button data-p="${escapeHtml(p.name)}" class="text-left hover:underline">${escapeHtml(p.name)}</button>
          </td>
          <td class="py-2 text-xs text-slate-400">${escapeHtml(p.version)}</td>
        </tr>
      `).join("");
      document.querySelectorAll("[data-p]").forEach(btn => {
        btn.onclick = async () => {
          $("#pName").value = btn.dataset.p;
          await loadPolicy();
        };
      });
    } catch (e) {
      $("#policyRows").innerHTML = `<tr><td class="py-3 text-rose-300" colspan="2">${escapeHtml(e.message)}</td></tr>`;
    }
  }

  async function loadPolicy() {
    $("#pMsg").textContent = "Loading…";
    try {
      if (!tenant) throw new Error("Set a tenant scope first.");
      const name = $("#pName").value.trim();
      const p = await client.pol.getPolicy(tenant, name);
      $("#pRules").value = JSON.stringify(p.rules || {}, null, 2);
      $("#pMsg").innerHTML = `<span class="text-emerald-300">Loaded</span> ${escapeHtml(p.version)}`;
    } catch (e) {
      $("#pMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  }

  $("#pLoad").onclick = loadPolicy;
  $("#pSave").onclick = async () => {
    $("#pMsg").textContent = "Saving…";
    try {
      if (!tenant) throw new Error("Set a tenant scope first.");
      const name = $("#pName").value.trim();
      const rules = JSON.parse($("#pRules").value);
      const saved = await client.pol.upsertPolicy(tenant, name, rules);
      $("#pMsg").innerHTML = `<span class="text-emerald-300">Saved</span> ${escapeHtml(saved.version)}`;
      await loadList();
    } catch (e) {
      $("#pMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };
  $("#pReload").onclick = loadList;

  await loadList();
}

async function viewProxy() {
  setTitle("Proxy Controls", "Evaluate URLs, refresh cache, and manage local blocks.");
  const tenant = settings.tenantScope;
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-4">
      ${card(`
        <div class="text-sm font-semibold">Policy cache</div>
        <div class="mt-2 text-xs text-slate-400">Proxy-agent fetches <span class="font-mono">proxy-default</span> from Policy Service.</div>
        <div class="mt-3">
          <button id="pxRefresh" class="w-full px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">Refresh now</button>
          <div id="pxRefreshMsg" class="text-xs text-slate-400 mt-2"></div>
        </div>
      `)}
      ${card(`
        <div class="text-sm font-semibold">Decision test</div>
        <div class="mt-3 space-y-2">
          <input id="pxUrlTest" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="https://example.com/path" />
          <button id="pxDecide" class="w-full px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Evaluate</button>
          <div id="pxDecisionMsg" class="text-xs text-slate-400"></div>
        </div>
      `)}
      ${card(`
        <div class="text-sm font-semibold">Local blocklist</div>
        <div class="mt-3 space-y-2">
          <input id="pxBlockTarget" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="substring to block (e.g., facebook.com)" />
          <button id="pxBlock" class="w-full px-3 py-2 rounded-xl bg-rose-900/40 hover:bg-rose-900/60 border border-rose-900 text-rose-200">Add block</button>
          <div id="pxBlockMsg" class="text-xs text-slate-400"></div>
        </div>
        <div class="mt-4">
          <div class="flex items-center justify-between">
            <div class="text-xs text-slate-400">Current blocks</div>
            <button id="pxBlocksReload" class="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700">Reload</button>
          </div>
          <div id="pxBlocks" class="mt-2 text-xs text-slate-300 font-mono space-y-1"></div>
        </div>
      `)}
    </div>
  `;

  const ensureTenant = () => {
    if (!tenant) throw new Error("Set a tenant scope first (top-right).");
  };

  async function loadBlocks() {
    $("#pxBlocks").innerHTML = `<div class="text-slate-400">Loading…</div>`;
    try {
      ensureTenant();
      const r = await client.px.blocks(tenant);
      const blocks = Array.isArray(r) ? r : (r.blocks || []);
        $("#pxBlocks").innerHTML = blocks.length
        ? blocks.map(b => `<div class="px-2 py-1 rounded-lg bg-slate-900 border border-slate-800">${escapeHtml(b)}</div>`).join("")
        : `<div class="text-slate-400">No local blocks.</div>`;
    } catch (e) {
      $("#pxBlocks").innerHTML = `<div class="text-rose-300">${escapeHtml(e.message)}</div>`;
    }
  }

  $("#pxRefresh").onclick = async () => {
    $("#pxRefreshMsg").textContent = "Refreshing…";
    try {
      ensureTenant();
      const r = await client.px.refreshPolicy(tenant);
      $("#pxRefreshMsg").innerHTML = `<span class="text-emerald-300">Cached</span> ${escapeHtml(JSON.stringify(r.policy))}`;
    } catch (e) {
      $("#pxRefreshMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };

  $("#pxDecide").onclick = async () => {
    $("#pxDecisionMsg").textContent = "Evaluating…";
    try {
      ensureTenant();
      const url = $("#pxUrlTest").value.trim();
      if (!url) throw new Error("Provide a URL.");
      const r = await client.px.decision(tenant, url);
      const tone = r.decision === "allow" ? "green" : "red";
      $("#pxDecisionMsg").innerHTML = `${badge(r.decision, tone)} <span class="text-slate-300">policy:</span> ${escapeHtml(r.policy_applied || "—")} ${r.reason ? `<span class="text-slate-300">reason:</span> ${escapeHtml(r.reason)}` : ""}`;
    } catch (e) {
      $("#pxDecisionMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };

  $("#pxBlock").onclick = async () => {
    $("#pxBlockMsg").textContent = "Adding…";
    try {
      ensureTenant();
      const target = $("#pxBlockTarget").value.trim();
      if (!target) throw new Error("Provide a substring to block.");
      await client.px.block(tenant, target);
      $("#pxBlockMsg").innerHTML = `<span class="text-emerald-300">Blocked</span> ${escapeHtml(target)}`;
      $("#pxBlockTarget").value = "";
      await loadBlocks();
    } catch (e) {
      $("#pxBlockMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };

  $("#pxBlocksReload").onclick = loadBlocks;
  await loadBlocks();
}

async function viewScan() {
  setTitle("Scan Tools", "Run detection pipelines on sample text (prompt, sensitive data, output).");
  const app = $("#app");
  app.innerHTML = `
    <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
      ${card(`
        <div class="text-sm font-semibold">Input text</div>
        <textarea id="scanText" class="mt-3 w-full h-56 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs" spellcheck="false"
        placeholder="Paste content here..."></textarea>
        <div class="mt-3 flex flex-wrap gap-2">
          <button id="btnPrompt" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Prompt injection scan</button>
          <button id="btnSensitive" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Sensitive data scan</button>
          <button id="btnOutput" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Output safety scan</button>
        </div>
        <div class="mt-2 text-xs text-slate-400">Detection service does not require API keys by default in this repo.</div>
      `)}
      ${card(`
        <div class="flex items-center justify-between">
          <div class="text-sm font-semibold">Result</div>
          <button id="btnClear" class="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700">Clear</button>
        </div>
        <pre id="scanResult" class="mt-3 text-xs bg-slate-900 border border-slate-800 rounded-xl p-3 overflow-auto h-80"></pre>
      `)}
      ${card(`
        <div class="text-sm font-semibold">Simulate incident response</div>
        <div class="mt-2 text-xs text-slate-400">Send an incident to the response orchestrator (optional: blocks via proxy agent).</div>
        <div class="mt-3 space-y-2">
          <input id="incSeverity" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="high" />
          <input id="incSource" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" value="detection" />
          <textarea id="incDesc" class="w-full h-24 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="Description"></textarea>
          <input id="incBlockTarget" class="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800" placeholder="(optional) block target substring" />
          <button id="btnIncident" class="w-full px-3 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500">Dispatch incident</button>
          <div id="incMsg" class="text-xs text-slate-400"></div>
        </div>
      `)}
    </div>
  `;
  const pre = $("#scanResult");
  const setPre = (obj) => pre.textContent = JSON.stringify(obj, null, 2);

  $("#btnClear").onclick = () => (pre.textContent = "");

  $("#btnPrompt").onclick = async () => {
    try {
      const text = $("#scanText").value || "";
      setPre(await client.det.scanPrompt(text));
    } catch (e) { pre.innerHTML = renderError(e); }
  };
  $("#btnSensitive").onclick = async () => {
    try {
      const text = $("#scanText").value || "";
      setPre(await client.det.scanSensitive(text));
    } catch (e) { pre.innerHTML = renderError(e); }
  };
  $("#btnOutput").onclick = async () => {
    try {
      const text = $("#scanText").value || "";
      setPre(await client.det.scanOutput(text));
    } catch (e) { pre.innerHTML = renderError(e); }
  };

  $("#btnIncident").onclick = async () => {
    $("#incMsg").textContent = "Sending…";
    try {
      const tenant_id = settings.tenantScope;
      if (!tenant_id) throw new Error("Set a tenant scope first (top-right).");
      const severity = $("#incSeverity").value.trim() || "medium";
      const source = $("#incSource").value.trim() || "detection";
      const description = $("#incDesc").value.trim() || "Test incident from dashboard";
      const target = $("#incBlockTarget").value.trim();
      const incident = {
        tenant_id,
        source,
        severity,
        description,
        actions: target ? [{ kind: "block", target }] : [{ kind: "webhook", message: "test" }],
      };
      const r = await client.rsp.respond(incident);
      $("#incMsg").innerHTML = `<span class="text-emerald-300">Queued</span> actions=${escapeHtml(JSON.stringify(r.actions))}`;
    } catch (e) {
      $("#incMsg").innerHTML = `<span class="text-rose-300">${escapeHtml(e.message)}</span>`;
    }
  };
}

async function viewAudit() {
  setTitle("Audit Logs", "API call audit trail from the Control Plane.");
  const app = $("#app");
  app.innerHTML = `
    ${card(`
      <div class="flex items-center justify-between">
        <div>
          <div class="text-sm font-semibold">Latest events</div>
          <div class="text-xs text-slate-400 mt-1">Filtered by tenant scope if set.</div>
        </div>
        <div class="flex items-center gap-2">
          <select id="aLimit" class="text-sm px-2 py-2 rounded-xl bg-slate-900 border border-slate-800">
            <option value="25">25</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="250">250</option>
          </select>
          <button id="aReload" class="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700">Reload</button>
        </div>
      </div>
      <div class="mt-4 overflow-auto">
        <table class="w-full text-sm">
          <thead class="text-xs text-slate-400">
            <tr>
              <th class="text-left py-2">Time</th>
              <th class="text-left py-2">Tenant</th>
              <th class="text-left py-2">Method</th>
              <th class="text-left py-2">Path</th>
              <th class="text-left py-2">Status</th>
              <th class="text-left py-2">Duration</th>
              <th class="text-left py-2">Principal</th>
            </tr>
          </thead>
          <tbody id="aRows" class="divide-y divide-slate-800"></tbody>
        </table>
      </div>
    `)}
  `;

  async function load() {
    $("#aRows").innerHTML = `<tr><td class="py-3 text-slate-400" colspan="7">Loading…</td></tr>`;
    try {
      const limit = parseInt($("#aLimit").value, 10);
      const logs = await client.cp.audit(limit);
      $("#aRows").innerHTML = logs.map(l => {
        const statusTone = String(l.status).startsWith("2") ? "green" : (String(l.status).startsWith("4") || String(l.status).startsWith("5")) ? "red" : "slate";
        return `
          <tr>
            <td class="py-2 text-xs text-slate-400">${escapeHtml(l.created_at || "")}</td>
            <td class="py-2 font-mono text-xs">${escapeHtml(l.tenant_id || "")}</td>
            <td class="py-2">${badge(l.method || "", "slate")}</td>
            <td class="py-2 font-mono text-xs">${escapeHtml(l.path || "")}</td>
            <td class="py-2">${badge(l.status || "", statusTone)}</td>
            <td class="py-2 text-xs text-slate-400">${escapeHtml(l.duration_s || "")}s</td>
            <td class="py-2 text-xs text-slate-400 max-w-[200px] truncate" title="${escapeHtml(l.principal || "")}">${escapeHtml(l.principal || "")}</td>
          </tr>
        `;
      }).join("");
    } catch (e) {
      $("#aRows").innerHTML = `<tr><td class="py-3 text-rose-300" colspan="7">${escapeHtml(e.message)}</td></tr>`;
    }
  }

  $("#aReload").onclick = load;
  await load();
}

/* ---------- Router + Settings UI ---------- */

const routes = {
  overview: viewOverview,
  tenants: viewTenants,
  policies: viewPolicies,
  proxy: viewProxy,
  scan: viewScan,
  audit: viewAudit,
};

function parseRoute() {
  const h = location.hash || "#/overview";
  const m = h.match(/^#\/([^?]+)(?:\?.*)?$/);
  return (m && m[1]) ? m[1] : "overview";
}

async function renderRoute() {
  settings = loadSettings();
  setConnectionLabels();
  const route = parseRoute();
  setActiveNav(route);
  const view = routes[route] || routes.overview;
  try {
    await view();
  } catch (e) {
    $("#app").innerHTML = renderError(e);
  }
}

function openSettings() {
  $("#settingsModal").classList.remove("hidden");
  $("#settingsModal").classList.add("flex");
  $("#cpUrl").value = settings.cpUrl;
  $("#cpKey").value = settings.cpKey;
  $("#polUrl").value = settings.polUrl;
  $("#polKey").value = settings.polKey;
  $("#pxUrl").value = settings.pxUrl;
  $("#pxKey").value = settings.pxKey;
  $("#detUrl").value = settings.detUrl;
  $("#rspUrl").value = settings.rspUrl;
}
function closeSettings() {
  $("#settingsModal").classList.add("hidden");
  $("#settingsModal").classList.remove("flex");
}

$("#openSettings").onclick = openSettings;
$("#closeSettings").onclick = closeSettings;
$("#saveSettings").onclick = () => {
  const s = {
    cpUrl: $("#cpUrl").value.trim(),
    cpKey: $("#cpKey").value.trim(),
    polUrl: $("#polUrl").value.trim(),
    polKey: $("#polKey").value.trim(),
    pxUrl: $("#pxUrl").value.trim(),
    pxKey: $("#pxKey").value.trim(),
    detUrl: $("#detUrl").value.trim(),
    rspUrl: $("#rspUrl").value.trim(),
    tenantScope: settings.tenantScope || "",
  };
  saveSettings(s);
  settings = loadSettings();
  setConnectionLabels();
  closeSettings();
  renderRoute();
};
$("#resetSettings").onclick = () => {
  localStorage.removeItem("ca_admin_settings");
  settings = loadSettings();
  setConnectionLabels();
  openSettings();
};

$("#applyScope").onclick = () => {
  settings.tenantScope = $("#tenantScope").value.trim();
  saveSettings(settings);
  setConnectionLabels();
  renderRoute();
};

$("#pingAll").onclick = async () => {
  $("#healthStatus").textContent = "Pinging…";
  const checks = await Promise.allSettled([
    client.cp.health(),
    client.pol.health(),
    client.px.health(),
    client.det.health(),
    client.rsp.health(),
  ]);
  const labels = ["CP","POL","PX","DET","RSP"];
  const out = checks.map((r,i)=> r.status==="fulfilled" ? `${labels[i]}:${"ok"}` : `${labels[i]}:${r.reason?.message || "down"}`);
  $("#healthStatus").innerHTML = out.map(s => {
    const [k,v] = s.split(":");
    return v==="ok" ? `<span class="text-emerald-300">${k}:ok</span>` : `<span class="text-rose-300">${k}:${escapeHtml(v)}</span>`;
  }).join("  ");
};

buildNav();
window.addEventListener("hashchange", renderRoute);
setConnectionLabels();
if (!location.hash) location.hash = "#/overview";
renderRoute();
