#!/usr/bin/env python3
"""
CyberArmor AI Identity Control Plane — CLI Tool
Version: 2.0.0

Usage:
    cyberarmor <command> [<subcommand>] [options]

Environment variables required:
    CYBERARMOR_URL          Base URL of the control plane
    CYBERARMOR_AGENT_ID     Agent identifier for authentication
    CYBERARMOR_AGENT_SECRET Agent secret / API key

Optional environment variables:
    CYBERARMOR_ENFORCE_MODE  enforce | audit | permissive  (default: enforce)
    CYBERARMOR_TENANT        Default tenant ID

Run `cyberarmor --help` or `cyberarmor <command> --help` for details.
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# Version
# ============================================================================
__version__ = "2.0.0"


# ============================================================================
# ANSI colour helpers (no extra deps)
# ============================================================================
_USE_COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""

def _c(code: str, text: str) -> str:
    if not _USE_COLOUR:
        return text
    return f"\033[{code}m{text}\033[0m"

def green(t: str)   -> str: return _c("32", t)
def red(t: str)     -> str: return _c("31", t)
def yellow(t: str)  -> str: return _c("33", t)
def cyan(t: str)    -> str: return _c("36", t)
def bold(t: str)    -> str: return _c("1",  t)
def dim(t: str)     -> str: return _c("2",  t)
def magenta(t: str) -> str: return _c("35", t)


# ============================================================================
# Output helpers
# ============================================================================
def print_success(msg: str) -> None:
    print(f"{green('OK')}  {msg}")

def print_error(msg: str) -> None:
    print(f"{red('ERROR')}  {msg}", file=sys.stderr)

def print_warn(msg: str) -> None:
    print(f"{yellow('WARN')}  {msg}", file=sys.stderr)

def print_info(msg: str) -> None:
    print(f"{cyan('INFO')}  {msg}")

def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def print_table(headers: List[str], rows: List[List[str]],
                col_sep: str = "  ") -> None:
    """Render a simple fixed-width table to stdout."""
    if not rows:
        print(dim("  (no results)"))
        return
    # Compute column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    # Header
    header_line = col_sep.join(bold(h.ljust(widths[i]))
                                for i, h in enumerate(headers))
    print(header_line)
    print(dim("-" * (sum(widths) + len(col_sep) * (len(headers) - 1))))
    # Rows
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            s = str(cell) if cell is not None else ""
            cells.append(s.ljust(widths[i]) if i < len(widths) else s)
        print(col_sep.join(cells))


# ============================================================================
# Configuration loading from environment
# ============================================================================
class Config:
    """Reads CyberArmor configuration from environment variables."""

    def __init__(self) -> None:
        self.url: str = (
            os.environ.get("CYBERARMOR_URL", "")
        )
        self.agent_id: str     = os.environ.get("CYBERARMOR_AGENT_ID", "")
        self.agent_secret: str = os.environ.get("CYBERARMOR_AGENT_SECRET", "")
        self.enforce_mode: str = os.environ.get("CYBERARMOR_ENFORCE_MODE", "enforce")
        self.tenant: str       = os.environ.get("CYBERARMOR_TENANT", "")
        self.timeout: int      = int(os.environ.get("CYBERARMOR_TIMEOUT_MS", "10000")) // 1000

    def require(self) -> None:
        """Raise SystemExit if required config is missing."""
        missing = []
        if not self.url:
            missing.append("CYBERARMOR_URL")
        if not self.agent_id:
            missing.append("CYBERARMOR_AGENT_ID")
        if not self.agent_secret:
            missing.append("CYBERARMOR_AGENT_SECRET")
        if missing:
            print_error(
                f"Missing required environment variable(s): {', '.join(missing)}\n"
                "  Set them in your shell or run: cyberarmor config show"
            )
            sys.exit(1)

    def service_url(self, port: int) -> str:
        """Derive a service URL from the base URL by replacing the port."""
        if not self.url:
            return f"http://localhost:{port}"
        parsed = urllib.parse.urlparse(self.url)
        return f"{parsed.scheme}://{parsed.hostname}:{port}"


# ============================================================================
# HTTP client (stdlib only)
# ============================================================================
class APIClient:
    """Thin HTTP client wrapping urllib.request."""

    # Default service ports matching docker-compose
    CONTROL_PLANE_PORT = 8000
    POLICY_PORT        = 8001
    IDENTITY_PORT      = 8008
    AI_ROUTER_PORT     = 8009
    AUDIT_PORT         = 8011

    def __init__(self, config: Config) -> None:
        self.config = config

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "X-API-Key":     self.config.agent_secret,
            "X-Agent-ID":    self.config.agent_id,
        }

    def _url(self, path: str, port: Optional[int] = None) -> str:
        base = self.config.url.rstrip("/") if self.config.url else ""
        if port and base:
            parsed = urllib.parse.urlparse(base)
            base = f"{parsed.scheme}://{parsed.hostname}:{port}"
        return f"{base}{path}"

    def _request(self, method: str, path: str,
                 body: Optional[Dict] = None,
                 port: Optional[int] = None,
                 params: Optional[Dict] = None) -> Tuple[int, Any]:
        url = self._url(path, port)
        if params:
            qs = urllib.parse.urlencode({k: v for k, v in params.items()
                                          if v is not None})
            if qs:
                url = f"{url}?{qs}"

        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            url, data=data, headers=self._headers(), method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                raw = resp.read()
                status = resp.status
                try:
                    return status, json.loads(raw)
                except json.JSONDecodeError:
                    return status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw)
            except Exception:
                return exc.code, raw.decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Connection failed to {url}: {exc.reason}") from exc

    def get(self, path: str, port: Optional[int] = None,
            params: Optional[Dict] = None) -> Tuple[int, Any]:
        return self._request("GET", path, port=port, params=params)

    def post(self, path: str, body: Optional[Dict] = None,
             port: Optional[int] = None) -> Tuple[int, Any]:
        return self._request("POST", path, body=body, port=port)

    def put(self, path: str, body: Optional[Dict] = None,
            port: Optional[int] = None) -> Tuple[int, Any]:
        return self._request("PUT", path, body=body, port=port)

    def delete(self, path: str, port: Optional[int] = None) -> Tuple[int, Any]:
        return self._request("DELETE", path, port=port)


def _check_status(status: int, body: Any, action: str) -> None:
    if status >= 400:
        detail = ""
        if isinstance(body, dict):
            detail = body.get("detail") or body.get("message") or body.get("error") or ""
        print_error(f"{action} failed (HTTP {status}): {detail or body}")
        sys.exit(1)


# ============================================================================
# Command: agents
# ============================================================================
def cmd_agents_list(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    params: Dict[str, Any] = {}
    if args.tenant:
        params["tenant_id"] = args.tenant
    elif cfg.tenant:
        params["tenant_id"] = cfg.tenant
    if args.limit:
        params["limit"] = args.limit

    status, body = api.get("/agents", port=APIClient.IDENTITY_PORT, params=params)
    _check_status(status, body, "agents list")

    items = body if isinstance(body, list) else body.get("agents", body.get("items", []))
    if args.json:
        print_json(items)
        return

    rows = []
    for a in items:
        rows.append([
            a.get("agent_id", ""),
            a.get("name", ""),
            a.get("trust_level", ""),
            a.get("status", ""),
            a.get("tenant_id", ""),
            a.get("created_at", "")[:10] if a.get("created_at") else "",
        ])
    print_table(["AGENT_ID", "NAME", "TRUST_LEVEL", "STATUS", "TENANT", "CREATED"], rows)
    print(dim(f"\n  {len(rows)} agent(s)"))


def cmd_agents_register(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    caps = [c.strip() for c in args.caps.split(",")] if args.caps else []
    payload = {
        "name":        args.name,
        "tenant_id":   args.tenant or cfg.tenant or "default",
        "trust_level": args.trust_level,
        "capabilities": caps,
    }
    status, body = api.post("/agents/register", body=payload,
                             port=APIClient.IDENTITY_PORT)
    _check_status(status, body, "agents register")
    if args.json:
        print_json(body)
        return
    agent_id = body.get("agent_id", "") if isinstance(body, dict) else ""
    print_success(f"Agent registered: {bold(agent_id)}")
    if isinstance(body, dict):
        for k, v in body.items():
            print(f"  {dim(k)}: {v}")


def cmd_agents_delete(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    status, body = api.delete(f"/agents/{args.agent_id}",
                               port=APIClient.IDENTITY_PORT)
    _check_status(status, body, "agents delete")
    if args.json:
        print_json(body)
        return
    print_success(f"Agent {bold(args.agent_id)} deleted/revoked.")


# ============================================================================
# Command: tokens
# ============================================================================
def cmd_tokens_issue(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    scopes = [s.strip() for s in args.scopes.split(",")] if args.scopes else ["ai:inference"]
    payload = {
        "tenant_id":  args.tenant or cfg.tenant or "default",
        "scopes":     scopes,
        "expires_in": args.expires,
    }
    status, body = api.post(f"/agents/{args.agent_id}/tokens/issue",
                             body=payload, port=APIClient.IDENTITY_PORT)
    _check_status(status, body, "tokens issue")
    if args.json:
        print_json(body)
        return
    token = body.get("access_token", "") if isinstance(body, dict) else ""
    expires_at = body.get("expires_at", "") if isinstance(body, dict) else ""
    print_success(f"Token issued (expires: {expires_at})")
    print(f"  {bold('access_token')}: {token}")


# ============================================================================
# Command: providers
# ============================================================================
def cmd_providers_list(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    status, body = api.get("/ai/providers", port=APIClient.AI_ROUTER_PORT)
    _check_status(status, body, "providers list")
    items = body if isinstance(body, list) else body.get("providers", [])
    if args.json:
        print_json(items)
        return
    rows = []
    for p in items:
        rows.append([
            p.get("provider", ""),
            p.get("status", ""),
            str(p.get("models_available", "")),
            str(p.get("budget_usd", "")),
            str(p.get("rate_limit_rpm", "")),
        ])
    print_table(["PROVIDER", "STATUS", "MODELS", "BUDGET_USD", "RATE_LIMIT_RPM"], rows)


def cmd_providers_configure(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    payload: Dict[str, Any] = {"api_key": args.api_key}
    if args.budget is not None:
        payload["budget_usd"] = args.budget
    if args.rate_limit is not None:
        payload["rate_limit_rpm"] = args.rate_limit
    status, body = api.post(
        f"/credentials/providers/{args.provider}/configure",
        body=payload, port=APIClient.AI_ROUTER_PORT
    )
    _check_status(status, body, "providers configure")
    if args.json:
        print_json(body)
        return
    print_success(f"Provider {bold(args.provider)} configured.")


# ============================================================================
# Command: policies
# ============================================================================
def cmd_policies_list(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    params: Dict[str, Any] = {}
    tenant = args.tenant or cfg.tenant
    if tenant:
        params["tenant_id"] = tenant
    status, body = api.get("/policies", port=APIClient.POLICY_PORT, params=params)
    _check_status(status, body, "policies list")
    items = body if isinstance(body, list) else body.get("policies", body.get("items", []))
    if args.json:
        print_json(items)
        return
    rows = []
    for p in items:
        rows.append([
            p.get("policy_id", p.get("id", "")),
            p.get("name", ""),
            p.get("action", ""),
            p.get("tenant_id", ""),
            str(p.get("priority", "")),
            p.get("updated_at", "")[:10] if p.get("updated_at") else "",
        ])
    print_table(["POLICY_ID", "NAME", "ACTION", "TENANT", "PRIORITY", "UPDATED"], rows)
    print(dim(f"\n  {len(rows)} policy/policies"))


# ============================================================================
# Command: audit
# ============================================================================
def cmd_audit_events(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    params: Dict[str, Any] = {"limit": args.limit}
    tenant = args.tenant or cfg.tenant
    if tenant:
        params["tenant_id"] = tenant

    status, body = api.get("/events", port=APIClient.AUDIT_PORT, params=params)
    _check_status(status, body, "audit events")
    items = body if isinstance(body, list) else body.get("events", body.get("items", []))
    if args.json:
        print_json(items)
        return
    rows = []
    for e in items:
        risk = e.get("risk_score", 0.0)
        risk_str = f"{risk:.2f}"
        if risk >= 0.7:
            risk_str = red(risk_str)
        elif risk >= 0.4:
            risk_str = yellow(risk_str)
        else:
            risk_str = green(risk_str)

        blocked = e.get("blocked", False)
        blocked_str = red("YES") if blocked else green("no")

        rows.append([
            e.get("event_id", "")[:12],
            e.get("agent_id", "")[:16],
            e.get("action", ""),
            e.get("model", ""),
            e.get("provider", ""),
            risk_str,
            blocked_str,
            (e.get("timestamp", "")[:19] if e.get("timestamp") else ""),
        ])
    print_table(
        ["EVENT_ID", "AGENT_ID", "ACTION", "MODEL", "PROVIDER", "RISK", "BLOCKED", "TIME"],
        rows
    )
    print(dim(f"\n  {len(rows)} event(s)"))


def cmd_audit_graph(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    status, body = api.get(f"/graph/agent/{args.agent}",
                            port=APIClient.AUDIT_PORT)
    _check_status(status, body, "audit graph")
    if args.json:
        print_json(body)
        return
    print(bold(f"Action graph for agent: {args.agent}"))
    print()
    if isinstance(body, dict):
        nodes = body.get("nodes", [])
        edges = body.get("edges", [])
        print(f"  {cyan('Nodes:')} {len(nodes)}")
        for n in nodes[:20]:
            print(f"    {dim('-')} {n.get('id', '')}  {dim(n.get('action', ''))}")
        if len(nodes) > 20:
            print(dim(f"    ... and {len(nodes) - 20} more"))
        print()
        print(f"  {cyan('Edges:')} {len(edges)}")
        for ed in edges[:20]:
            print(f"    {ed.get('from', '')}  {cyan('-->')}  {ed.get('to', '')}"
                  f"  {dim(ed.get('label', ''))}")
        if len(edges) > 20:
            print(dim(f"    ... and {len(edges) - 20} more"))
    else:
        print_json(body)


# ============================================================================
# Command: delegations
# ============================================================================
def cmd_delegations_list(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    params: Dict[str, Any] = {}
    tenant = args.tenant or cfg.tenant
    if tenant:
        params["tenant_id"] = tenant
    status, body = api.get("/delegations", port=APIClient.IDENTITY_PORT,
                            params=params)
    _check_status(status, body, "delegations list")
    items = body if isinstance(body, list) else body.get("delegations", [])
    if args.json:
        print_json(items)
        return
    rows = []
    for d in items:
        revoked = d.get("revoked", False)
        status_str = red("revoked") if revoked else green("active")
        rows.append([
            d.get("chain_id", "")[:16],
            d.get("delegator_id", "")[:20],
            d.get("delegate_id", "")[:20],
            ", ".join(d.get("scopes", [])),
            status_str,
            d.get("expires_at", "")[:16] if d.get("expires_at") else "",
        ])
    print_table(
        ["CHAIN_ID", "DELEGATOR", "DELEGATE", "SCOPES", "STATUS", "EXPIRES"],
        rows
    )
    print(dim(f"\n  {len(rows)} delegation chain(s)"))


def _parse_expires(expires_str: str) -> int:
    """Convert e.g. '24h', '30m', '3600' to seconds."""
    s = expires_str.strip().lower()
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    return int(s)


def cmd_delegations_create(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    scopes = [s.strip() for s in args.scopes.split(",")] if args.scopes else ["ai:inference"]
    expires_s = _parse_expires(args.expires) if args.expires else 86400
    payload = {
        "tenant_id":    args.tenant or cfg.tenant or "default",
        "delegator_id": getattr(args, "from_agent"),
        "delegate_id":  args.to_agent,
        "scopes":       scopes,
        "expires_in":   expires_s,
        "max_depth":    2,
    }
    status, body = api.post("/delegations", body=payload,
                             port=APIClient.IDENTITY_PORT)
    _check_status(status, body, "delegations create")
    if args.json:
        print_json(body)
        return
    chain_id = body.get("chain_id", "") if isinstance(body, dict) else ""
    expires_at = body.get("expires_at", "") if isinstance(body, dict) else ""
    print_success(f"Delegation chain created: {bold(chain_id)} (expires: {expires_at})")


# ============================================================================
# Command: config show
# ============================================================================
def cmd_config_show(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    data = {
        "CYBERARMOR_URL":          cfg.url or dim("(not set)"),
        "CYBERARMOR_AGENT_ID":     cfg.agent_id or dim("(not set)"),
        "CYBERARMOR_AGENT_SECRET": ("*" * 8 + cfg.agent_secret[-4:])
                                   if len(cfg.agent_secret) > 4
                                   else (dim("(not set)") if not cfg.agent_secret else "****"),
        "CYBERARMOR_ENFORCE_MODE": cfg.enforce_mode,
        "CYBERARMOR_TENANT":       cfg.tenant or dim("(not set)"),
        "CYBERARMOR_TIMEOUT_MS":   str(cfg.timeout * 1000),
    }
    if args.json:
        print_json({k: v for k, v in data.items()})
        return
    print(bold("CyberArmor CLI Configuration"))
    print(dim("=" * 40))
    for k, v in data.items():
        status_marker = green("SET") if ("(not set)" not in str(v)) else red("NOT SET")
        print(f"  {status_marker}  {cyan(k)}: {v}")


# ============================================================================
# Command: health
# ============================================================================
def cmd_health(args: argparse.Namespace, cfg: Config, api: APIClient) -> None:
    services = [
        ("control-plane",   8000, "/health"),
        ("policy",          8001, "/health"),
        ("detection",       8002, "/health"),
        ("response",        8003, "/health"),
        ("identity",        8004, "/health"),
        ("siem-connector",  8005, "/health"),
        ("compliance",      8006, "/health"),
        ("runtime",         8007, "/health"),
        ("agent-identity",  8008, "/health"),
        ("ai-router",       8009, "/health"),
        ("proxy",           8010, "/health"),
        ("audit-graph",     8011, "/health"),
    ]
    results = []
    for name, port, path in services:
        t0 = time.monotonic()
        try:
            status, body = api.get(path, port=port)
            latency_ms = int((time.monotonic() - t0) * 1000)
            ok = status < 300
            svc_status = body.get("status", "ok") if isinstance(body, dict) else "ok"
            results.append((name, port, ok, svc_status, latency_ms))
        except ConnectionError as exc:
            latency_ms = int((time.monotonic() - t0) * 1000)
            results.append((name, port, False, "unreachable", latency_ms))

    if args.json:
        print_json([
            {"service": r[0], "port": r[1], "healthy": r[2],
             "status": r[3], "latency_ms": r[4]}
            for r in results
        ])
        return

    print(bold("CyberArmor Service Health"))
    print(dim("=" * 50))
    rows = []
    for name, port, ok, svc_status, latency_ms in results:
        health_str = green("healthy") if ok else red("UNHEALTHY")
        rows.append([name, str(port), health_str, svc_status, f"{latency_ms}ms"])
    print_table(["SERVICE", "PORT", "HEALTH", "STATUS", "LATENCY"], rows)
    healthy = sum(1 for r in results if r[2])
    total = len(results)
    colour = green if healthy == total else (yellow if healthy > 0 else red)
    print(f"\n  {colour(str(healthy))}/{total} services healthy")


# ============================================================================
# Argument parser setup
# ============================================================================
def _add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add flags common to all subcommands."""
    parser.add_argument(
        "--json", action="store_true",
        help="Output raw JSON instead of formatted tables"
    )
    parser.add_argument(
        "--tenant", default=None,
        help="Tenant ID (overrides CYBERARMOR_TENANT env var)"
    )


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="cyberarmor",
        description=bold("CyberArmor AI Identity Control Plane CLI v" + __version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dim(
            "Environment variables:\n"
            "  CYBERARMOR_URL           Control plane base URL (required)\n"
            "  CYBERARMOR_AGENT_ID      Agent ID for auth (required)\n"
            "  CYBERARMOR_AGENT_SECRET  Agent secret/API key (required)\n"
            "  CYBERARMOR_TENANT        Default tenant ID\n"
            "  CYBERARMOR_ENFORCE_MODE  enforce | audit | permissive\n"
        )
    )
    root.add_argument(
        "--version", action="version",
        version=f"cyberarmor-cli {__version__}"
    )
    root.add_argument(
        "--json", action="store_true",
        help="Global: output raw JSON"
    )

    sub = root.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # ------------------------------------------------------------------ agents
    p_agents = sub.add_parser("agents", help="Manage AI agent identities")
    agents_sub = p_agents.add_subparsers(dest="subcommand", metavar="<subcommand>")
    agents_sub.required = True

    # agents list
    p_al = agents_sub.add_parser("list", help="List registered agents")
    _add_common_args(p_al)
    p_al.add_argument("--limit", type=int, default=50, metavar="N",
                       help="Maximum number of results (default: 50)")

    # agents register
    p_ar = agents_sub.add_parser("register", help="Register a new AI agent")
    _add_common_args(p_ar)
    p_ar.add_argument("--name", required=True, help="Agent display name")
    p_ar.add_argument(
        "--trust-level",
        choices=["standard", "privileged", "restricted"],
        default="standard",
        help="Trust level for the agent (default: standard)"
    )
    p_ar.add_argument(
        "--caps", default="",
        metavar="CAP1,CAP2",
        help="Comma-separated list of capability tags"
    )

    # agents delete
    p_ad = agents_sub.add_parser("delete", help="Revoke/delete an agent")
    _add_common_args(p_ad)
    p_ad.add_argument("agent_id", help="Agent ID to delete")

    # ------------------------------------------------------------------ tokens
    p_tokens = sub.add_parser("tokens", help="Issue and manage agent tokens")
    tokens_sub = p_tokens.add_subparsers(dest="subcommand", metavar="<subcommand>")
    tokens_sub.required = True

    # tokens issue
    p_ti = tokens_sub.add_parser("issue", help="Issue a JWT for an agent")
    _add_common_args(p_ti)
    p_ti.add_argument("agent_id", help="Agent ID to issue token for")
    p_ti.add_argument(
        "--scopes", default="ai:inference,ai:audit",
        metavar="SCOPE1,SCOPE2",
        help="Comma-separated OAuth2 scopes (default: ai:inference,ai:audit)"
    )
    p_ti.add_argument(
        "--expires", type=int, default=3600, metavar="SECONDS",
        help="Token lifetime in seconds (default: 3600)"
    )

    # ---------------------------------------------------------------- providers
    p_prov = sub.add_parser("providers", help="Manage AI provider integrations")
    prov_sub = p_prov.add_subparsers(dest="subcommand", metavar="<subcommand>")
    prov_sub.required = True

    # providers list
    p_pl = prov_sub.add_parser("list", help="List configured AI providers")
    _add_common_args(p_pl)

    # providers configure
    p_pc = prov_sub.add_parser("configure", help="Configure a provider credential")
    _add_common_args(p_pc)
    p_pc.add_argument("provider",
                       help="Provider name (openai | anthropic | google | azure | ...)")
    p_pc.add_argument("--api-key", required=True, dest="api_key",
                       help="Provider API key")
    p_pc.add_argument("--budget", type=float, default=None, metavar="USD",
                       help="Monthly budget cap in USD")
    p_pc.add_argument("--rate-limit", type=int, default=None, metavar="RPM",
                       help="Rate limit in requests per minute")

    # ---------------------------------------------------------------- policies
    p_pol = sub.add_parser("policies", help="View AI security policies")
    pol_sub = p_pol.add_subparsers(dest="subcommand", metavar="<subcommand>")
    pol_sub.required = True

    # policies list
    p_poll = pol_sub.add_parser("list", help="List policies")
    _add_common_args(p_poll)

    # ------------------------------------------------------------------ audit
    p_audit = sub.add_parser("audit", help="Query audit trail and action graphs")
    audit_sub = p_audit.add_subparsers(dest="subcommand", metavar="<subcommand>")
    audit_sub.required = True

    # audit events
    p_ae = audit_sub.add_parser("events", help="List recent audit events")
    _add_common_args(p_ae)
    p_ae.add_argument("--limit", type=int, default=50, metavar="N",
                       help="Maximum events to return (default: 50)")

    # audit graph
    p_ag = audit_sub.add_parser("graph",
                                  help="Fetch causal action graph for an agent")
    _add_common_args(p_ag)
    p_ag.add_argument("--agent", required=True, metavar="AGENT_ID",
                       help="Agent ID to build graph for")

    # ------------------------------------------------------------ delegations
    p_del = sub.add_parser("delegations",
                            help="Manage agent-to-agent delegation chains")
    del_sub = p_del.add_subparsers(dest="subcommand", metavar="<subcommand>")
    del_sub.required = True

    # delegations list
    p_dll = del_sub.add_parser("list", help="List delegation chains")
    _add_common_args(p_dll)

    # delegations create
    p_dlc = del_sub.add_parser("create", help="Create a delegation chain")
    _add_common_args(p_dlc)
    p_dlc.add_argument("--from", dest="from_agent", required=True,
                        metavar="AGENT_ID",
                        help="Delegating agent (source of permissions)")
    p_dlc.add_argument("--to", dest="to_agent", required=True,
                        metavar="AGENT_ID",
                        help="Delegate agent (recipient of permissions)")
    p_dlc.add_argument("--scopes", default="ai:inference",
                        metavar="SCOPE1,SCOPE2",
                        help="Comma-separated scopes to delegate")
    p_dlc.add_argument("--expires", default="24h",
                        metavar="DURATION",
                        help="Expiry as e.g. 24h, 30m, 3600 (seconds). Default: 24h")

    # ------------------------------------------------------------------ config
    p_cfg = sub.add_parser("config", help="Show CLI configuration")
    cfg_sub = p_cfg.add_subparsers(dest="subcommand", metavar="<subcommand>")
    cfg_sub.required = True

    p_cs = cfg_sub.add_parser("show", help="Show current env var configuration")
    p_cs.add_argument("--json", action="store_true", help="Output JSON")

    # ------------------------------------------------------------------ health
    p_health = sub.add_parser("health", help="Ping all CyberArmor services")
    p_health.add_argument("--json", action="store_true", help="Output JSON")

    return root


# ============================================================================
# Dispatcher
# ============================================================================
DISPATCH = {
    ("agents",      "list"):      cmd_agents_list,
    ("agents",      "register"):  cmd_agents_register,
    ("agents",      "delete"):    cmd_agents_delete,
    ("tokens",      "issue"):     cmd_tokens_issue,
    ("providers",   "list"):      cmd_providers_list,
    ("providers",   "configure"): cmd_providers_configure,
    ("policies",    "list"):      cmd_policies_list,
    ("audit",       "events"):    cmd_audit_events,
    ("audit",       "graph"):     cmd_audit_graph,
    ("delegations", "list"):      cmd_delegations_list,
    ("delegations", "create"):    cmd_delegations_create,
    ("config",      "show"):      cmd_config_show,
    ("health",      None):        cmd_health,
}


# ============================================================================
# Entry point
# ============================================================================
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = Config()
    api = APIClient(cfg)

    key = (args.command, getattr(args, "subcommand", None))
    handler = DISPATCH.get(key)

    if handler is None:
        print_error(f"Unknown command: {args.command} {getattr(args, 'subcommand', '')}")
        return 1

    # Health and config show do not require auth
    needs_auth = args.command not in ("health", "config")
    if needs_auth:
        cfg.require()

    try:
        handler(args, cfg, api)
        return 0
    except ConnectionError as exc:
        print_error(str(exc))
        print_warn("Is the CyberArmor control plane running? Check: cyberarmor health")
        return 2
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as exc:
        print_error(f"Unexpected error: {exc}")
        if os.environ.get("CYBERARMOR_DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
