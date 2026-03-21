#!/usr/bin/env python3
from __future__ import annotations

import os
import ssl
import sys
from pathlib import Path

import uvicorn


def _is_true(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: run_uvicorn_tls.py <module:app> <port>", file=sys.stderr)
        return 2

    app_path = sys.argv[1]
    port = int(sys.argv[2])
    host = os.getenv("UVICORN_HOST", "0.0.0.0")

    native_tls = _is_true(os.getenv("CYBERARMOR_ENABLE_NATIVE_TLS_LISTENER", "false"))
    require_client_cert = _is_true(os.getenv("CYBERARMOR_REQUIRE_CLIENT_CERT", "false"))
    ca_file = os.getenv("CYBERARMOR_TLS_CA_FILE")
    cert_file = os.getenv("CYBERARMOR_TLS_CERT_FILE")
    key_file = os.getenv("CYBERARMOR_TLS_KEY_FILE")

    kwargs = {
        "app": app_path,
        "host": host,
        "port": port,
        "proxy_headers": True,
        "forwarded_allow_ips": "*",
    }

    if native_tls:
        missing = []
        for env_name, path in [
            ("CYBERARMOR_TLS_CERT_FILE", cert_file),
            ("CYBERARMOR_TLS_KEY_FILE", key_file),
        ]:
            if not path:
                missing.append(f"{env_name}(unset)")
            elif not Path(path).exists():
                missing.append(f"{env_name}({path} missing)")

        if require_client_cert:
            if not ca_file:
                missing.append("CYBERARMOR_TLS_CA_FILE(unset)")
            elif not Path(ca_file).exists():
                missing.append(f"CYBERARMOR_TLS_CA_FILE({ca_file} missing)")

        if missing:
            raise RuntimeError(
                "Native TLS listener enabled but required TLS artifacts missing: "
                + ", ".join(missing)
            )

        kwargs["ssl_certfile"] = cert_file
        kwargs["ssl_keyfile"] = key_file
        if ca_file:
            kwargs["ssl_ca_certs"] = ca_file
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL

    uvicorn.run(**kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
