"""TLS Configuration for AIShields Transparent Proxy.

Provides TLS 1.3 enforcement, CNSA 2.0 cipher suites, CA certificate
generation for TLS interception, and FIPS mode support.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


# CNSA 2.0 approved cipher suites for TLS 1.3
CNSA_20_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
]

# AI services that should NOT have TLS interception (certificate pinning)
PINNED_DOMAINS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "*.banking.com",
]

FIPS_MODE = os.getenv("AISHIELDS_FIPS_MODE", "false").lower() == "true"
CA_CERT_DIR = Path(os.getenv("AISHIELDS_CA_DIR", "/etc/aishields/certs"))


def generate_ca_cert(
    common_name: str = "AIShields Intercept CA",
    org_name: str = "AIShields Security",
    validity_days: int = 3650,
    key_size: int = 4096,
    output_dir: Optional[Path] = None,
) -> Tuple[bytes, bytes]:
    """Generate a self-signed CA certificate for TLS interception.

    Returns:
        Tuple of (ca_cert_pem, ca_key_pem)
    """
    out = output_dir or CA_CERT_DIR
    out.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA384())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    (out / "ca.crt").write_bytes(cert_pem)
    (out / "ca.key").write_bytes(key_pem)
    os.chmod(out / "ca.key", 0o600)

    return cert_pem, key_pem


def generate_server_cert(
    hostname: str,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    validity_days: int = 365,
) -> Tuple[bytes, bytes]:
    """Generate a server certificate signed by the CA for TLS interception."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    server_key = ec.generate_private_key(ec.SECP384R1())

    san_list = [x509.DNSName(hostname)]
    if hostname.replace(".", "").isdigit():
        try:
            san_list = [x509.IPAddress(ipaddress.ip_address(hostname))]
        except ValueError:
            pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA384())
    )

    return (
        cert.public_bytes(serialization.Encoding.PEM),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def should_intercept(hostname: str) -> bool:
    """Check if TLS interception should be applied to this hostname."""
    import fnmatch
    for pinned in PINNED_DOMAINS:
        if fnmatch.fnmatch(hostname, pinned):
            return False
    return True


def get_tls_context_options() -> dict:
    """Get TLS context options for CNSA 2.0 compliance."""
    return {
        "min_version": "TLSv1.3",
        "ciphers": ":".join(CNSA_20_CIPHERS),
        "fips_mode": FIPS_MODE,
    }


def load_ca_cert(ca_dir: Optional[Path] = None) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Load existing CA cert and key from disk."""
    d = ca_dir or CA_CERT_DIR
    cert_path = d / "ca.crt"
    key_path = d / "ca.key"
    if cert_path.exists() and key_path.exists():
        return cert_path.read_bytes(), key_path.read_bytes()
    return None, None
