"""
EventSigner — cryptographic signing of audit events.

Primary: Ed25519 digital signatures (via cryptography library).
Fallback: HMAC-SHA256 when Ed25519 is unavailable or key format is ambiguous.

The signing_key parameter is expected to be a base64-encoded Ed25519 private
key (PEM or raw 32-byte seed) or an arbitrary HMAC secret string/bytes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _canonical_event(event: Dict[str, Any]) -> bytes:
    """
    Return a deterministic bytes representation of *event* for signing.

    Only stable fields are included to avoid signature breakage on
    server-side enrichment.
    """
    canonical = {
        "event_type": event.get("event_type", ""),
        "agent_id": event.get("agent_id", ""),
        "tenant_id": event.get("tenant_id", ""),
        "environment": event.get("environment", ""),
        "timestamp": event.get("timestamp", 0),
        "payload": event.get("payload", {}),
    }
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EventSigner:
    """
    Signs audit events with Ed25519 (preferred) or HMAC-SHA256 (fallback).

    Usage
    -----
    signer = EventSigner(signing_key="base64-encoded-private-key-or-hmac-secret")
    signature = signer.sign(event_dict)
    is_valid = signer.verify(event_dict, signature)

    Signature format (Ed25519)
    -------------------------
    "ed25519:<base64url-encoded-signature>"

    Signature format (HMAC)
    -----------------------
    "hmac-sha256:<hex-digest>"
    """

    def __init__(self, signing_key: Optional[str] = None) -> None:
        self._ed25519_private_key = None
        self._ed25519_public_key = None
        self._hmac_key: Optional[bytes] = None
        self._mode: str = "none"

        if signing_key:
            self._init_key(signing_key)

    # ------------------------------------------------------------------
    # Key initialisation
    # ------------------------------------------------------------------

    def _init_key(self, signing_key: str) -> None:
        """
        Attempt to parse *signing_key* as Ed25519; fall back to HMAC.
        """
        # Try Ed25519 first
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding, NoEncryption, PrivateFormat, PublicFormat,
                load_pem_private_key,
            )

            key_bytes: Optional[bytes] = None

            if signing_key.startswith("-----BEGIN"):
                # PEM format
                key_bytes = signing_key.encode("utf-8")
                private_key = load_pem_private_key(key_bytes, password=None)
            else:
                # Try base64-encoded raw seed (32 bytes)
                try:
                    raw = base64.b64decode(signing_key + "==")  # pad
                    if len(raw) == 32:
                        private_key = Ed25519PrivateKey.from_private_bytes(raw)
                    elif len(raw) == 64:
                        # Could be seed+public or PKCS8 raw — try seed
                        private_key = Ed25519PrivateKey.from_private_bytes(raw[:32])
                    else:
                        raise ValueError(f"Unexpected key length: {len(raw)}")
                except Exception:
                    raise ValueError("Not a valid Ed25519 raw key")

            self._ed25519_private_key = private_key
            self._ed25519_public_key = private_key.public_key()
            self._mode = "ed25519"
            logger.debug("EventSigner: using Ed25519.")
            return

        except Exception as exc:
            logger.debug("Ed25519 key parse failed (%s); falling back to HMAC.", exc)

        # HMAC fallback
        try:
            raw = base64.b64decode(signing_key + "==")
        except Exception:
            raw = signing_key.encode("utf-8")

        self._hmac_key = raw
        self._mode = "hmac-sha256"
        logger.debug("EventSigner: using HMAC-SHA256.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sign(self, event: Dict[str, Any]) -> str:
        """
        Return a signature string for *event*.

        Returns "" if no signing key is configured.
        """
        if self._mode == "ed25519":
            return self._sign_ed25519(event)
        if self._mode == "hmac-sha256":
            return self._sign_hmac(event)
        return ""

    def verify(self, event: Dict[str, Any], signature: str) -> bool:
        """
        Return True if *signature* is valid for *event*.

        Returns False (not raises) on any verification failure.
        """
        if not signature:
            return False
        try:
            if signature.startswith("ed25519:"):
                return self._verify_ed25519(event, signature)
            if signature.startswith("hmac-sha256:"):
                return self._verify_hmac(event, signature)
            return False
        except Exception as exc:
            logger.debug("Signature verification error: %s", exc)
            return False

    @property
    def mode(self) -> str:
        """Return the active signing mode: 'ed25519', 'hmac-sha256', or 'none'."""
        return self._mode

    # ------------------------------------------------------------------
    # Ed25519 internals
    # ------------------------------------------------------------------

    def _sign_ed25519(self, event: Dict[str, Any]) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        payload = _canonical_event(event)
        sig_bytes = self._ed25519_private_key.sign(payload)  # type: ignore[union-attr]
        return "ed25519:" + base64.urlsafe_b64encode(sig_bytes).decode("ascii")

    def _verify_ed25519(self, event: Dict[str, Any], signature: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        if not self._ed25519_public_key:
            return False
        payload = _canonical_event(event)
        sig_b64 = signature[len("ed25519:"):]
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        try:
            self._ed25519_public_key.verify(sig_bytes, payload)
            return True
        except InvalidSignature:
            return False

    # ------------------------------------------------------------------
    # HMAC internals
    # ------------------------------------------------------------------

    def _sign_hmac(self, event: Dict[str, Any]) -> str:
        payload = _canonical_event(event)
        digest = hmac.new(
            self._hmac_key,  # type: ignore[arg-type]
            payload,
            hashlib.sha256,
        ).hexdigest()
        return "hmac-sha256:" + digest

    def _verify_hmac(self, event: Dict[str, Any], signature: str) -> bool:
        expected = self._sign_hmac(event)
        return hmac.compare_digest(expected, signature)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def generate_ed25519_key() -> str:
        """
        Generate a new Ed25519 private key and return it as a base64 string.

        Useful for initial key provisioning.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes_raw()  # 32-byte seed
        return base64.b64encode(raw).decode("ascii")

    @staticmethod
    def generate_hmac_key(length: int = 32) -> str:
        """Generate a random HMAC key and return it as a base64 string."""
        import os
        return base64.b64encode(os.urandom(length)).decode("ascii")

    def __repr__(self) -> str:
        return f"EventSigner(mode={self._mode!r})"
