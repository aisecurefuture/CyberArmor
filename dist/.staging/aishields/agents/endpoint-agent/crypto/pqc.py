"""Post-Quantum Cryptography for Endpoint Agent.

Provides ML-KEM-1024 (Kyber) key encapsulation and ML-DSA-87 (Dilithium)
digital signatures for PQC-encrypted API key transport and secure telemetry.
Uses liboqs when available, falls back to X25519/Ed25519 classical crypto.
"""

import base64
import hashlib
import hmac
import logging
import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger("endpoint.crypto.pqc")

# Try native PQC via liboqs
try:
    import oqs
    HAS_LIBOQS = True
    logger.info("liboqs available — using native ML-KEM-1024 / ML-DSA-87")
except ImportError:
    HAS_LIBOQS = False
    logger.warning("liboqs not available — falling back to X25519/Ed25519")

# Classical fallback via cryptography library
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# ---------------------------------------------------------------------------
# Key Encapsulation (ML-KEM-1024 / X25519 fallback)
# ---------------------------------------------------------------------------

@dataclass
class KEMKeyPair:
    """KEM keypair container."""
    public_key: bytes
    secret_key: bytes
    algorithm: str


@dataclass
class KEMEncapsulationResult:
    """Result of KEM encapsulation."""
    ciphertext: bytes
    shared_secret: bytes


class EndpointKEM:
    """ML-KEM-1024 key encapsulation for endpoint-to-server communication."""

    ALGORITHM = "ML-KEM-1024"
    FALLBACK = "X25519-HKDF"
    SHARED_SECRET_LEN = 32

    def __init__(self):
        self._use_pqc = HAS_LIBOQS

    @property
    def algorithm_name(self) -> str:
        return self.ALGORITHM if self._use_pqc else self.FALLBACK

    def generate_keypair(self) -> KEMKeyPair:
        """Generate a new KEM keypair."""
        if self._use_pqc:
            kem = oqs.KeyEncapsulation("ML-KEM-1024")
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            return KEMKeyPair(public_key=pk, secret_key=sk, algorithm=self.ALGORITHM)
        else:
            sk = X25519PrivateKey.generate()
            pk = sk.public_key()
            pk_bytes = pk.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            sk_bytes = sk.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            return KEMKeyPair(public_key=pk_bytes, secret_key=sk_bytes, algorithm=self.FALLBACK)

    def encapsulate(self, peer_public_key: bytes) -> KEMEncapsulationResult:
        """Encapsulate a shared secret using the peer's public key."""
        if self._use_pqc:
            kem = oqs.KeyEncapsulation("ML-KEM-1024")
            ct, ss = kem.encap_secret(peer_public_key)
            return KEMEncapsulationResult(ciphertext=ct, shared_secret=ss)
        else:
            # X25519: generate ephemeral keypair, perform DH, derive via HKDF
            eph_sk = X25519PrivateKey.generate()
            eph_pk = eph_sk.public_key()
            peer_pk = X25519PublicKey.from_public_bytes(peer_public_key)
            raw_shared = eph_sk.exchange(peer_pk)
            ss = HKDF(
                algorithm=hashes.SHA256(), length=self.SHARED_SECRET_LEN,
                salt=None, info=b"aishields-endpoint-kem-v1",
            ).derive(raw_shared)
            ct = eph_pk.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            return KEMEncapsulationResult(ciphertext=ct, shared_secret=ss)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate a shared secret using our secret key."""
        if self._use_pqc:
            kem = oqs.KeyEncapsulation("ML-KEM-1024", secret_key)
            return kem.decap_secret(ciphertext)
        else:
            sk = X25519PrivateKey.from_private_bytes(secret_key)
            eph_pk = X25519PublicKey.from_public_bytes(ciphertext)
            raw_shared = sk.exchange(eph_pk)
            return HKDF(
                algorithm=hashes.SHA256(), length=self.SHARED_SECRET_LEN,
                salt=None, info=b"aishields-endpoint-kem-v1",
            ).derive(raw_shared)


# ---------------------------------------------------------------------------
# Digital Signatures (ML-DSA-87 / Ed25519 fallback)
# ---------------------------------------------------------------------------

@dataclass
class SignKeyPair:
    """Signing keypair container."""
    public_key: bytes
    secret_key: bytes
    algorithm: str


class EndpointSigner:
    """ML-DSA-87 digital signatures for endpoint telemetry integrity."""

    ALGORITHM = "ML-DSA-87"
    FALLBACK = "Ed25519"

    def __init__(self):
        self._use_pqc = HAS_LIBOQS

    @property
    def algorithm_name(self) -> str:
        return self.ALGORITHM if self._use_pqc else self.FALLBACK

    def generate_keypair(self) -> SignKeyPair:
        if self._use_pqc:
            sig = oqs.Signature("ML-DSA-87")
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
            return SignKeyPair(public_key=pk, secret_key=sk, algorithm=self.ALGORITHM)
        else:
            sk = Ed25519PrivateKey.generate()
            pk = sk.public_key()
            pk_bytes = pk.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            )
            sk_bytes = sk.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            return SignKeyPair(public_key=pk_bytes, secret_key=sk_bytes, algorithm=self.FALLBACK)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        if self._use_pqc:
            sig = oqs.Signature("ML-DSA-87", secret_key)
            return sig.sign(message)
        else:
            sk = Ed25519PrivateKey.from_private_bytes(secret_key)
            return sk.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        if self._use_pqc:
            sig = oqs.Signature("ML-DSA-87")
            return sig.verify(message, signature, public_key)
        else:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            try:
                pk.verify(signature, message)
                return True
            except Exception:
                return False


# ---------------------------------------------------------------------------
# PQC-Encrypted API Key Transport
# ---------------------------------------------------------------------------

@dataclass
class EncryptedAPIKey:
    """Container for a PQC-encrypted API key."""
    kem_ciphertext: bytes
    iv: bytes
    aes_ciphertext: bytes
    tag: bytes  # included in aes_ciphertext for GCM

    def encode(self) -> str:
        """Encode to header format: PQC:<base64(kem_ct_len | kem_ct | iv | aes_ct)>"""
        kem_len = struct.pack(">H", len(self.kem_ciphertext))
        payload = kem_len + self.kem_ciphertext + self.iv + self.aes_ciphertext
        return f"PQC:{base64.b64encode(payload).decode()}"

    @classmethod
    def decode(cls, header_value: str) -> "EncryptedAPIKey":
        """Decode from header format."""
        if not header_value.startswith("PQC:"):
            raise ValueError("Not a PQC-encrypted key (missing PQC: prefix)")
        raw = base64.b64decode(header_value[4:])
        kem_len = struct.unpack(">H", raw[:2])[0]
        offset = 2
        kem_ct = raw[offset:offset + kem_len]
        offset += kem_len
        iv = raw[offset:offset + 12]
        offset += 12
        aes_ct = raw[offset:]
        return cls(kem_ciphertext=kem_ct, iv=iv, aes_ciphertext=aes_ct, tag=b"")


class PQCKeyTransport:
    """Encrypt/decrypt API keys using PQC key encapsulation + AES-256-GCM."""

    def __init__(self):
        self._kem = EndpointKEM()

    def encrypt_api_key(self, api_key: str, server_public_key: bytes) -> EncryptedAPIKey:
        """Encrypt an API key for transport to the server."""
        # KEM encapsulation gives us a shared secret
        encap = self._kem.encapsulate(server_public_key)

        # Use shared secret as AES-256-GCM key
        iv = os.urandom(12)
        aesgcm = AESGCM(encap.shared_secret[:32])
        ct = aesgcm.encrypt(iv, api_key.encode("utf-8"), b"aishields-api-key-v1")

        return EncryptedAPIKey(
            kem_ciphertext=encap.ciphertext,
            iv=iv,
            aes_ciphertext=ct,
            tag=b"",  # GCM tag is appended to ct by cryptography lib
        )

    def decrypt_api_key(self, encrypted: EncryptedAPIKey, secret_key: bytes) -> str:
        """Decrypt an API key received from a client."""
        ss = self._kem.decapsulate(encrypted.kem_ciphertext, secret_key)
        aesgcm = AESGCM(ss[:32])
        plaintext = aesgcm.decrypt(encrypted.iv, encrypted.aes_ciphertext, b"aishields-api-key-v1")
        return plaintext.decode("utf-8")

    def encrypt_header(self, api_key: str, server_public_key: bytes) -> str:
        """Convenience: returns the full x-api-key header value."""
        enc = self.encrypt_api_key(api_key, server_public_key)
        return enc.encode()

    def decrypt_header(self, header_value: str, secret_key: bytes) -> str:
        """Convenience: decrypts a full x-api-key header value."""
        if not header_value.startswith("PQC:"):
            return header_value  # Plaintext fallback
        enc = EncryptedAPIKey.decode(header_value)
        return self.decrypt_api_key(enc, secret_key)


# ---------------------------------------------------------------------------
# Telemetry Signing
# ---------------------------------------------------------------------------

class TelemetrySigner:
    """Sign endpoint telemetry payloads for integrity verification."""

    def __init__(self, secret_key: Optional[bytes] = None):
        self._signer = EndpointSigner()
        if secret_key:
            self._sk = secret_key
        else:
            kp = self._signer.generate_keypair()
            self._sk = kp.secret_key
            self._pk = kp.public_key
            logger.info("Generated %s signing keypair for telemetry", self._signer.algorithm_name)

    @property
    def public_key(self) -> bytes:
        return self._pk

    def sign_payload(self, payload: bytes) -> bytes:
        """Sign a telemetry payload."""
        return self._signer.sign(payload, self._sk)

    def sign_and_encode(self, payload: bytes) -> str:
        """Sign and return base64-encoded signature."""
        sig = self.sign_payload(payload)
        return base64.b64encode(sig).decode()
