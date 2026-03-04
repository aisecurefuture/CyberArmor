"""FIPS 140-3 Compliant Cryptographic Operations.

Provides AES-256-GCM encryption, SHA-384/512 hashing, HMAC-SHA-256,
PBKDF2 key derivation, and secure random number generation.
"""

import hashlib
import hmac
import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def is_fips_mode() -> bool:
    """Check if FIPS mode is enabled."""
    return os.getenv("CYBERARMOR_FIPS_MODE", "false").lower() == "true"


def secure_random(n: int) -> bytes:
    """Generate n cryptographically secure random bytes."""
    return os.urandom(n)


def aes256_gcm_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext_with_tag)."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad or None)
    return nonce, ct


def aes256_gcm_decrypt(nonce: bytes, ciphertext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad or None)


def sha384(data: bytes) -> bytes:
    """SHA-384 hash."""
    return hashlib.sha384(data).digest()


def sha512(data: bytes) -> bytes:
    """SHA-512 hash."""
    return hashlib.sha512(data).digest()


def sha256(data: bytes) -> bytes:
    """SHA-256 hash."""
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA-256 message authentication."""
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_sha256_verify(key: bytes, message: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA-256. Constant-time comparison."""
    computed = hmac_sha256(key, message)
    return hmac.compare_digest(computed, expected_mac)


def pbkdf2_derive(password: str, salt: bytes = b"", iterations: int = 600000, key_length: int = 32) -> Tuple[bytes, bytes]:
    """Derive a key from password using PBKDF2-HMAC-SHA256.

    Returns (salt, derived_key). If salt is empty, generates a random 16-byte salt.
    """
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=iterations)
    key = kdf.derive(password.encode("utf-8"))
    return salt, key


def pbkdf2_verify(password: str, salt: bytes, expected_key: bytes, iterations: int = 600000) -> bool:
    """Verify a password against a PBKDF2-derived key."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=len(expected_key), salt=salt, iterations=iterations)
    try:
        kdf.verify(password.encode("utf-8"), expected_key)
        return True
    except Exception:
        return False
