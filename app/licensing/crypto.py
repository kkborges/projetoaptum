"""Cryptographic utilities for license signing and validation.

Implements chain of trust using RSA signatures:
  - Server holds the private key (signs licenses)
  - Clients hold the public key (verify licenses)
  - License key = base64(signed payload)
"""
import hashlib
import hmac
import json
import base64
import secrets
import subprocess
import platform
import uuid
from datetime import datetime, timedelta
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# --- Key Management ---

def generate_keypair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate RSA keypair for license signing. Returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def get_key_fingerprint(public_pem: bytes) -> str:
    """SHA256 fingerprint of a public key."""
    return hashlib.sha256(public_pem).hexdigest()


# --- License Signing ---

def sign_license_payload(payload: dict, private_pem: bytes) -> str:
    """Sign a license payload and return base64 signature."""
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(
        canonical,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_license_signature(payload: dict, signature_b64: str, public_pem: bytes) -> bool:
    """Verify the RSA signature of a license payload."""
    try:
        public_key = serialization.load_pem_public_key(
            public_pem, backend=default_backend()
        )
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, Exception):
        return False


# --- License Key Generation ---

def generate_license_key() -> str:
    """Generate a unique license key in format XXXX-XXXX-XXXX-XXXX-XXXX."""
    segments = []
    for _ in range(5):
        segment = secrets.token_hex(2).upper()
        segments.append(segment)
    return "-".join(segments)


# --- Machine ID ---

def get_machine_id() -> str:
    """Get a unique machine identifier based on hardware/OS characteristics."""
    components = []

    # Try reading machine-id on Linux
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            with open(path, "r") as f:
                mid = f.read().strip()
                if mid:
                    components.append(mid)
                    break
        except (FileNotFoundError, PermissionError):
            continue

    # Fallback: use platform info + uuid
    if not components:
        try:
            node = uuid.getnode()
            components.append(str(node))
        except Exception:
            pass

    components.append(platform.node())
    components.append(platform.machine())

    raw = "|".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_machine_binding(stored_machine_id: str) -> bool:
    """Check if the current machine matches a stored machine ID."""
    current = get_machine_id()
    return hmac.compare_digest(current, stored_machine_id)


# --- HMAC Utility for Cache Integrity ---

def compute_cache_hmac(data: str, secret: str) -> str:
    """Compute HMAC-SHA256 for cache integrity verification."""
    return hmac.new(
        secret.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_cache_hmac(data: str, expected_hmac: str, secret: str) -> bool:
    """Verify cache HMAC."""
    computed = compute_cache_hmac(data, secret)
    return hmac.compare_digest(computed, expected_hmac)
