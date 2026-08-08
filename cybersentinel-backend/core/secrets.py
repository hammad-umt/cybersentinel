"""
core/secrets.py

Encrypt sensitive settings at rest.

Supports:
  - Legacy Fernet (AES-128-CBC + HMAC)
  - AES-256-GCM via CYBERSENTINEL_MASTER_KEY (32-byte hex or base64)
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from loguru import logger

SECRET_FIELDS = (
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "API_KEY",
)

_AES256_PREFIX = b"A256:"


def _fernet(master_key: str) -> Fernet:
    normalized = master_key.strip().encode("utf-8")
    if len(normalized) != 44:
        raise ValueError("Fernet CYBERSENTINEL_MASTER_KEY must be 44 url-safe base64 chars.")
    return Fernet(normalized)


def _aes256_key(master_key: str) -> bytes:
    """Derive a 32-byte AES-256 key from master key material."""
    raw = master_key.strip()
    if len(raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
        return bytes.fromhex(raw)
    try:
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    # Fallback: SHA-256 digest of passphrase
    import hashlib

    return hashlib.sha256(raw.encode("utf-8")).digest()


def encrypt_secrets_aes256(secrets: dict[str, str], master_key: str, output_path: Path) -> None:
    payload = json.dumps({key: secrets.get(key, "") for key in SECRET_FIELDS}).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_aes256_key(master_key)).encrypt(nonce, payload, None)
    output_path.write_bytes(_AES256_PREFIX + nonce + ciphertext)
    logger.info("AES-256-GCM encrypted secrets written to {}", output_path)


def decrypt_secrets_aes256(master_key: str, secrets_path: Path) -> dict[str, str]:
    raw = secrets_path.read_bytes()
    if not raw.startswith(_AES256_PREFIX):
        raise ValueError("Not an AES-256 secrets file.")
    body = raw[len(_AES256_PREFIX) :]
    nonce, ciphertext = body[:12], body[12:]
    plain = AESGCM(_aes256_key(master_key)).decrypt(nonce, ciphertext, None)
    loaded = json.loads(plain.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("Decrypted secrets payload is invalid.")
    return {str(key): str(value) for key, value in loaded.items()}


def encrypt_secrets(secrets: dict[str, str], master_key: str, output_path: Path) -> None:
    """Prefer AES-256-GCM for new encryptions."""
    try:
        encrypt_secrets_aes256(secrets, master_key, output_path)
        return
    except ValueError:
        pass
    payload = json.dumps({key: secrets.get(key, "") for key in SECRET_FIELDS}).encode("utf-8")
    token = _fernet(master_key).encrypt(payload)
    output_path.write_bytes(token)
    logger.info("Fernet encrypted secrets written to {}", output_path)


def decrypt_secrets(master_key: str, secrets_path: Path) -> dict[str, str]:
    if not secrets_path.exists():
        return {}
    raw = secrets_path.read_bytes()
    if raw.startswith(_AES256_PREFIX):
        return decrypt_secrets_aes256(master_key, secrets_path)
    try:
        plain = _fernet(master_key).decrypt(raw)
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt secrets.enc with the provided master key.") from exc
    loaded = json.loads(plain.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("Decrypted secrets payload is invalid.")
    return {str(key): str(value) for key, value in loaded.items()}


def load_secrets_into_settings(settings_obj: Any) -> None:
    master_key = getattr(settings_obj, "CYBERSENTINEL_MASTER_KEY", "")
    secrets_path = Path(getattr(settings_obj, "SECRETS_ENC_PATH"))
    if not master_key or not secrets_path.exists():
        return
    decrypted = decrypt_secrets(master_key, secrets_path)
    for field in SECRET_FIELDS:
        if field in decrypted and decrypted[field]:
            setattr(settings_obj, field, decrypted[field])


def bootstrap_encrypt_from_env(settings_obj: Any) -> None:
    """One-time helper: encrypt plain .env secret values into secrets.enc."""
    master_key = getattr(settings_obj, "CYBERSENTINEL_MASTER_KEY", "")
    secrets_path = Path(getattr(settings_obj, "SECRETS_ENC_PATH"))
    if not master_key:
        raise ValueError("Set CYBERSENTINEL_MASTER_KEY before encrypting secrets.")
    secrets = {field: getattr(settings_obj, field, "") for field in SECRET_FIELDS}
    if not any(secrets.values()):
        raise ValueError("No secret values found in settings to encrypt.")
    encrypt_secrets(secrets, master_key, secrets_path)


if __name__ == "__main__":
    import argparse

    from core.config import Settings

    parser = argparse.ArgumentParser(description="Encrypt CyberSentinel secrets into secrets.enc")
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Read secret values from .env and write secrets.enc using CYBERSENTINEL_MASTER_KEY",
    )
    args = parser.parse_args()
    if args.encrypt:
        bootstrap_encrypt_from_env(Settings())
        print("secrets.enc created successfully.")
