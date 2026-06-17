"""
core/secrets.py

Encrypt sensitive settings at rest with Fernet (AES-128-CBC + HMAC via cryptography).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from loguru import logger

SECRET_FIELDS = (
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "API_KEY",
)


def _fernet(master_key: str) -> Fernet:
    normalized = master_key.strip().encode("utf-8")
    if len(normalized) != 44:
        raise ValueError("CYBERSENTINEL_MASTER_KEY must be a Fernet key (44 url-safe base64 chars).")
    return Fernet(normalized)


def encrypt_secrets(secrets: dict[str, str], master_key: str, output_path: Path) -> None:
    payload = json.dumps({key: secrets.get(key, "") for key in SECRET_FIELDS}).encode("utf-8")
    token = _fernet(master_key).encrypt(payload)
    output_path.write_bytes(token)
    logger.info("Encrypted secrets written to {}", output_path)


def decrypt_secrets(master_key: str, secrets_path: Path) -> dict[str, str]:
    if not secrets_path.exists():
        return {}
    try:
        raw = _fernet(master_key).decrypt(secrets_path.read_bytes())
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt secrets.enc with the provided master key.") from exc
    loaded = json.loads(raw.decode("utf-8"))
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
