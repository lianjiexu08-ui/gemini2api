"""Encrypted server-side storage for optional relogin credentials."""
from __future__ import annotations
import json
from pathlib import Path
from cryptography.fernet import Fernet
from app.config import settings


def _fernet() -> Fernet:
    key = settings.credentials_encryption_key.strip()
    if not key:
        raise RuntimeError("CREDENTIALS_ENCRYPTION_KEY is not configured")
    return Fernet(key.encode())


def _path() -> Path:
    return Path(settings.credentials_file)


def load_all() -> dict:
    p = _path()
    if not p.exists():
        return {}
    try:
        return json.loads(_fernet().decrypt(p.read_bytes()).decode())
    except Exception as exc:
        raise RuntimeError(f"credential vault cannot be decrypted: {exc}") from exc


def put(account_id: str, values: dict) -> None:
    data = load_all()
    data[account_id] = values
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(_fernet().encrypt(json.dumps(data, ensure_ascii=False).encode()))
    try:
        p.chmod(0o600)
    except OSError:
        pass


def delete(account_id: str) -> None:
    data = load_all()
    data.pop(account_id, None)
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(_fernet().encrypt(json.dumps(data, ensure_ascii=False).encode()))
    try:
        p.chmod(0o600)
    except OSError:
        pass
