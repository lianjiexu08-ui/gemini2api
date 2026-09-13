"""Persistent proxy pool used by the admin panel.

The account pool still stores the selected proxy on each account.  This store keeps
an optional managed inventory so operators can import a list once and select entries
when editing accounts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from app.utils.atomic_io import atomic_write_text
from app.utils.proxy import normalize_proxy


class ProxyStore:
    def __init__(self, path: str = "data/proxies.json"):
        self.path = Path(path)

    def _read(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text())
        except Exception:
            return []
        items = raw if isinstance(raw, list) else raw.get("proxies", [])
        return [dict(item) for item in items if isinstance(item, dict) and item.get("proxy")]

    def _write(self, items: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps({"proxies": items}, ensure_ascii=False, indent=2))

    @staticmethod
    def _id(proxy: str) -> str:
        digest = hashlib.sha256(proxy.encode("utf-8")).hexdigest()[:16]
        return f"proxy-{digest}"

    def list(self) -> list[dict]:
        return self._read()

    def import_values(self, values: Iterable[str]) -> tuple[list[dict], int]:
        items = self._read()
        by_proxy = {item.get("proxy"): item for item in items}
        added: list[dict] = []
        for value in values:
            normalized = normalize_proxy(value)
            if not normalized or normalized in by_proxy:
                continue
            entry = {"id": self._id(normalized), "proxy": normalized}
            by_proxy[normalized] = entry
            items.append(entry)
            added.append(entry)
        if added:
            self._write(items)
        return added, len(items)

    def remove(self, proxy_id: str) -> bool:
        items = self._read()
        kept = [item for item in items if item.get("id") != proxy_id]
        if len(kept) == len(items):
            return False
        self._write(kept)
        return True


proxy_store = ProxyStore()
