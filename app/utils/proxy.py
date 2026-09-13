"""Proxy address normalization shared by HTTP clients and Playwright."""
from __future__ import annotations

from urllib.parse import quote, unquote, urlsplit


def normalize_proxy(value: str | None) -> str | None:
    """Return a URL accepted by curl clients.

    Besides regular URLs, accept the common ``host:port:user:password`` form.
    Splitting at most three times keeps colons in the password intact.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if "://" not in raw:
        parts = raw.split(":", 3)
        if len(parts) == 4 and parts[1].isdigit():
            host, port, username, password = parts
            if host and username:
                return f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        if len(parts) == 2 and parts[1].isdigit() and parts[0]:
            return f"http://{parts[0]}:{parts[1]}"
    return raw


def playwright_proxy(value: str | None) -> dict | None:
    """Convert a proxy URL to Playwright's server/username/password object."""
    normalized = normalize_proxy(value)
    if not normalized:
        return None
    parsed = urlsplit(normalized)
    try:
        port = parsed.port
    except ValueError:
        return {"server": normalized}
    if not parsed.hostname or not port:
        return {"server": normalized}
    scheme = parsed.scheme or "http"
    server = f"{scheme}://{parsed.hostname}:{port}"
    result = {"server": server}
    if parsed.username is not None:
        result["username"] = unquote(parsed.username)
    if parsed.password is not None:
        result["password"] = unquote(parsed.password)
    return result
