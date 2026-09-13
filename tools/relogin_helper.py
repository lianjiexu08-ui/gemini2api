#!/usr/bin/env python3
"""Local-only relogin helper.

Secrets are stored in macOS Keychain, never in the gemini2api server or repo.
This helper launches a dedicated Chrome profile through the account proxy and
can generate a TOTP code locally. Google may still require an interactive
challenge; the helper never sends credentials over the network itself.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

SERVICE = "gemini2api-relogin"


def keychain_get(account: str) -> dict:
    p = subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"], capture_output=True, text=True)
    if p.returncode:
        return {}
    try:
        return json.loads(p.stdout.strip())
    except Exception:
        return {}


def keychain_put(account: str, value: dict) -> None:
    payload = json.dumps(value, ensure_ascii=False)
    subprocess.run(["security", "delete-generic-password", "-s", SERVICE, "-a", account], capture_output=True)
    r = subprocess.run(["security", "add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", payload], capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(r.stderr.strip() or "无法写入 macOS Keychain")


def totp(secret: str, digits: int = 6, period: int = 30) -> str:
    raw = base64.b32decode(secret.replace(" ", "").upper() + "=" * ((8 - len(secret.replace(" ", "")) % 8) % 8))
    counter = int(time.time()) // period
    digest = hmac.new(raw, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def launch(data: dict) -> None:
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    profile = data.get("profile_dir") or str(Path.home() / "Library/Application Support/Google/Chrome")
    args = [chrome, f"--user-data-dir={profile}", "https://gemini.google.com/app"]
    if data.get("proxy"):
        args.insert(1, f"--proxy-server={data['proxy']}")
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> None:
    ap = argparse.ArgumentParser(description="gemini2api 本机重登助手")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set", help="保存账号凭据到 macOS Keychain")
    s.add_argument("account")
    s.add_argument("--email", required=True)
    s.add_argument("--password", required=True)
    s.add_argument("--totp-secret")
    s.add_argument("--proxy")
    s.add_argument("--profile-dir")
    t = sub.add_parser("code", help="生成当前 TOTP（只在本机输出）")
    t.add_argument("account")
    l = sub.add_parser("launch", help="通过该账号代理启动 Chrome")
    l.add_argument("account")
    args = ap.parse_args()
    if args.cmd == "set":
        keychain_put(args.account, {"email": args.email, "password": args.password, "totp_secret": args.totp_secret, "proxy": args.proxy, "profile_dir": args.profile_dir})
    elif args.cmd == "code":
        data = keychain_get(args.account)
        if not data.get("totp_secret"):
            raise SystemExit("该账号没有配置 TOTP 密钥")
        print(totp(data["totp_secret"]))
    elif args.cmd == "launch":
        data = keychain_get(args.account)
        if not data:
            raise SystemExit("Keychain 中没有该账号")
        launch(data)


if __name__ == "__main__":
    main()
