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
from http.server import BaseHTTPRequestHandler, HTTPServer
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


def auto_login(data: dict) -> None:
    """Best-effort local UI fill; secrets never leave this process."""
    launch(data)
    time.sleep(4)
    email = data.get("email", "")
    password = data.get("password", "")
    if not email or not password:
        raise SystemExit("Keychain 中缺少邮箱或密码")
    # Chrome login UI is intentionally driven locally through Accessibility.
    # It may pause on Google risk checks; no server receives these values.
    script = f'''tell application "Google Chrome" to activate
tell application "System Events"
  keystroke {json.dumps(email)}
  key code 36
  delay 2
  keystroke {json.dumps(password)}
  key code 36
end tell'''
    subprocess.run(["osascript", "-e", script], check=False)
    if data.get("totp_secret"):
        time.sleep(3)
        script2 = f'''tell application "System Events"
  keystroke {json.dumps(totp(data["totp_secret"]))}
  key code 36
end tell'''
        subprocess.run(["osascript", "-e", script2], check=False)


def serve() -> None:
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, code, body):
            raw = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers(); self.wfile.write(raw)
        def do_OPTIONS(self): self._reply(204, {})
        def do_POST(self):
            if self.path != "/relogin": self._reply(404, {"error": "not found"}); return
            try:
                n = int(self.headers.get("Content-Length", "0")); body = json.loads(self.rfile.read(n) or b"{}")
                data = keychain_get(body.get("account_id", ""))
                if not data: raise ValueError("账号不在本机 Keychain")
                auto_login(data); self._reply(200, {"status": "started"})
            except Exception as exc: self._reply(400, {"error": str(exc)})
        def log_message(self, *_): pass
    HTTPServer(("127.0.0.1", 17891), Handler).serve_forever()


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
    a = sub.add_parser("auto", help="本机自动填写邮箱、密码和 TOTP")
    a.add_argument("account")
    sub.add_parser("serve", help="启动浏览器点击触发的本地重登服务")
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
    elif args.cmd == "auto":
        data = keychain_get(args.account)
        if not data:
            raise SystemExit("Keychain 中没有该账号")
        auto_login(data)
    elif args.cmd == "serve":
        serve()


if __name__ == "__main__":
    main()
