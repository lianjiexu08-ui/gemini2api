"""
Gemini Cookie Refresher - Playwright 自动续期

通过真实 Chromium 浏览器定时访问 Gemini 页面，
触发 Google 前端 JS 自动续期 __Secure-1PSIDTS，
然后将最新 Cookie 写入共享文件并通知 gemini2api 热更新。
"""
import os
import sys
import json
import time
import base64
import hashlib
import hmac
import requests as http_requests
from playwright.sync_api import sync_playwright

DATA_DIR = "/app/data"
STATE_DIR = os.path.join(DATA_DIR, "browser_states")
COOKIES_OUTPUT = os.path.join(DATA_DIR, "refreshed_cookies.json")
GEMINI2API_URL = os.environ.get("GEMINI2API_URL", "http://gemini2api:5918")
API_KEY = os.environ.get("API_KEY", "")
# /admin/* 路由由 verify_admin_key 鉴权：ADMIN_API_KEY 设置时用它，否则回退 API_KEY，
# 与服务端 auth.verify_admin_key 的优先级保持一致（否则通知恒 401）。
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
ADMIN_KEY = ADMIN_API_KEY or API_KEY
# 续期周期：优先读文档/.env 里的 REFRESH_INTERVAL（单位=分钟，与 README/主服务一致），
# 兼容旧的 REFRESH_INTERVAL_SECONDS（单位=秒）；最终统一换算成秒。
_interval_seconds = os.environ.get("REFRESH_INTERVAL_SECONDS")
if _interval_seconds is not None:
    REFRESH_INTERVAL = int(_interval_seconds)
else:
    REFRESH_INTERVAL = int(float(os.environ.get("REFRESH_INTERVAL", "8")) * 60)
SINGLE_RUN = os.environ.get("SINGLE_RUN", "false").lower() == "true"


def fetch_2fa_code(url, key):
    """Fetch a third-party OTP; accepts plain text or common JSON field names."""
    headers = {"Authorization": f"Bearer {key}", "X-API-Key": key} if key else {}
    resp = http_requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    try:
        data = resp.json()
        for name in ("code", "otp", "token", "verification_code"):
            if data.get(name): return str(data[name]).strip()
    except ValueError:
        pass
    return resp.text.strip()


def generate_totp(secret, digits=6, period=30):
    compact = secret.replace(" ", "").upper()
    raw = base64.b32decode(compact + "=" * ((8 - len(compact) % 8) % 8))
    counter = int(time.time()) // period
    digest = hmac.new(raw, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def load_accounts():
    accounts_file = os.path.join(DATA_DIR, "refresher_accounts.json")
    if os.path.exists(accounts_file):
        with open(accounts_file, "r") as f:
            return json.load(f)

    main_file = os.path.join(DATA_DIR, "accounts.json")
    if os.path.exists(main_file):
        try:
            with open(main_file, "r") as f:
                data = json.load(f)
            return data.get("accounts", data) if isinstance(data, (dict, list)) else []
        except Exception:
            pass

    # 默认直接读取主服务账号池，避免再维护一份 refresher_accounts.json。
    try:
        headers = {"Authorization": f"Bearer {ADMIN_KEY}"} if ADMIN_KEY else {}
        resp = http_requests.get(f"{GEMINI2API_URL}/admin/accounts", headers=headers, timeout=10)
        if resp.ok:
            rows = resp.json().get("accounts", [])
            return [{"id": a["id"], "psid": a.get("psid", ""), "psidts": a.get("psidts", ""), "label": a.get("label", a["id"])} for a in rows if a.get("id") and a.get("psid")]
    except Exception as exc:
        print(f"  [ERROR] Cannot load accounts from main service: {exc}")

    psid = os.environ.get("GEMINI_PSID", "")
    psidts = os.environ.get("GEMINI_PSIDTS", "")
    if psid:
        return [{"id": "account-0", "psid": psid, "psidts": psidts, "label": "Default"}]
    return []


def ensure_state_dir(account_id):
    path = os.path.join(STATE_DIR, account_id)
    os.makedirs(path, exist_ok=True)
    return path


def _state_psid(state_file):
    """读取 state.json 中当前的 __Secure-1PSID，用于判断配置是否已轮换。"""
    try:
        with open(state_file, "r") as f:
            state = json.load(f)
        for c in state.get("cookies", []):
            if c.get("name") == "__Secure-1PSID":
                return c.get("value")
    except Exception:
        return None
    return None


def inject_cookies_to_state(state_dir, psid, psidts):
    state_file = os.path.join(state_dir, "state.json")
    cookies = [
        {"name": "__Secure-1PSID", "value": psid, "domain": ".google.com", "path": "/", "secure": True, "httpOnly": True, "sameSite": "None"},
    ]
    # 仅在 psidts 非空时写入：present-but-empty 的 __Secure-1PSIDTS 与“缺失”语义不同，
    # 空值会污染浏览器状态、阻止 Google 前端 JS 重新签发 token（与主服务 cookie_jar 的处理一致）。
    if psidts:
        cookies.append({"name": "__Secure-1PSIDTS", "value": psidts, "domain": ".google.com", "path": "/", "secure": True, "httpOnly": True, "sameSite": "None"})
    state = {"cookies": cookies, "origins": []}
    with open(state_file, "w") as f:
        json.dump(state, f)
    print(f"  [init] Injected cookies from config into state")


def refresh_account(browser, account):
    account_id = account["id"]
    label = account.get("label", account_id)
    state_dir = ensure_state_dir(account_id)
    state_file = os.path.join(state_dir, "state.json")

    # 首次运行注入，或当 refresher_accounts.json 中的源 PSID 已被运营者轮换
    # （与 state.json 中已持久化的 PSID 不一致）时重新注入——否则旋转后的凭据被永久忽略，
    # 过期账号无法通过编辑配置恢复。
    if not os.path.exists(state_file) or _state_psid(state_file) != account["psid"]:
        inject_cookies_to_state(state_dir, account["psid"], account.get("psidts", ""))

    print(f"  [{label}] Opening browser context...")
    context = browser.new_context(
        storage_state=state_file,
        locale="en-US",
        timezone_id="America/New_York",
    )
    page = context.new_page()

    try:
        page.goto("https://gemini.google.com/app", timeout=90000, wait_until="domcontentloaded")
        time.sleep(15)

        # Cookie 失效时，尝试使用服务器加密凭据完成登录；Google 风控/手机确认仍会停在页面。
        if account.get("email") and account.get("password") and "accounts.google.com" in page.url:
            email_box = page.locator('input[type="email"]').first
            if email_box.count():
                email_box.fill(account["email"]); page.get_by_role("button", name="Next").click(); time.sleep(3)
            pw_box = page.locator('input[type="password"]').first
            if pw_box.count():
                pw_box.fill(account["password"]); page.get_by_role("button", name="Next").click(); time.sleep(4)
            if account.get("totp_secret") or (account.get("totp_url") and account.get("totp_key")):
                code = generate_totp(account["totp_secret"]) if account.get("totp_secret") else fetch_2fa_code(account["totp_url"], account["totp_key"])
                code_box = page.locator('input[name="totpPin"], input[name="code"], input[type="tel"]').first
                if code_box.count(): code_box.fill(code); page.get_by_role("button", name="Next").click(); time.sleep(8)

        cookies = context.cookies()
        psid = next((c["value"] for c in cookies if c["name"] == "__Secure-1PSID"), None)
        psidts = next((c["value"] for c in cookies if c["name"] == "__Secure-1PSIDTS"), None)

        if psid and psidts:
            context.storage_state(path=state_file)
            print(f"  [{label}] OK - PSIDTS: {psidts[:20]}...")
            return {"id": account_id, "label": label, "psid": psid, "psidts": psidts, "status": "active", "updated_at": time.time()}
        else:
            print(f"  [{label}] FAILED - Cookie not found, may need re-login")
            return {"id": account_id, "label": label, "status": "expired", "updated_at": time.time()}
    except Exception as e:
        print(f"  [{label}] ERROR - {e}")
        return {"id": account_id, "label": label, "status": "error", "error": str(e), "updated_at": time.time()}
    finally:
        context.close()


def notify_gemini2api(account_id, psid, psidts):
    headers = {"Content-Type": "application/json"}
    # /admin/* 用 ADMIN_KEY（ADMIN_API_KEY 优先，否则回退 API_KEY）。
    if ADMIN_KEY:
        headers["Authorization"] = f"Bearer {ADMIN_KEY}"

    # 优先按账号 ID 精确更新（多账号隔离）
    try:
        resp = http_requests.put(
            f"{GEMINI2API_URL}/admin/accounts/{account_id}/cookies",
            json={"psid": psid, "psidts": psidts},
            headers=headers,
            timeout=10
        )
        if resp.status_code == 200:
            print(f"  [notify] {account_id} cookies updated via PUT")
            return True
        elif resp.status_code == 404:
            # 账号不存在，fallback 到全局 reload
            resp2 = http_requests.post(
                f"{GEMINI2API_URL}/admin/reload-cookies",
                json={"psid": psid, "psidts": psidts},
                headers=headers,
                timeout=10
            )
            if resp2.status_code == 200:
                print(f"  [notify] cookies reloaded via POST (account not in pool)")
                return True
            elif resp2.status_code == 401:
                print(f"  [notify] auth rejected (401) — set ADMIN_API_KEY/API_KEY to match the server's admin key")
                return False
            else:
                print(f"  [notify] reload failed: {resp2.status_code} {resp2.text[:100]}")
                return False
        elif resp.status_code == 401:
            print(f"  [notify] auth rejected (401) — set ADMIN_API_KEY/API_KEY to match the server's admin key")
            return False
        else:
            print(f"  [notify] PUT failed: {resp.status_code} {resp.text[:100]}")
            return False
    except Exception as e:
        print(f"  [notify] Failed to reach gemini2api: {e}")
        return False


def refresh_all():
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*50}")
    print(f"[{ts}] Starting cookie refresh cycle...")
    print(f"{'='*50}")

    accounts = load_accounts()
    if not accounts:
        print("  [ERROR] No accounts configured!")
        print("  Set GEMINI_PSID/GEMINI_PSIDTS env vars or create data/refresher_accounts.json")
        return

    os.makedirs(DATA_DIR, exist_ok=True)
    results = []

    with sync_playwright() as p:
        launch_args = [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--single-process",
                "--no-zygote",
                "--disable-extensions",
            ]

        for i, account in enumerate(accounts):
            # credentials are fetched only for this run and never written to refresher output
            try:
                h = {"Authorization": f"Bearer {ADMIN_KEY}"} if ADMIN_KEY else {}
                cr = http_requests.get(f"{GEMINI2API_URL}/admin/accounts/{account['id']}/credentials", headers=h, timeout=10)
                if cr.ok: account.update(cr.json())
            except Exception as exc:
                print(f"  [{account.get('id')}] credential fetch skipped: {exc}")
            proxy = account.get("proxy")
            browser = p.chromium.launch(headless=True, proxy={"server": proxy} if proxy else None, args=launch_args)
            result = refresh_account(browser, account)
            browser.close()
            results.append(result)
            if i < len(accounts) - 1:
                time.sleep(5)

        browser.close()

    with open(COOKIES_OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

    active = [r for r in results if r.get("status") == "active"]
    for acc in active:
        notify_gemini2api(acc["id"], acc["psid"], acc["psidts"])

    print(f"\n  Summary: {len(active)}/{len(results)} accounts active")


if __name__ == "__main__":
    if SINGLE_RUN:
        refresh_all()
        print("\n[Single run mode] Done, exiting.")
        sys.exit(0)

    print(f"Gemini Cookie Refresher started (interval: {REFRESH_INTERVAL}s; set REFRESH_INTERVAL in minutes)")
    while True:
        try:
            refresh_all()
        except Exception as e:
            print(f"[FATAL] {e}")
        print(f"\nSleeping {REFRESH_INTERVAL}s until next refresh...")
        time.sleep(REFRESH_INTERVAL)
