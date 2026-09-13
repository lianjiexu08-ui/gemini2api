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
from urllib.parse import quote, unquote, urlsplit
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


def normalize_proxy(value):
    """Accept URL form and host:port:user:password, return a URL form."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if "://" not in raw:
        parts = raw.split(":", 3)
        if len(parts) == 4 and parts[1].isdigit() and parts[0] and parts[2]:
            host, port, username, password = parts
            return f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        if len(parts) == 2 and parts[1].isdigit() and parts[0]:
            return f"http://{parts[0]}:{parts[1]}"
    return raw


def playwright_proxy(value):
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
    result = {"server": f"{parsed.scheme or 'http'}://{parsed.hostname}:{port}"}
    if parsed.username is not None:
        result["username"] = unquote(parsed.username)
    if parsed.password is not None:
        result["password"] = unquote(parsed.password)
    return result


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


def safe_error(exc, account=None):
    """Return a useful error without leaking login credentials into logs."""
    text = str(exc)
    if account:
        for key in ("password", "totp_secret", "totp_key", "email"):
            value = account.get(key)
            if value:
                text = text.replace(str(value), "[redacted]")
    return text[:240]


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


def write_relogin_status(account_id, status, message):
    """写共享状态日志，供管理面板实时展示。"""
    path = os.path.join(DATA_DIR, "relogin_status", f"{account_id}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"account_id": account_id, "status": status, "message": message, "updated_at": time.time(), "logs": []}
    try:
        with open(path, "r") as f:
            old = json.load(f)
        payload["logs"] = old.get("logs", [])[-19:]
    except Exception:
        pass
    payload["logs"].append({"time": time.strftime("%H:%M:%S"), "message": message})
    with open(path, "w") as f:
        json.dump(payload, f, ensure_ascii=False)


def load_relogin_requests():
    """读取面板发出的重登请求，返回 account_id -> request file 映射。

    主服务会在共享 data/relogin_requests/{account_id}.json 写入一个请求文件。
    文件名本身也作为兜底 ID，这样即使请求内容损坏也不会让刷新循环中断。
    """
    request_dir = os.path.join(DATA_DIR, "relogin_requests")
    if not os.path.isdir(request_dir):
        return {}

    pending = {}
    for name in os.listdir(request_dir):
        if not name.endswith(".json"):
            continue
        path = os.path.join(request_dir, name)
        account_id = name[:-5]
        try:
            with open(path, "r") as f:
                payload = json.load(f)
            account_id = str(payload.get("account_id") or account_id)
        except Exception as exc:
            print(f"  [relogin] ignoring malformed request {name}: {exc}")
        if account_id:
            pending[account_id] = path
    return pending


def prioritize_relogin_accounts(accounts, pending):
    """将面板点选的账号移到本轮最前面，保持其余账号原有顺序。"""
    if not pending:
        return accounts
    requested = [a for a in accounts if a.get("id") in pending]
    regular = [a for a in accounts if a.get("id") not in pending]
    if requested:
        print(f"  [relogin] prioritizing: {', '.join(a['id'] for a in requested)}")
    return requested + regular


def consume_relogin_request(account_id, pending):
    """删除已开始处理的请求，避免每个刷新周期重复触发重登。"""
    path = pending.get(account_id)
    if not path:
        return
    try:
        os.unlink(path)
        print(f"  [relogin] consumed request for {account_id}")
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"  [relogin] could not consume {account_id}: {exc}")


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
        # 同一 Google Profile 的多账号共享 __Secure-1PSID，必须通过
        # authuser 选择器指定目标账号，否则 Playwright 总会落到默认账号。
        authuser = account.get("authuser")
        login_url = "https://gemini.google.com/app"
        if authuser is not None and str(authuser).strip() not in ("", "0"):
            login_url += f"?authuser={quote(str(authuser).strip(), safe='')}"
        page.goto(login_url, timeout=90000, wait_until="domcontentloaded")
        time.sleep(15)

        if account.get("_force_login"):
            email_inputs = page.locator('input[type="email"]:visible').count()
            password_inputs = page.locator('input[type="password"]:visible').count()
            if account.get("email") and account.get("password") and not email_inputs and not password_inputs:
                # 失效的 PSID 可能仍让 Gemini URL 返回 200，但不会触发
                # accounts.google.com 重定向。手动重登时显式走 Google 登录入口，
                # 同时保留 continue/authuser，确保回到目标账号而不是默认账号。
                continue_url = quote(login_url, safe="")
                service_url = f"https://accounts.google.com/ServiceLogin?continue={continue_url}"
                if authuser is not None and str(authuser).strip() not in ("", "0"):
                    service_url += f"&authuser={quote(str(authuser).strip(), safe='')}"
                page.goto(service_url, timeout=90000, wait_until="domcontentloaded")
                time.sleep(5)
                email_inputs = page.locator('input[type="email"]:visible').count()
                password_inputs = page.locator('input[type="password"]:visible').count()
            print(
                f"  [{label}] Login probe: url={page.url[:120]} "
                f"email_inputs={email_inputs} password_inputs={password_inputs}"
            )

        # Cookie 失效时，尝试使用服务器加密凭据完成登录；Google 风控/手机确认仍会停在页面。
        if account.get("email") and account.get("password") and "accounts.google.com" in page.url:
            email_box = page.locator('input[type="email"]:visible').first
            if email_box.count():
                email_box.fill(account["email"]); page.get_by_role("button", name="Next").click(); time.sleep(3)
            pw_box = page.locator('input[type="password"]:visible').first
            if pw_box.count():
                pw_box.fill(account["password"]); page.get_by_role("button", name="Next").click(); time.sleep(4)
            if account.get("totp_secret") or (account.get("totp_url") and account.get("totp_key")):
                code = generate_totp(account["totp_secret"]) if account.get("totp_secret") else fetch_2fa_code(account["totp_url"], account["totp_key"])
                code_box = page.locator('input[name="totpPin"]:visible, input[name="code"]:visible, input[type="tel"]:visible').first
                if code_box.count(): code_box.fill(code); page.get_by_role("button", name="Next").click(); time.sleep(8)

        # 不能把登录页里残留的旧 Cookie 误判成新会话。没有凭据、密码错误、
        # 2FA/风控未完成时，Playwright 仍可能带着旧 Cookie 返回。
        if "accounts.google.com" in page.url:
            print(f"  [{label}] FAILED - still on Google login page")
            return {
                "id": account_id,
                "label": label,
                "status": "expired",
                "error": "仍停留在 Google 登录页，账号凭据或 2FA 未完成",
                "updated_at": time.time(),
            }

        cookies = context.cookies()
        psid = next((c["value"] for c in cookies if c["name"] == "__Secure-1PSID"), None)
        psidts = next((c["value"] for c in cookies if c["name"] == "__Secure-1PSIDTS"), None)

        if psid and psidts:
            context.storage_state(path=state_file)
            print(f"  [{label}] OK - PSIDTS: {psidts[:20]}...")
            return {
                "id": account_id,
                "label": label,
                "psid": psid,
                "psidts": psidts,
                "cookie_changed": psid != account.get("psid") or psidts != account.get("psidts"),
                "status": "active",
                "updated_at": time.time(),
            }
        else:
            print(f"  [{label}] FAILED - Cookie not found, may need re-login")
            return {"id": account_id, "label": label, "status": "expired", "error": "未获取到有效 Cookie", "updated_at": time.time()}
    except Exception as e:
        message = safe_error(e, account)
        print(f"  [{label}] ERROR - {message}")
        return {"id": account_id, "label": label, "status": "error", "error": message, "updated_at": time.time()}
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
            return True, ""
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
                return True, ""
            elif resp2.status_code == 401:
                print(f"  [notify] auth rejected (401) — set ADMIN_API_KEY/API_KEY to match the server's admin key")
                return False, "管理密钥不匹配（401）"
            else:
                print(f"  [notify] reload failed: {resp2.status_code} {resp2.text[:100]}")
                return False, f"服务器回写接口返回 HTTP {resp2.status_code}: {resp2.text[:120]}"
        elif resp.status_code == 401:
            print(f"  [notify] auth rejected (401) — set ADMIN_API_KEY/API_KEY to match the server's admin key")
            return False, "管理密钥不匹配（401）"
        else:
            print(f"  [notify] PUT failed: {resp.status_code} {resp.text[:180]}")
            try:
                detail = resp.json().get("error", {}).get("message", "")
            except Exception:
                detail = ""
            return False, f"服务器拒绝 Cookie（HTTP {resp.status_code}）" + (f"：{detail}" if detail else "")
    except Exception as e:
        print(f"  [notify] Failed to reach gemini2api: {e}")
        return False, f"无法连接主服务：{str(e)[:120]}"


def refresh_all():
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*50}")
    print(f"[{ts}] Starting cookie refresh cycle...")
    print(f"{'='*50}")

    pending_relogins = load_relogin_requests()
    accounts = load_accounts()
    if not accounts:
        print("  [ERROR] No accounts configured!")
        print("  Set GEMINI_PSID/GEMINI_PSIDTS env vars or create data/refresher_accounts.json")
        return

    # “重登”按钮写入共享目录后，该账号会在本轮排到最前面；处理一次后
    # 消费请求文件，后续周期恢复普通的全量续期顺序。
    accounts = prioritize_relogin_accounts(accounts, pending_relogins)
    known_ids = {a.get("id") for a in accounts}
    for account_id in list(pending_relogins):
        if account_id not in known_ids:
            print(f"  [relogin] dropping request for unknown account {account_id}")
            consume_relogin_request(account_id, pending_relogins)

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

        processed_ids = set()
        for i in range(len(accounts)):
            # 刷新一轮期间也持续读取队列。这样用户在整轮刷新开始后点击
            # “重登”，不会被迫等待剩余账号全部跑完才开始处理。
            pending_now = load_relogin_requests()
            pending_relogins.update(pending_now)
            remaining = [a for a in accounts if a.get("id") not in processed_ids]
            requested_accounts = [a for a in remaining if a.get("id") in pending_now]
            account = (requested_accounts or remaining)[0]
            account_id = account.get("id")
            processed_ids.add(account_id)
            requested = account_id in pending_relogins
            if requested:
                write_relogin_status(account_id, "processing", "正在启动 Playwright 浏览器")
            # credentials are fetched only for this run and never written to refresher output
            try:
                h = {"Authorization": f"Bearer {ADMIN_KEY}"} if ADMIN_KEY else {}
                cr = http_requests.get(f"{GEMINI2API_URL}/admin/accounts/{account_id}/credentials", headers=h, timeout=10)
                if cr.ok:
                    account.update(cr.json())
                elif requested and cr.status_code == 404:
                    write_relogin_status(account_id, "processing", "该账号未配置登录凭据，将检查现有 Cookie")
            except Exception as exc:
                print(f"  [{account_id}] credential fetch skipped: {exc}")
            proxy = normalize_proxy(account.get("proxy"))
            if requested:
                account["_force_login"] = True
            if requested:
                write_relogin_status(account_id, "processing", "凭据已读取，正在通过账号代理打开登录页")
            browser = None
            try:
                browser = p.chromium.launch(headless=True, proxy=playwright_proxy(proxy), args=launch_args)
                if requested:
                    write_relogin_status(account_id, "processing", "浏览器已启动，正在登录并获取 Cookie")
                result = refresh_account(browser, account)
                if requested and result.get("status") == "active":
                    write_relogin_status(account_id, "cookies_found", "已获取新 Cookie，正在回写账号池")
            except Exception as exc:
                message = safe_error(exc, account)
                print(f"  [{account_id}] ERROR - browser refresh failed: {message}")
                if requested:
                    write_relogin_status(account_id, "failed", f"浏览器重登失败：{message}")
                result = {"id": account_id, "label": account.get("label", account_id), "status": "error", "error": message, "updated_at": time.time()}
            finally:
                if browser is not None:
                    browser.close()
                # 无论成功、Cookie 失效还是浏览器异常，都只消费本次请求，
                # 避免单个坏账号在每个周期阻塞整个账号池。
                consume_relogin_request(account_id, pending_relogins)
            results.append(result)
            # 手动点击的账号在本账号浏览器结束后立即回写，避免等待整轮账号
            # 刷新和其它账号的 RotateCookies 请求，状态日志也能及时收敛。
            if requested:
                if result.get("status") != "active":
                    write_relogin_status(
                        account_id,
                        "failed",
                        result.get("error") or "未获取到有效 Cookie，可能需要检查账号凭据或 Google 验证",
                    )
                else:
                    synced, notify_error = notify_gemini2api(account_id, result["psid"], result["psidts"])
                    write_relogin_status(
                        account_id,
                        "completed" if synced else "failed",
                        (
                            "新 Cookie 已自动写回账号池"
                            if result.get("cookie_changed")
                            else "Cookie 未变化，但服务器确认当前会话仍有效"
                        ) if synced else (
                            "Cookie 未变化，服务器验证失败：" + notify_error
                            if not result.get("cookie_changed")
                            else "Cookie 已获取，但回写账号池失败：" + notify_error
                        ),
                    )
            if i < len(accounts) - 1:
                time.sleep(5)

    with open(COOKIES_OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

    active = [r for r in results if r.get("status") == "active"]
    for acc in active:
        # 定时续期只需要把真正变化的 Cookie 写回，避免旧 Cookie 反复触发
        # RotateCookies 401/503；手动重登账号已在上面的即时分支处理。
        if acc["id"] in pending_relogins or not acc.get("cookie_changed"):
            continue
        notify_gemini2api(acc["id"], acc["psid"], acc["psidts"])

    print(f"\n  Summary: {len(active)}/{len(results)} accounts active")


if __name__ == "__main__":
    if SINGLE_RUN:
        refresh_all()
        print("\n[Single run mode] Done, exiting.")
        sys.exit(0)

    print(f"Gemini Cookie Refresher started (interval: {REFRESH_INTERVAL}s; queued relogin is checked every 2s)")
    last_cycle = 0.0
    while True:
        request_dir = os.path.join(DATA_DIR, "relogin_requests")
        queued = os.path.isdir(request_dir) and any(name.endswith(".json") for name in os.listdir(request_dir))
        if queued or time.time() - last_cycle >= REFRESH_INTERVAL:
            try:
                refresh_all()
            except Exception as e:
                print(f"[FATAL] {e}")
            last_cycle = time.time()
            print(f"\nSleeping until next refresh (interval {REFRESH_INTERVAL}s; queued relogin wakes within 2s)...")
        time.sleep(2)
