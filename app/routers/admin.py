import asyncio
import logging
import os
import platform
import sys
import time
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.config import APP_VERSION, mask_secret
from app.core.account_pool import account_pool

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["Admin"])

_start_time = time.time()


def _masked_status() -> dict:
    """VULN-003：在响应层对 psid（Google 登录态 Cookie）脱敏，不改 account_pool 内部数据。
    get_status() 每次返回新 dict，可安全就地掩码。保留字段，仅掩码值。"""
    status = account_pool.get_status()
    for acc in status.get("accounts", []):
        if acc.get("psid"):
            acc["psid"] = mask_secret(acc["psid"])
    return status


class ReloadCookiesRequest(BaseModel):
    psid: Optional[str] = None
    psidts: Optional[str] = None


class AddAccountRequest(BaseModel):
    psid: Optional[str] = None
    psidts: str = ""
    label: str = ""
    # 直接粘贴整段 Cookie 字符串（如从浏览器 F12 复制的完整 Cookie 头），
    # 服务端自动解析 __Secure-1PSID / __Secure-1PSIDTS，与 psid/psidts 字段二选一
    cookie: Optional[str] = None


def _extract_cookie_value(raw: str, name: str) -> Optional[str]:
    """从整段 Cookie 字符串中提取指定名称的值（如 F12 复制的 `a=1; b=2` 格式）。
    容忍空白、首尾引号；值含 % 时按 URL 编码解码（document.cookie 导出场景）。"""
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        if key.strip() != name:
            continue
        value = value.strip().strip('"').strip("'")
        if not value:
            return None
        if "%" in value:
            from urllib.parse import unquote

            value = unquote(value)
        return value or None
    return None


def _resolve_credentials(
    psid: Optional[str], psidts: str, cookie: Optional[str]
) -> tuple[Optional[str], str]:
    """合并显式字段与整段 Cookie：Cookie 字符串中解析到的值优先。"""
    if cookie:
        parsed_psid = _extract_cookie_value(cookie, "__Secure-1PSID")
        parsed_psidts = _extract_cookie_value(cookie, "__Secure-1PSIDTS")
        if parsed_psid:
            psid = parsed_psid
        if parsed_psidts:
            psidts = parsed_psidts
    return psid, psidts


async def _auto_label_account(account_id: str):
    """标签留空时，从网页会话抓取 Google 账号邮箱作为标签（后台异步执行）。"""
    await asyncio.sleep(0)  # 让上号响应先返回
    for acc in account_pool.accounts:
        if acc.id == account_id and acc.client:
            try:
                email = await asyncio.wait_for(acc.client.get_account_email(), timeout=20)
            except Exception as e:
                logger.debug(f"auto label failed for {account_id}: {e}")
                return
            if email:
                account_pool.rename_account(account_id, email)
                logger.info(f"Account {account_id} auto-labeled as {email}")
            return


@router.post("/reload-cookies")
async def reload_cookies(req: ReloadCookiesRequest = None):
    # 修复：result 仅在 `if account.client:` 内赋值，若账号池为空或所有账号无 client，
    # 循环体不执行、result 始终未绑定，后续 result.get(...) 会抛 UnboundLocalError
    # （显式 cookie 分支直接 500，.env 分支被误判为 "Failed to read .env"），
    # 且末尾 "No accounts available" 成为死代码。初始化 result=None 并在循环后兜底返回 503。
    if req and (req.psid or req.psidts):
        result = None
        for account in account_pool.accounts:
            if account.client:
                result = await account.client.reload_cookies(psid=req.psid, psidts=req.psidts)
                if result.get("success"):
                    return {"status": "ok", "message": "Cookies reloaded successfully", "healthy": True}
        if result is None:
            return JSONResponse(
                status_code=503,
                content={"error": {"message": "No accounts available", "type": "reload_error"}},
            )
        return JSONResponse(
            status_code=503,
            content={"error": {"message": result.get("error", "Cookie reload failed"), "type": "reload_error"}},
        )
    else:
        from app.config import Settings
        try:
            fresh = Settings()
            result = None
            for account in account_pool.accounts:
                if account.client:
                    result = await account.client.reload_cookies(
                        psid=fresh.gemini_psid,
                        psidts=fresh.gemini_psidts,
                    )
                    if result.get("success"):
                        return {"status": "ok", "message": "Cookies reloaded successfully", "healthy": True}
            if result is None:
                return JSONResponse(
                    status_code=503,
                    content={"error": {"message": "No accounts available", "type": "reload_error"}},
                )
            return JSONResponse(
                status_code=503,
                content={"error": {"message": result.get("error", "Cookie reload failed"), "type": "reload_error"}},
            )
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": {"message": f"Failed to read .env: {e}", "type": "config_error"}},
            )


@router.get("/status")
async def admin_status():
    return _masked_status()


@router.get("/system-info")
async def system_info():
    import psutil
    proc = psutil.Process(os.getpid())
    mem = proc.memory_info()
    total_mem = psutil.virtual_memory().total
    uptime_seconds = int(time.time() - _start_time)

    return {
        "version": APP_VERSION,
        "python_version": platform.python_version(),
        "server_time": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
        "os": f"{platform.system()} {platform.release()}",
        "memory_usage": mem.rss // (1024 * 1024),
        "memory_total": total_mem // (1024 * 1024),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "pid": os.getpid(),
        "run_mode": "Docker" if os.path.exists("/.dockerenv") else "直接运行",
        "uptime_seconds": uptime_seconds,
    }


@router.get("/check-account")
async def check_all_accounts():
    results = await account_pool.check_all()
    return {"accounts": results}


@router.get("/health-history")
async def health_history():
    history = []
    for account in account_pool.accounts:
        if account.client:
            history.extend(
                {**r, "account_id": account.id} for r in account.client.check_history
            )
    history.sort(key=lambda x: x.get("checked_at", ""), reverse=True)
    return {"total": len(history), "records": history[:50]}


@router.get("/accounts")
async def list_accounts():
    return _masked_status()


@router.post("/accounts")
async def add_account(req: AddAccountRequest):
    psid, psidts = _resolve_credentials(req.psid, req.psidts, req.cookie)
    if not psid:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "psid is required: provide psid or a cookie string containing __Secure-1PSID",
                    "type": "invalid_request",
                }
            },
        )
    try:
        account, created = await account_pool.add_account(
            psid=psid,
            psidts=psidts,
            label=req.label,
        )
        if created and not (req.label or "").strip():
            # 新号且标签留空：后台自动抓 Google 账号邮箱命名，不阻塞上号响应
            asyncio.create_task(_auto_label_account(account.id))
        return {
            "status": "ok",
            "account": {
                "id": account.id,
                "label": account.label,
                "status": account.status.value,
            },
            "created": created,
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": {"message": str(e), "type": "add_account_error"}},
        )


@router.delete("/accounts/{account_id}")
async def remove_account(account_id: str):
    removed = await account_pool.remove_account(account_id)
    if removed:
        return {"status": "ok", "message": f"Account {account_id} removed"}
    return JSONResponse(
        status_code=404,
        content={"error": {"message": f"Account {account_id} not found", "type": "not_found"}},
    )


@router.get("/accounts/{account_id}/check")
async def check_single_account(account_id: str):
    try:
        result = await account_pool.check_account(account_id)
        return result
    except ValueError as e:
        return JSONResponse(
            status_code=404,
            content={"error": {"message": str(e), "type": "not_found"}},
        )


class UpdateCookiesRequest(BaseModel):
    psid: Optional[str] = None
    psidts: str = ""
    # 同 AddAccountRequest：可直接粘贴整段 Cookie 字符串自动解析
    cookie: Optional[str] = None


class UpdateAccountRequest(BaseModel):
    label: Optional[str] = None


class TestAccountRequest(BaseModel):
    model: str = "gemini-pro"
    prompt: str = "Say ok"


class PreviewAccountRequest(BaseModel):
    """上号前预览：识别 Cookie 对应的真实 Google 账号（邮箱+指纹+是否已在池中）。"""

    cookie: Optional[str] = None
    psid: Optional[str] = None
    psidts: str = ""


@router.post("/accounts/preview")
async def preview_account(req: PreviewAccountRequest):
    """干跑验证：不起号入池，只回答「这段 Cookie 是谁」。"""
    psid, psidts = _resolve_credentials(req.psid, req.psidts, req.cookie)
    if not psid:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "psid is required: provide psid or a cookie string containing __Secure-1PSID", "type": "invalid_request"}},
        )
    duplicate = next((a for a in account_pool.accounts if a.psid == psid), None)
    from app.core.gemini_client import GeminiWebClient

    client = GeminiWebClient(psid=psid, psidts=psidts)
    # 预览要回答的是「这段（新提交的）Cookie 是谁/活没活」，必须先清掉磁盘上
    # 同 PSID 的陈旧 Cookie 罐，否则「磁盘优先」会拿旧 cookie 判新 cookie 的死刑。
    client.wipe_cookie_jar()
    try:
        await asyncio.wait_for(client.initialize(), timeout=30)
        valid = bool(getattr(client, "_session_token", ""))
        email = await asyncio.wait_for(client.get_account_email(), timeout=20)
    except Exception:
        valid = False
        email = ""
    finally:
        try:
            await client.shutdown()
        except Exception:
            pass
    return {
        "valid": valid,
        "email": email,
        "psid_suffix": psid[-12:],
        "duplicate_of": duplicate.id if duplicate else None,
        "in_pool_count": sum(1 for a in account_pool.accounts if a.psid == psid),
    }


@router.post("/accounts/{account_id}/test")
async def test_account_generation(account_id: str, req: TestAccountRequest):
    """对指定账号发起真实生成测试（自定义模型/Prompt），返回耗时与结果摘要。"""
    try:
        result = await account_pool.test_account_generation(account_id, req.model, req.prompt)
    except ValueError:
        return JSONResponse(
            status_code=404,
            content={"error": {"message": f"Account {account_id} not found", "type": "not_found"}},
        )
    return result


@router.patch("/accounts/{account_id}")
async def update_account(account_id: str, req: UpdateAccountRequest):
    """编辑账号元信息（当前支持重命名标签），成功后立即持久化到 accounts.json。"""
    if req.label is None or not req.label.strip():
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "label is required and must not be empty", "type": "invalid_request"}},
        )
    if account_pool.rename_account(account_id, req.label):
        return {"status": "ok", "message": f"Account {account_id} updated", "label": req.label.strip()}
    return JSONResponse(
        status_code=404,
        content={"error": {"message": f"Account {account_id} not found", "type": "not_found"}},
    )


@router.put("/accounts/{account_id}/cookies")
async def update_account_cookies(account_id: str, req: UpdateCookiesRequest):
    psid, psidts = _resolve_credentials(req.psid, req.psidts, req.cookie)
    if not psid and not psidts:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "nothing to update: provide psid/psidts or a cookie string containing __Secure-1PSIDTS",
                    "type": "invalid_request",
                }
            },
        )
    for account in account_pool.accounts:
        if account.id == account_id:
            if account.client:
                result = await account.client.reload_cookies(psid=psid, psidts=psidts)
                if result.get("success"):
                    # 同步池内字段并持久化，否则容器重建后凭据回退为旧值
                    account_pool.update_credentials(account_id, psid=req.psid, psidts=req.psidts)
                    return {"status": "ok", "message": f"Account {account_id} cookies updated"}
                return JSONResponse(
                    status_code=503,
                    content={"error": {"message": result.get("error", "Cookie reload failed"), "type": "reload_error"}},
                )
            return JSONResponse(
                status_code=503,
                content={"error": {"message": "Account client not initialized", "type": "client_error"}},
            )
    return JSONResponse(
        status_code=404,
        content={"error": {"message": f"Account {account_id} not found", "type": "not_found"}},
    )


@router.get("/verify")
async def verify_token():
    return {"status": "ok"}


@router.post("/restart")
async def restart_server(confirm: bool = False):
    """重启服务（已受 admin 鉴权保护）。需 confirm=true 防误触，
    避免无意/单击直接触发进程级 SIGTERM 造成可用性中断（VULN-009）。"""
    if not confirm:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": "重启需二次确认，请带查询参数 ?confirm=true", "type": "confirmation_required"}},
        )
    import threading
    import signal

    def _restart():
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_restart, daemon=True).start()
    return {"status": "ok", "message": "Server restarting..."}


@router.get("/check-update")
async def check_update():
    """Check if a new version is available via GitHub Releases"""
    import httpx

    current = APP_VERSION
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.github.com/repos/xwteam/gemini2api/releases/latest",
                headers={"Accept": "application/vnd.github.v3+json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                latest = data.get("tag_name", "").lstrip("v")
                return {
                    "current": current,
                    "latest": latest,
                    "has_update": latest != current and latest != "",
                    "update_url": data.get("html_url", "https://github.com/xwteam/gemini2api/releases"),
                    "release_notes": data.get("body", "")
                }
    except Exception as e:
        logger.error(f"Failed to check update: {e}")

    return {"current": current, "latest": current, "has_update": False, "update_url": "https://github.com/xwteam/gemini2api/releases"}


@router.post("/update")
async def perform_update():
    """Return update instructions"""
    return {
        "status": "ok",
        "message": "Please run the following command on your server to update:",
        "command": "cd /home/ubuntu/gemini2api && git pull origin main && docker compose up -d --build"
    }


class CleanupWebChatsRequest(BaseModel):
    keep_hours: float = 24.0
    skip_pinned: bool = True


@router.get("/web-chats")
async def list_web_chats(recent: int = 300):
    """列出账号在 Gemini 网页端的会话（只读，用于排查/确认清理范围）。"""
    try:
        return {"accounts": await account_pool.list_web_chats(recent=recent)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


_cleanup_bg_tasks: set = set()


@router.post("/cleanup-web-chats")
async def cleanup_web_chats(req: CleanupWebChatsRequest = None):
    """清理超过 keep_hours 的网页端会话（置顶可保留）。手动触发。
    后台异步执行立即返回：清理重度堆积账号可能耗时数分钟（每删一个间隔 0.3s），
    同步等待会让 HTTP 请求超时。结果在服务端日志可见。
    """
    req = req or CleanupWebChatsRequest()
    import asyncio

    async def _run():
        try:
            await account_pool.cleanup_web_chats(
                keep_hours=req.keep_hours, skip_pinned=req.skip_pinned
            )
        except Exception as e:
            logger.warning(f"[cleanup-web-chats] 后台清理异常: {e}")

    task = asyncio.create_task(_run())
    _cleanup_bg_tasks.add(task)
    task.add_done_callback(_cleanup_bg_tasks.discard)
    return {"status": "started", "message": "清理已在后台开始，结果见服务端日志"}

