#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huawei Cloud Find Device API Server

Features:
- Multi-session isolation with independent storage
- Headless browser automation with Playwright
- Automatic login and session management
- Device location tracking with coordinate conversion (GCJ-02 to WGS84)
"""

import asyncio
import hashlib
import json
import logging
import math
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Frame

logging.basicConfig(
    level=logging.DEBUG if os.getenv("DEBUG_MODE", "0") == "1" else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

VERSION = "2.3.0-fast-login"
_HW_MODEL = os.getenv("HW_MODEL", "noh-an00")   # x-hw-model header，可通过环境变量覆盖
_API_KEY = os.getenv("API_KEY", "")              # 简单鉴权，空=不启用
STORAGE_DIR = Path(os.getenv("STORAGE_STATE_PATH", "/data"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

FIND_DEVICE_URL = "https://cloud.huawei.com/webFindPhone.html#/home"
FIND_DEVICE_ENTRY_URL = "https://cloud.huawei.com/wap"
FIND_DEVICE_MOBILE_URL = "https://cloud.huawei.com/wap/findDevice"

USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)

_last_csrf_token: Optional[str] = None

logger.info(f"VERSION: {VERSION}, STORAGE_DIR: {STORAGE_DIR}, exists={STORAGE_DIR.exists()}")
existing_sessions = list(STORAGE_DIR.glob("storage_state_*.json"))
logger.info(f"已有 session 文件: {len(existing_sessions)} 个")

@dataclass
class SessionState:
    session_key: str
    storage_path: Path
    credentials: Dict[str, str] = field(default_factory=dict)
    device_cache: Dict[str, Dict] = field(default_factory=dict)
    device_list: List[Dict] = field(default_factory=list)
    login_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    login_task: Optional[asyncio.Task] = None
    last_login_attempt: float = 0.0
    last_login_failed: float = 0.0
    last_login_trigger: float = 0.0
    need_reauth: bool = False
    last_err_reason: Optional[str] = None
    user_id: str = ""
    csrf_token: str = ""
    bell_last_start: Dict[str, float] = field(default_factory=dict)  # device_id → 上次 start 时间

class GlobalState:
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.playwright = None
        self.sessions: Dict[str, SessionState] = {}
        self.http_session: Optional[aiohttp.ClientSession] = None
    
    def get_session(self, session_key: str) -> SessionState:
        if session_key not in self.sessions:
            storage_path = STORAGE_DIR / f"storage_state_{session_key}.json"
            self.sessions[session_key] = SessionState(
                session_key=session_key,
                storage_path=storage_path
            )
            logger.debug(f"[Session] 创建新 session: {session_key[:8]}")
        return self.sessions[session_key]

state = GlobalState()

def _is_html(text: str) -> bool:
    t = text.strip().lower()
    return t.startswith("<!doctype") or t.startswith("<html")

def mask(text: str, n: int = 4) -> str:
    return "***" if not text or len(text) <= n else "*" * (len(text) - n) + text[-n:]

def trace_id() -> str:
    return f"{int(time.time())}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"

def _safe_int(val) -> int:
    """安全地将值转换为整数（华为云 API 可能返回字符串类型的 code）"""
    try:
        return int(val) if val is not None else -1
    except (ValueError, TypeError):
        return -1

def build_headers(csrf: str = "", uid: str = "") -> Dict[str, str]:
    h = {
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://cloud.huawei.com",
        "Referer": FIND_DEVICE_URL,
        "User-Agent": USER_AGENT,
        "x-hw-framework-type": "web",
    }
    if csrf:
        h["CSRFToken"] = csrf
    if uid:
        h["userId"] = uid
    return {k: v for k, v in h.items() if k and v and k != "undefined"}

def distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    R = 6371000
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)

    a = math.sin(dphi/2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    return R * c


def gcj02_to_wgs84(gcj_lng: float, gcj_lat: float) -> tuple[float, float]:
    """GCJ-02 → WGS84 迭代逼近算法"""
    if not (72.004 <= gcj_lng <= 137.8347 and 0.8293 <= gcj_lat <= 55.8271):
        return gcj_lng, gcj_lat

    wgs_lng = gcj_lng
    wgs_lat = gcj_lat
    threshold = 1e-6
    max_iterations = 10

    for i in range(max_iterations):
        gcj_lng_est, gcj_lat_est = wgs84_to_gcj02(wgs_lng, wgs_lat)
        d_lng = gcj_lng - gcj_lng_est
        d_lat = gcj_lat - gcj_lat_est
        if abs(d_lng) < threshold and abs(d_lat) < threshold:
            break
        wgs_lng += d_lng
        wgs_lat += d_lat

    return wgs_lng, wgs_lat


def wgs84_to_gcj02(wgs_lng: float, wgs_lat: float) -> tuple[float, float]:
    """WGS84 → GCJ-02"""
    if not (72.004 <= wgs_lng <= 137.8347 and 0.8293 <= wgs_lat <= 55.8271):
        return wgs_lng, wgs_lat

    a = 6378245.0
    ee = 0.00669342162296594323

    def _transform_lat(x: float, y: float) -> float:
        ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * math.sqrt(abs(x))
        ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
        ret += (20.0 * math.sin(y * math.pi) + 40.0 * math.sin(y / 3.0 * math.pi)) * 2.0 / 3.0
        ret += (160.0 * math.sin(y / 12.0 * math.pi) + 320.0 * math.sin(y * math.pi / 30.0)) * 2.0 / 3.0
        return ret

    def _transform_lng(x: float, y: float) -> float:
        ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * math.sqrt(abs(x))
        ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
        ret += (20.0 * math.sin(x * math.pi) + 40.0 * math.sin(x / 3.0 * math.pi)) * 2.0 / 3.0
        ret += (150.0 * math.sin(x / 12.0 * math.pi) + 300.0 * math.sin(x / 30.0 * math.pi)) * 2.0 / 3.0
        return ret

    dlat = _transform_lat(wgs_lng - 105.0, wgs_lat - 35.0)
    dlng = _transform_lng(wgs_lng - 105.0, wgs_lat - 35.0)
    radlat = wgs_lat / 180.0 * math.pi
    magic = math.sin(radlat)
    magic = 1 - ee * magic * magic
    sqrtmagic = math.sqrt(magic)
    dlat = (dlat * 180.0) / ((a * (1 - ee)) / (magic * sqrtmagic) * math.pi)
    dlng = (dlng * 180.0) / (a / sqrtmagic * math.cos(radlat) * math.pi)

    gcj02_lat = wgs_lat + dlat
    gcj02_lng = wgs_lng + dlng

    return gcj02_lng, gcj02_lat


def bd09_to_gcj02(bd_lng: float, bd_lat: float) -> tuple[float, float]:
    """BD-09 → GCJ-02"""
    x = bd_lng - 0.0065
    y = bd_lat - 0.006
    z = math.sqrt(x * x + y * y) - 0.00002 * math.sin(y * math.pi * 3000 / 180)
    theta = math.atan2(y, x) - 0.000003 * math.cos(x * math.pi * 3000 / 180)
    return z * math.cos(theta), z * math.sin(theta)


STEALTH_INIT_SCRIPT = r"""
(() => {
  try {
    // webdriver 标记
    const newProto = navigator.__proto__ || Object.getPrototypeOf(navigator);
    if (newProto) {
      Object.defineProperty(newProto, 'webdriver', {
        get: () => undefined,
      });
    }

    // 语言
    Object.defineProperty(navigator, 'languages', {
      get: () => ['zh-CN', 'zh'],
    });

    // 平台 & UA 相关补丁
    Object.defineProperty(navigator, 'platform', {
      get: () => 'iPhone',
    });
    window.chrome = window.chrome || { runtime: {} };

    // plugins
    Object.defineProperty(navigator, 'plugins', {
      get: () => [1, 2, 3],
    });

    // permissions.query - 避免 Notification 探测异常
    if (window.navigator.permissions && window.navigator.permissions.query) {
      const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
      window.navigator.permissions.query = (parameters) => {
        if (parameters && parameters.name === 'notifications') {
          return Promise.resolve({ state: Notification.permission });
        }
        return originalQuery(parameters);
      };
    }

    // 屏幕尺寸，避免 0 / 异常值
    try {
      const screenProto = Object.getPrototypeOf(window.screen) || window.screen;
      const sw = window.screen.width || 375;
      const sh = window.screen.height || 667;
      Object.defineProperty(screenProto, 'availWidth', { get: () => sw });
      Object.defineProperty(screenProto, 'availHeight', { get: () => sh });
    } catch (e) {}

    // hardwareConcurrency / deviceMemory
    try {
      Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
      Object.defineProperty(navigator, 'deviceMemory', { get: () => 4 });
    } catch (e) {}

    // 简单 WebGL 指纹（避免为空）
    try {
      const getParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) { // UNMASKED_VENDOR_WEBGL
          return 'Apple Inc.';
        }
        if (parameter === 37446) { // UNMASKED_RENDERER_WEBGL
          return 'Apple GPU';
        }
        return getParameter.call(this, parameter);
      };
    } catch (e) {}
  } catch (e) {
    // 静默失败，避免影响主流程
  }
})();
"""


async def _apply_stealth_to_context(context: BrowserContext) -> None:
  """Apply stealth script to browser context."""
  try:
      await context.add_init_script(STEALTH_INIT_SCRIPT)
      logger.debug("[Stealth] Script applied")
  except Exception as e:
      logger.debug(f"[Stealth] Failed to apply script: {e}")


async def ensure_browser():
    if not state.browser:
        logger.debug("[Browser] 启动 headless 浏览器")
        state.playwright = await async_playwright().start()
        state.browser = await state.playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage"
            ]
        )

async def save_diagnostic(page: Page, sess: SessionState, reason: str):
    try:
        logger.error(f"[诊断] reason={reason}, session={sess.session_key[:8]}")
        try:
            screenshot_path = Path("/mnt/hw-gps-synchronization") / f"login_failed_{sess.session_key[:8]}.png"
            await page.screenshot(path=str(screenshot_path))
            logger.error(f"[诊断] 截图已保存: {screenshot_path.name}")
        except Exception as e:
            logger.error(f"[诊断] 截图失败: {e}")
    except Exception as e:
        logger.error(f"[诊断] 保存失败: {e}")

async def _get_csrf_and_uid_from_page(page: Page) -> Dict[str, str]:
    """Extract CSRF token and userId from page (cookie → meta → window)."""
    global _last_csrf_token
    info = {"csrf": None, "userId": None, "source": None}

    try:
        cookies = await page.context.cookies()
        cookie_map = {c["name"]: c["value"] for c in cookies if "cloud.huawei.com" in (c.get("domain") or "")}
        cookie_names = list(cookie_map.keys())

        for name in ["CSRFToken", "hicloud_csrf", "XSRF-TOKEN", "csrf-token", "_csrf", "csrfToken"]:
            if name in cookie_map:
                info["csrf"] = cookie_map[name]
                info["source"] = f"cookie:{name}"
                if info["csrf"] != _last_csrf_token:
                    logger.debug(f"[Token] 从cookie找到 CSRF: {name}")
                    _last_csrf_token = info["csrf"]
                break

        for name in ["userId", "user_id", "uid"]:
            if name in cookie_map:
                info["userId"] = cookie_map[name]
                if not info["source"]:
                    info["source"] = f"cookie:{name}"
                else:
                    info["source"] += f",cookie:{name}"
                break

        page_data = await page.evaluate("""() => {
            const result = {csrf: null, userId: null, sources: []};

            for (const sel of ['meta[name="csrf-token"]', 'meta[name="csrfToken"]', 'meta[name="_csrf"]']) {
                const el = document.querySelector(sel);
                if (el && el.getAttribute('content')) {
                    result.csrf = el.getAttribute('content');
                    result.sources.push('meta:' + sel);
                    break;
                }
            }

            if (!result.csrf) {
                if (window.csrf_token) { result.csrf = window.csrf_token; result.sources.push('window.csrf_token'); }
                else if (window._csrf) { result.csrf = window._csrf; result.sources.push('window._csrf'); }
                else if (window.csrfToken) { result.csrf = window.csrfToken; result.sources.push('window.csrfToken'); }
                else if (window.CSRFToken) { result.csrf = window.CSRFToken; result.sources.push('window.CSRFToken'); }
            }

            try {
                if (window.__INITIAL_STATE__ && window.__INITIAL_STATE__.user) {
                    result.userId = window.__INITIAL_STATE__.user.userId || window.__INITIAL_STATE__.user.id;
                    result.sources.push('__INITIAL_STATE__.user');
                }
            } catch (e) {}

            return result;
        }""")

        if not info["csrf"] and page_data.get("csrf"):
            info["csrf"] = page_data["csrf"]
            info["source"] = ", ".join(page_data.get("sources", []))
            logger.debug(f"[Token] 从页面找到 CSRF，source={info['source']}")

        if not info["userId"] and page_data.get("userId"):
            info["userId"] = page_data["userId"]
            logger.debug(f"[Token] 从页面找到 userId")

        if not info["csrf"]:
            logger.warning(f"[Token] 未找到 CSRF token，cookies={len(cookie_names)}个")
        if not info["userId"]:
            logger.debug(f"[Token] 未找到 userId")

    except Exception as e:
        logger.warning(f"[Token] 提取异常: {e}")

    return info

async def _get_csrf(page: Page) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    page_info = await _get_csrf_and_uid_from_page(page)

    if page_info.get("csrf"):
        headers["X-CSRF-Token"] = page_info["csrf"]
        headers["CSRFToken"] = page_info["csrf"]
    else:
        logger.warning("[CSRF] 未找到 token")

    headers.setdefault("X-Requested-With", "XMLHttpRequest")
    headers.setdefault("Accept", "application/json")
    headers.setdefault("Origin", "https://cloud.huawei.com")
    headers.setdefault("Referer", FIND_DEVICE_URL)
    headers.setdefault("Accept-Language", "zh-CN,zh;q=0.9")

    return headers

async def establish_cloud_session(page: Page, sess: SessionState) -> bool:
    """建立华为云空间会话（激活定位权限）"""
    start_time = time.time()
    try:
        logger.debug(f"[EstablishSession] session={sess.session_key[:8]}")

        current_url = page.url.lower()
        if "webfindphone" not in current_url:
            logger.debug("[EstablishSession] 导航到 webFindPhone")
            try:
                await page.goto(FIND_DEVICE_URL, wait_until="domcontentloaded", timeout=8000)
            except Exception as e:
                if "ERR_ABORTED" not in str(e) and "interrupted" not in str(e).lower():
                    logger.warning(f"[EstablishSession] 导航失败: {e}")
                    return False

        try:
            await page.wait_for_load_state("domcontentloaded", timeout=6000)
        except:
            pass

        logger.debug("[EstablishSession] 等待 getHomeData 响应...")
        try:
            async with page.expect_response(
                lambda r: "getHomeData" in r.url and r.status == 200,
                timeout=3000
            ) as response_info:
                pass
            response = await response_info.value
            logger.debug(f"[EstablishSession] getHomeData 响应到达，status={response.status}")
        except:
            logger.debug("[EstablishSession] getHomeData 响应超时，继续尝试主动调用")

        cookies_list = await page.context.cookies()
        cookies_dict = {c["name"]: c["value"] for c in cookies_list if "cloud.huawei.com" in (c.get("domain") or "")}
        hydrate_result = hydrate_tokens_from_cookies(sess, cookies_dict)
        logger.debug(f"[EstablishSession] hydrate 结果: csrf_ok={hydrate_result['csrf_ok']}, user_ok={hydrate_result['user_ok']}")

        if not sess.csrf_token or not sess.user_id:
            token_info = await _get_csrf_and_uid_from_page(page)
            if token_info.get("csrf") and not sess.csrf_token:
                sess.csrf_token = token_info["csrf"]
            if token_info.get("userId") and not sess.user_id:
                sess.user_id = token_info["userId"]

        headers = {
            "Content-Type": "application/json;charset=UTF-8",
            "Accept": "application/json, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://cloud.huawei.com",
            "Referer": FIND_DEVICE_URL,
            "User-Agent": USER_AGENT,
        }
        if sess.csrf_token:
            headers["CSRFToken"] = sess.csrf_token
            headers["X-CSRF-Token"] = sess.csrf_token
        if sess.user_id:
            headers["userId"] = sess.user_id

        logger.debug(f"[EstablishSession] 调用 getHomeData，csrf={bool(sess.csrf_token)}, uid={bool(sess.user_id)}")
        home_resp = await page.context.request.post(
            "https://cloud.huawei.com/findDevice/getHomeData",
            headers=headers,
            data=json.dumps({})
        )

        home_text = await home_resp.text()
        if _is_html(home_text):
            logger.error(f"[EstablishSession] getHomeData 返回HTML（status={home_resp.status}）: {home_text[:100]}")
            return False

        try:
            home_data = json.loads(home_text)
        except json.JSONDecodeError:
            logger.error(f"[EstablishSession] getHomeData 非JSON（ct={home_resp.headers.get('content-type')}）: {home_text[:100]}")
            return False

        home_code = str(home_data.get("code", "0"))
        if home_code != "0":
            logger.warning(f"[EstablishSession] getHomeData code={home_code}, info={home_data.get('info')}")
            if home_code == "990":
                return False

        if home_data.get("userid") and not sess.user_id:
            sess.user_id = home_data["userid"]
            logger.debug(f"[EstablishSession] 从getHomeData提取 userid={mask(sess.user_id)}")

        if sess.csrf_token:
            headers["CSRFToken"] = sess.csrf_token
            headers["X-CSRF-Token"] = sess.csrf_token
        if sess.user_id:
            headers["userId"] = sess.user_id

        logger.debug(f"[EstablishSession] 调用 getMobileDeviceList")
        list_resp = await page.context.request.post(
            "https://cloud.huawei.com/findDevice/getMobileDeviceList",
            headers=headers,
            data=json.dumps({"deviceType": 0})
        )
        list_text = await list_resp.text()

        if list_resp.status == 200 and _is_html(list_text):
            logger.warning(f"[EstablishSession] getMobileDeviceList 返回HTML，软重试: {list_text[:100]}")
            try:
                await page.goto(FIND_DEVICE_URL, wait_until="domcontentloaded", timeout=8000)
                await page.wait_for_load_state("domcontentloaded", timeout=6000)

                cookies_list = await page.context.cookies()
                cookies_dict = {c["name"]: c["value"] for c in cookies_list if "cloud.huawei.com" in (c.get("domain") or "")}
                hydrate_result = hydrate_tokens_from_cookies(sess, cookies_dict)

                if not sess.csrf_token:
                    token_info = await _get_csrf_and_uid_from_page(page)
                    if token_info.get("csrf"):
                        sess.csrf_token = token_info["csrf"]

                if sess.csrf_token:
                    headers["CSRFToken"] = sess.csrf_token
                    headers["X-CSRF-Token"] = sess.csrf_token

                list_resp = await page.context.request.post(
                    "https://cloud.huawei.com/findDevice/getMobileDeviceList",
                    headers=headers,
                    data=json.dumps({"deviceType": 0})
                )
                list_text = await list_resp.text()

                if _is_html(list_text):
                    logger.error(f"[EstablishSession] 软重试后仍返回HTML: {list_text[:100]}")
                    return False
            except Exception as retry_err:
                logger.warning(f"[EstablishSession] 软重试异常: {retry_err}")
                return False

        if list_resp.status != 200:
            logger.warning(f"[EstablishSession] getMobileDeviceList status={list_resp.status}")
            return False

        try:
            list_data = json.loads(list_text)
        except json.JSONDecodeError:
            logger.warning(f"[EstablishSession] getMobileDeviceList 非JSON: {list_text[:100]}")
            return False

        list_code = str(list_data.get("code", ""))
        if list_code == "990":
            logger.warning("[EstablishSession] getMobileDeviceList code=990")
            return False
        elif list_code != "0":
            logger.warning(f"[EstablishSession] getMobileDeviceList code={list_code}")
            return False

        logger.debug("[EstablishSession] getMobileDeviceList 成功")

        devices = list_data.get("devices") or list_data.get("deviceList") or []
        if devices:
            test_device_id = devices[0].get("deviceId")
            if test_device_id:
                try:
                    test_resp = await page.context.request.post(
                        "https://cloud.huawei.com/findDevice/queryLocateResult",
                        headers=headers,
                        data=json.dumps({"deviceId": test_device_id, "deviceType": 0})
                    )
                    test_text = await test_resp.text()
                    if test_resp.status == 200:
                        test_data = json.loads(test_text)
                        test_code = str(test_data.get("code", ""))
                        if test_code in ("0", "1"):
                            logger.debug(f"[EstablishSession] queryLocateResult 探测成功（定位权限正常）")
                        elif test_code == "990":
                            logger.warning("[EstablishSession] queryLocateResult code=990（定位权限可能未激活，但不影响会话建立）")
                        else:
                            logger.debug(f"[EstablishSession] queryLocateResult code={test_code}")
                except Exception as e:
                    logger.debug(f"[EstablishSession] queryLocateResult 探测失败: {e}")

        elapsed = int((time.time() - start_time) * 1000)
        logger.info(f"✅ [EstablishSession] 云空间会话已建立（基于 getHomeData + getMobileDeviceList），耗时{elapsed}ms")
        return True

    except Exception as e:
        logger.exception(f"[EstablishSession] 异常: {e}")
        return False

async def _click_find_device_entry(page: Page) -> bool:
    selectors = [
        'text="查找设备"',
        ':text("查找设备")',
        'a:has-text("查找设备")',
        'div:has-text("查找设备")',
        '[href*="findDevice"]',
        '[href*="webFindPhone"]',
    ]
    for selector in selectors:
        try:
            element = await page.wait_for_selector(selector, timeout=2000, state="visible")
            if element:
                logger.info(f'[Mobile] 点击"查找设备"入口: {selector}')
                await element.click()
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=3000)
                except:
                    pass
                return True
        except Exception:
            pass
    logger.warning('[Mobile] 未能找到可点击的"查找设备"入口')
    return False

async def _prepare_mobile_login_entry(page: Page) -> str:
    """返回: 'login' / 'device' / 'unknown'"""
    try:
        current_url = page.url

        if "cloud.huawei.com/wap" in current_url and "login" not in current_url.lower():
            if "webfindphone" not in current_url.lower() and "finddevice" not in current_url.lower():
                logger.info('[Mobile] 当前在华为云移动主页，尝试点击"查找设备"触发登录')
                clicked = await _click_find_device_entry(page)

                if not clicked:
                    try:
                        logger.info("[Mobile] 尝试直接访问移动版查找设备页面")
                        await page.goto(FIND_DEVICE_MOBILE_URL, wait_until="domcontentloaded", timeout=8000)
                    except Exception as e:
                        logger.warning(f"[Mobile] 访问移动版查找设备页面失败: {e}")

        try:
            await page.wait_for_url(
                lambda url: any(k in url.lower() for k in ["login", "auth", "cas"]),
                timeout=10000
            )
            url = page.url
            logger.info(f"[Mobile] ✓ 已跳转到登录页面: {url}")
            return "login"
        except:
            url = page.url
            if "webfindphone" in url.lower() and all(k not in url.lower() for k in ["login", "auth", "cas"]):
                logger.info("[Mobile] 检测到查找设备页面，可能已登录")
                return "device"

            logger.warning(f"[Mobile] 等待跳转超时，当前url={url}")
            return "unknown"
    except Exception as e:
        logger.warning(f"[Mobile] 准备移动端登录入口异常: {e}")
        return "unknown"

async def login_huawei(page: Page, username: str, password: str, sess: SessionState) -> bool:
    start_time = time.time()
    try:
        logger.debug(f"[Login] 开始登录 session={sess.session_key[:8]}, user={mask(username)}")

        await page.wait_for_load_state("domcontentloaded", timeout=8000)
        elapsed = int((time.time() - start_time) * 1000)
        logger.debug(f"[Login] 页面加载完成（{elapsed}ms），url={page.url}")

        current_url_lower = page.url.lower()
        is_login_page = any(k in current_url_lower for k in ["login", "cas", "auth"])

        if not is_login_page:
            logger.debug(f"[Login] 当前非登录页（{page.url}），等待自动跳转...")
            try:
                await page.wait_for_url(
                    lambda url: any(k in url.lower() for k in ["login", "cas", "auth"]),
                    timeout=10000
                )
                elapsed = int((time.time() - start_time) * 1000)
                logger.debug(f"[Login] ✓ 跳转到登录页（{elapsed}ms），url={page.url}")
            except:
                elapsed = int((time.time() - start_time) * 1000)
                logger.warning(f"[Login] 10秒未跳转到登录页（{elapsed}ms），当前url={page.url}")

        target = page
        try:
            banner_close = await page.query_selector('.hwid-banner_close, [ht="click_common_cookieBanner_close"]')
            if banner_close:
                await banner_close.click()
                logger.debug("[Login] 关闭 Cookie 提示条")
        except Exception:
            pass

        selectors_user = [
            '#userAccount',
            'input[name="userAccount"]',
            'input[name="username"]',
            'input.userAccount',
            'input.hwid-input.userAccount',
            'input[ht="input_pwdlogin_account"]',
            'input[placeholder*="手机号/邮件地址/账号名"]',
            'input[placeholder*="邮件地址/账号名"]',
            'input[type="text"]',
            'input[type="email"]',
            'input[type="tel"]',
        ]

        user_input = None
        for sel in selectors_user:
            try:
                user_input = await target.wait_for_selector(sel, state="visible", timeout=800)
                if user_input:
                    logger.debug(f"[Login] 找到用户名: {sel}")
                    break
            except:
                pass

        if not user_input:
            logger.debug("[Login] 主页未找到用户名框，遍历所有frames")
            for f in page.frames:
                for sel in selectors_user:
                    try:
                        user_input = await f.wait_for_selector(sel, state="visible", timeout=600)
                        if user_input:
                            logger.debug(f"[Login] 在frame中找到用户名: {sel}")
                            target = f
                            break
                    except:
                        pass
                if user_input:
                    break

        if not user_input:
            elapsed = int((time.time() - start_time) * 1000)
            logger.error(f"[Login] 无法找到用户名输入框（{elapsed}ms）")
            await save_diagnostic(page, sess, "no_username")
            return False

        await user_input.fill(username)
        elapsed = int((time.time() - start_time) * 1000)
        logger.debug(f"[Login] 填充用户名完成（{elapsed}ms）")

        # "Next" button
        try:
            next_btn = await target.wait_for_selector('#btn-next, button:has-text("下一步")', state="visible", timeout=1000)
            if next_btn:
                await next_btn.click()
                logger.debug("[Login] 点击下一步")
                await page.wait_for_load_state("domcontentloaded", timeout=3000)
        except:
            pass

        selectors_pwd = [
            '#password',
            'input[name="password"]',
            'input[ht="input_enter_password1"]',
            'input.hwid-input[type="password"]',
            'input[placeholder="密码"]',
            'input[type="password"]',
        ]

        pwd_input = None
        for sel in selectors_pwd:
            try:
                pwd_input = await target.wait_for_selector(sel, state="visible", timeout=1000)
                if pwd_input:
                    logger.debug(f"[Login] 找到密码: {sel}")
                    break
            except:
                pass

        if not pwd_input:
            elapsed = int((time.time() - start_time) * 1000)
            logger.error(f"[Login] 无法找到密码输入框（{elapsed}ms）")
            await save_diagnostic(page, sess, "no_password")
            return False

        await pwd_input.fill(password)
        elapsed = int((time.time() - start_time) * 1000)
        logger.debug(f"[Login] 填充密码完成（{elapsed}ms）")

        login_clicked = False
        login_selectors = [
            '[ht="click_pwdlogin_submitLogin"]',
            '.hwid-login-btn-wrap .normalBtn[ht="click_pwdlogin_submitLogin"]',
            '.hwid-login-btn-wrap .hwid-btn.hwid-btn-primary',
            '#btn-login',
            'button:has-text("登录")',
            'button[type="submit"]',
        ]

        for sel in login_selectors:
            try:
                btn = await target.wait_for_selector(sel, state="visible", timeout=1500)
                if btn:
                    await btn.click()
                    logger.debug(f"[Login] 点击登录: {sel}")
                    login_clicked = True
                    break
            except Exception:
                pass

        if not login_clicked:
            logger.debug("[Login] 未找到登录按钮，按回车")
            await pwd_input.press("Enter")

        elapsed = int((time.time() - start_time) * 1000)
        logger.debug(f"[Login] 点击登录完成（{elapsed}ms）")

        logger.debug("[Login] 等待跳转到主页...")
        try:
            await page.wait_for_url("**#/home", timeout=5000)
            elapsed = int((time.time() - start_time) * 1000)
            logger.debug(f"[Login] ✓ 跳转成功（{elapsed}ms），url={page.url}")
        except:
            try:
                await page.wait_for_url(lambda url: "cloud.huawei.com" in url and not any(k in url.lower() for k in ["login", "cas", "auth"]), timeout=8000)
                elapsed = int((time.time() - start_time) * 1000)
                logger.debug(f"[Login] ✓ 跳转成功/fallback（{elapsed}ms），url={page.url}")
            except:
                elapsed = int((time.time() - start_time) * 1000)
                logger.error(f"[Login] 跳转超时（{elapsed}ms），仍在: {page.url}")
                await save_diagnostic(page, sess, "timeout")
                return False

        logger.debug("[Login] 等待 getHomeData 响应...")
        try:
            async with page.expect_response(lambda r: "getHomeData" in r.url and r.ok, timeout=3000) as response_info:
                pass
            elapsed = int((time.time() - start_time) * 1000)
            logger.debug(f"[Login] ✓ getHomeData 响应成功（{elapsed}ms）")
        except:
            elapsed = int((time.time() - start_time) * 1000)
            logger.warning(f"[Login] getHomeData 响应超时（{elapsed}ms），继续")

        cookies = await page.context.cookies()
        elapsed = int((time.time() - start_time) * 1000)
        logger.debug(f"[Login] ✅ 登录成功（总耗时{elapsed}ms），cookies={len(cookies)}个")

        return True

    except Exception as e:
        logger.exception(f"[Login] 登录异常 session={sess.session_key[:8]}: {e}")
        try:
            await save_diagnostic(page, sess, "exception")
        except:
            pass
        return False

async def refresh_login(sess: SessionState):
    start_time = time.time()
    async with sess.login_lock:
        username = sess.credentials.get("username", "")
        password = sess.credentials.get("password", "")

        if not username or not password:
            logger.error(f"[RefreshLogin] session={sess.session_key[:8]} 无凭据")
            return

        logger.debug(f"[RefreshLogin] 开始，session={sess.session_key[:8]}, user={mask(username)}")
        
        now = time.time()
        if sess.last_login_failed > 0 and now - sess.last_login_failed < 30:
            wait = 30 - (now - sess.last_login_failed)
            logger.warning(f"[RefreshLogin] 上次失败未满30s，等待 {wait:.1f}s")
            await asyncio.sleep(wait)
        
        if now - sess.last_login_attempt < 60:
            wait = 60 - (now - sess.last_login_attempt)
            logger.debug(f"[RefreshLogin] 距上次不足60s，等待 {wait:.1f}s")
            await asyncio.sleep(wait)
        
        sess.last_login_attempt = time.time()
        
        try:
            await ensure_browser()

            context = await state.browser.new_context(
                user_agent=USER_AGENT,
                locale="zh-CN",
                timezone_id="Asia/Shanghai",
                viewport={"width": 375, "height": 667}
            )

            await _apply_stealth_to_context(context)

            async def block_resources(route):
                resource_type = route.request.resource_type
                url = route.request.url
                allow_hosts = [
                    "id1.cloud.huawei.com",
                    "metrics-drcn.dt.hicloud.com",
                    "necaptcha",
                    "cstaticdun",
                    ".127.net",
                    ".163.com",
                    ".163yun.com",
                ]
                if any(h in url for h in allow_hosts):
                    await route.continue_()
                    return

                if resource_type in ["image", "font", "media"]:
                    await route.abort()
                elif any(url.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".mp3", ".wav"]):
                    await route.abort()
                else:
                    await route.continue_()

            await context.route("**/*", block_resources)
            
            page = await context.new_page()

            try:
                goto_ok = False
                for attempt in range(2):
                    try:
                        await page.goto(FIND_DEVICE_ENTRY_URL, timeout=8000)
                        goto_ok = True
                        logger.debug(f"[RefreshLogin] 访问登录入口成功")
                        break
                    except Exception as e:
                        logger.warning(f"[RefreshLogin] goto登录入口失败 (attempt {attempt+1}/2): {e}")
                        if attempt == 0:
                            continue
                        else:
                            raise

                if not goto_ok:
                    logger.error(f"[RefreshLogin] goto登录入口失败")
                    sess.last_login_failed = time.time()
                    return

                status = await _prepare_mobile_login_entry(page)
                if status == "unknown":
                    try:
                        await page.goto(FIND_DEVICE_MOBILE_URL, wait_until="domcontentloaded", timeout=8000)
                    except Exception:
                        pass
                    status = await _prepare_mobile_login_entry(page)

                if status == "device":
                    logger.debug("[RefreshLogin] 检测到已在查找设备页（可能已登录），跳过表单登录")
                    success = True
                else:
                    success = await login_huawei(page, username, password, sess)
                login_elapsed = int((time.time() - start_time) * 1000)

                if success:
                    logger.debug(f"[RefreshLogin] 登录成功（{login_elapsed}ms），进入 FindDevice 页面")
                    find_device_ok = False
                    for attempt in range(2):
                        try:
                            await page.goto(FIND_DEVICE_URL, timeout=8000)
                            await page.wait_for_load_state("domcontentloaded", timeout=8000)
                            find_device_ok = True
                            logger.debug(f"[RefreshLogin] 已进入 {FIND_DEVICE_URL}")
                            break
                        except Exception as e:
                            logger.warning(f"[RefreshLogin] 进入FindDevice页面失败 (attempt {attempt+1}/2): {e}")
                            if attempt == 0:
                                continue
                            else:
                                logger.error(f"[RefreshLogin] 进入 FindDevice 页面失败")
                                sess.last_login_failed = time.time()
                                return

                    if not find_device_ok:
                        sess.last_login_failed = time.time()
                        return

                    session_start = time.time()
                    logger.debug(f"[RefreshLogin] 建立云空间会话")
                    session_ok = await establish_cloud_session(page, sess)
                    session_elapsed = int((time.time() - session_start) * 1000)

                    if not session_ok:
                        logger.error(f"[RefreshLogin] establish_cloud_session 失败（{session_elapsed}ms）")
                        sess.last_login_failed = time.time()
                    else:
                        logger.debug(f"[RefreshLogin] establish_cloud_session 成功（{session_elapsed}ms）")
                        tmp = sess.storage_path.with_suffix(".tmp")
                        await context.storage_state(path=str(tmp))
                        tmp.replace(sess.storage_path)

                        file_size = sess.storage_path.stat().st_size
                        cookies_list = await context.cookies()
                        total_elapsed = int((time.time() - start_time) * 1000)
                        logger.info(f"[RefreshLogin] ✅ 成功（总耗时{total_elapsed}ms），session={sess.session_key[:8]}, cookies={len(cookies_list)}个")
                        logger.debug(f"[RefreshLogin] storage_state 已写入: {sess.storage_path.name}, 大小={file_size} bytes")

                        sess.need_reauth = False
                        sess.last_err_reason = None
                        sess.last_login_failed = 0
                else:
                    total_elapsed = int((time.time() - start_time) * 1000)
                    logger.error(f"[RefreshLogin] ✗ 失败（{total_elapsed}ms），session={sess.session_key[:8]}")
                    sess.last_login_failed = time.time()
                    
            finally:
                await page.close()
                await context.close()

        except Exception as e:
            logger.exception(f"[RefreshLogin] 异常 session={sess.session_key[:8]}: {e}")
            sess.last_login_failed = time.time()
        finally:
            sess.login_task = None

def trigger_refresh_login_nowait(sess: SessionState, reason: str = "UNKNOWN"):
    if sess.login_task and not sess.login_task.done():
        logger.debug(f"[Trigger] 登录任务运行中 session={sess.session_key[:8]}")
        return

    if sess.login_lock.locked():
        logger.debug(f"[Trigger] 登录锁已占用 session={sess.session_key[:8]}")
        return

    now = time.time()
    cooldown = 600
    if sess.last_login_trigger > 0:
        elapsed = now - sess.last_login_trigger
        if elapsed < cooldown and reason not in ["AUTH_FAILED_990", "HTTP_401", "HTTP_403"]:
            logger.warning(
                f"[Trigger] 冷却中 session={sess.session_key[:8]}, "
                f"距上次触发 {elapsed:.1f}s < {cooldown}s, reason={reason}, 跳过"
            )
            return

    sess.last_login_trigger = now
    sess.login_task = asyncio.create_task(refresh_login(sess))
    logger.debug(f"[Trigger] 启动后台登录 session={sess.session_key[:8]}, reason={reason}")

async def get_cookies_from_storage(storage_path: Path) -> Optional[Dict[str, str]]:
    if not storage_path.exists():
        logger.debug(f"[Cookies] storage_state 不存在: {storage_path.name}")
        return None

    try:
        data = json.loads(storage_path.read_text(encoding="utf-8"))
        cookies = {}
        for cookie in data.get("cookies", []):
            cookies[cookie["name"]] = cookie["value"]

        cookie_names = list(cookies.keys())
        logger.debug(f"[Cookies] 从 {storage_path.name} 提取 {len(cookies)} 个 cookie")
        logger.debug(f"[Cookies] 关键 cookie 存在: CSRFToken={bool(cookies.get('CSRFToken'))}, USER_ID={bool(cookies.get('USER_ID'))}")
        return cookies
    except Exception as e:
        logger.exception(f"[Cookies] 解析失败 {storage_path.name}: {e}")
        return None

def hydrate_tokens_from_cookies(sess: SessionState, cookies: Dict[str, str]) -> Dict[str, bool]:
    csrf_from_cookie = (
        cookies.get("CSRFToken") or
        cookies.get("hicloud_csrf") or
        cookies.get("csrfToken") or
        cookies.get("XSRF-TOKEN") or
        cookies.get("csrf-token") or
        cookies.get("_csrf")
    )

    user_from_cookie = (
        cookies.get("USER_ID") or
        cookies.get("userId") or
        cookies.get("uid")
    )

    csrf_ok_before = bool(sess.csrf_token)
    user_ok_before = bool(sess.user_id)

    if csrf_from_cookie:
        sess.csrf_token = csrf_from_cookie

    if user_from_cookie:
        sess.user_id = user_from_cookie

    csrf_ok_after = bool(sess.csrf_token)
    user_ok_after = bool(sess.user_id)

    logger.debug(
        f"[Hydrate] cookie(csrf={bool(csrf_from_cookie)}, uid={bool(user_from_cookie)}) "
        f"-> sess(csrf: {csrf_ok_before}->{csrf_ok_after}, uid: {user_ok_before}->{user_ok_after})"
    )

    return {"csrf_ok": csrf_ok_after, "user_ok": user_ok_after}

async def ensure_api_tokens(sess: SessionState, cookies: Dict[str, str]) -> bool:
    """获取 userId 和 CSRFToken（bootstrap）"""
    cookie_names = list(cookies.keys())
    logger.debug(f"[Bootstrap] session={sess.session_key[:8]}, cookies={len(cookie_names)}")

    hydrate_result = hydrate_tokens_from_cookies(sess, cookies)
    csrf_ok = hydrate_result["csrf_ok"]
    user_ok = hydrate_result["user_ok"]

    if csrf_ok and user_ok:
        logger.debug(f"[Bootstrap] ✓ 跳过（token 已从 cookie hydrate），userId={mask(sess.user_id)}, csrf={sess.csrf_token[:8]}...")
        return True

    try:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items() if k])

        if not user_ok:
            url_home = "https://cloud.huawei.com/findDevice/getHomeData"
            headers = {
                "Content-Type": "application/json;charset=UTF-8",
                "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://cloud.huawei.com",
                "Referer": FIND_DEVICE_URL,
                "User-Agent": USER_AGENT,
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Cookie": cookie_str,
            }
            if sess.csrf_token:
                headers["CSRFToken"] = sess.csrf_token

            logger.debug(f"[Bootstrap] 调用 getHomeData")
            async with state.http_session.post(url_home, json={}, headers=headers, timeout=aiohttp.ClientTimeout(total=8.0)) as r:
                status = r.status
                ct = r.headers.get("Content-Type", "")
                text = await r.text()

                if status != 200:
                    logger.error(f"[Bootstrap] getHomeData HTTP {status}, ct={ct}, body={text[:100]}")
                    return False

                if _is_html(text):
                    logger.error(f"[Bootstrap] getHomeData 返回HTML（会话失效）, body={text[:100]}")
                    return False

                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    logger.error(f"[Bootstrap] getHomeData JSON解析失败, ct={ct}, body={text[:100]}")
                    return False

                code = str(data.get("code", "0"))
                if code != "0":
                    logger.error(f"[Bootstrap] getHomeData code={code}, info={data.get('info')}")
                    if code == "990":
                        return False

                user_id = data.get("userid")
                if user_id:
                    sess.user_id = user_id
                    user_ok = True
                    logger.debug(f"[Bootstrap] 获取 userid={mask(user_id)}")
                else:
                    logger.warning(f"[Bootstrap] getHomeData 未返回 userid, keys={list(data.keys())[:10]}")

        if not csrf_ok:
            url_hb = f"https://cloud.huawei.com/heartbeatCheck?checkType=1&traceId={trace_id()}"
            headers_hb = {
                "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "https://cloud.huawei.com",
                "Referer": FIND_DEVICE_URL,
                "User-Agent": USER_AGENT,
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Cookie": cookie_str,
            }
            if sess.user_id:
                headers_hb["userId"] = sess.user_id

            logger.debug(f"[Bootstrap] 调用 heartbeatCheck, userId={mask(sess.user_id) if sess.user_id else 'None'}")
            async with state.http_session.get(url_hb, headers=headers_hb, timeout=aiohttp.ClientTimeout(total=8.0)) as r:
                status = r.status
                text = await r.text()

                if status == 401:
                    # 华为服务端明确表示会话已离线，无法通过 bootstrap 恢复，直接返回失败
                    logger.warning(f"[Bootstrap] heartbeatCheck HTTP 401（会话已在服务端失效），body={text[:100]}")
                    return False
                elif status != 200:
                    logger.warning(f"[Bootstrap] heartbeatCheck HTTP {status}, body={text[:100]}")
                elif _is_html(text):
                    logger.warning(f"[Bootstrap] heartbeatCheck 返回HTML: {text[:100]}")
                else:
                    csrf_token = r.headers.get("CSRFToken") or r.headers.get("csrfToken") or r.headers.get("X-CSRF-Token")
                    if csrf_token:
                        sess.csrf_token = csrf_token
                        csrf_ok = True
                        logger.debug(f"[Bootstrap] 获取 CSRFToken={csrf_token[:8]}...")
                    else:
                        logger.warning(f"[Bootstrap] heartbeatCheck 未返回 CSRFToken（非致命，继续）")

        if not user_ok:
            logger.error(f"[Bootstrap] 失败：无法获取 userId")
            return False

        if not csrf_ok:
            if cookies.get("CSRFToken"):
                logger.error(f"[Bootstrap] 代码 BUG：cookie 已有 CSRFToken 但 sess.csrf_token 为空，请检查 hydrate 逻辑")
            logger.warning(f"[Bootstrap] 无 CSRFToken，后续 API 调用可能失败")

        csrf_display = sess.csrf_token[:8] + "..." if sess.csrf_token else "None"
        logger.info(f"[Bootstrap] ✓ 成功，userId={mask(sess.user_id)}, csrf={csrf_display}")
        return True

    except asyncio.TimeoutError:
        logger.error(f"[Bootstrap] 超时 session={sess.session_key[:8]}")
        return False
    except aiohttp.ClientError as e:
        logger.error(f"[Bootstrap] 网络异常: {e}")
        return False
    except Exception as e:
        logger.exception(f"[Bootstrap] 未知异常: {e}")
        return False

async def call_huawei_api(url: str, body: Dict, cookies: Dict[str, str], sess: SessionState, timeout: float = 5.0, extra_headers: Optional[Dict[str, str]] = None) -> Optional[Dict]:
    if not sess.user_id or not sess.csrf_token:
        hydrate_result = hydrate_tokens_from_cookies(sess, cookies)

    if not sess.user_id or not sess.csrf_token:
        logger.debug(f"[HuaweiAPI] session={sess.session_key[:8]} 缺少 token（userId={bool(sess.user_id)}, csrf={bool(sess.csrf_token)}），执行 bootstrap")
        bootstrap_ok = await ensure_api_tokens(sess, cookies)
        if not bootstrap_ok:
            logger.error(f"[HuaweiAPI] bootstrap 失败 session={sess.session_key[:8]}")
            return {"code": 990, "info": "BOOTSTRAP_FAILED"}

        if not sess.user_id:
            logger.error(f"[HuaweiAPI] bootstrap 失败：无 userId")
            return {"code": 990, "info": "BOOTSTRAP_NO_USERID"}

    csrf = sess.csrf_token
    uid = sess.user_id
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "https://cloud.huawei.com",
        "Referer": FIND_DEVICE_URL,
        "User-Agent": USER_AGENT,
        "Accept-Language": "zh-CN,zh;q=0.9",
    }
    if csrf:
        headers["CSRFToken"] = csrf
        headers["X-CSRF-Token"] = csrf
    if uid:
        headers["userId"] = uid

    if extra_headers:
        headers.update(extra_headers)

    huawei_cookies = {k: v for k, v in cookies.items() if k}
    cookie_str = "; ".join([f"{k}={v}" for k, v in huawei_cookies.items()])
    if cookie_str:
        headers["Cookie"] = cookie_str

    cookie_names = list(huawei_cookies.keys())
    logger.debug(f"[HuaweiAPI] {url.split('/')[-1]}, csrf={bool(csrf)}, uid={bool(uid)}, cookies={len(cookie_names)}")

    try:
        async with state.http_session.post(url, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            status = r.status
            ct = r.headers.get("Content-Type", "")
            text = await r.text()

            if status in (401, 403):
                logger.error(f"[HuaweiAPI] HTTP {status}（鉴权失败）, ct={ct}, body={text[:100]}")
                sess.user_id = ""
                sess.csrf_token = ""
                return {"code": 990, "info": f"HTTP_{status}_AUTH_FAILED"}

            if status != 200:
                logger.error(f"[HuaweiAPI] HTTP {status}, ct={ct}, body={text[:100]}")
                return {"code": -1, "info": f"HTTP_{status}"}

            if _is_html(text):
                logger.error(f"[HuaweiAPI] 返回HTML（会话失效）, ct={ct}, body={text[:100]}")
                sess.user_id = ""
                sess.csrf_token = ""
                return {"code": 990, "info": "AUTH_EXPIRED_HTML"}

            try:
                result = json.loads(text)
            except json.JSONDecodeError:
                logger.error(f"[HuaweiAPI] JSON解析失败, ct={ct}, body={text[:100]}")
                return {"code": -1, "info": "JSON_DECODE_ERROR"}

            result_code = result.get("code")
            logger.debug(f"[HuaweiAPI] {url.split('/')[-1]} code={result_code}")

            if result_code == 990:
                logger.warning(f"[HuaweiAPI] code=990（鉴权失败），清空 token")
                sess.user_id = ""
                sess.csrf_token = ""

            return result
    except asyncio.TimeoutError:
        logger.error(f"[HuaweiAPI] 请求超时 {url.split('/')[-1]}, timeout={timeout}s")
        return {"code": -1, "info": "TIMEOUT"}
    except aiohttp.ClientError as e:
        logger.exception(f"[HuaweiAPI] 网络异常 {url.split('/')[-1]}: {e}")
        return {"code": -1, "info": f"CLIENT_ERROR: {str(e)}"}
    except Exception as e:
        logger.exception(f"[HuaweiAPI] 未知异常 {url.split('/')[-1]}: {e}")
        return {"code": -1, "info": f"EXCEPTION: {str(e)}"}

@asynccontextmanager
async def lifespan(app: FastAPI):
    state.http_session = aiohttp.ClientSession()
    logger.info("[Startup] 全局 aiohttp session 已创建")

    yield

    if state.http_session:
        await state.http_session.close()
        logger.info("[Shutdown] 全局 aiohttp session 已关闭")

    if state.browser:
        await state.browser.close()
        logger.info("[Shutdown] Playwright 浏览器已关闭")

    if state.playwright:
        await state.playwright.stop()
        logger.info("[Shutdown] Playwright 已停止")

app = FastAPI(title="华为云查找设备 API", version=VERSION, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class LoginReq(BaseModel):
    session_key: str
    username: str
    password: str

class SyncReq(BaseModel):
    session_key: str
    force_locate: bool = False

@app.get("/status")
async def status(session_key: Optional[str] = None):
    if session_key:
        sess = state.get_session(session_key)
        return {
            "logged_in": sess.storage_path.exists() and not sess.need_reauth,
            "need_reauth": sess.need_reauth,
            "last_err_reason": sess.last_err_reason,
            "session_key": session_key,
            "storage_exists": sess.storage_path.exists(),
            "version": VERSION
        }
    else:
        return {
            "version": VERSION,
            "total_sessions": len(state.sessions),
            "storage_dir": str(STORAGE_DIR)
        }

@app.post("/auth/ensure")
async def auth_ensure(req: LoginReq):
    sess = state.get_session(req.session_key)

    logger.debug(f"[/auth/ensure] session={req.session_key[:8]}, user={mask(req.username)}")

    sess.credentials = {
        "username": req.username,
        "password": req.password,
        "last_update": time.time()
    }

    if sess.login_task and not sess.login_task.done():
        logger.debug(f"[/auth/ensure] 登录任务运行中，跳过")
        return {"ok": True, "status": "IN_PROGRESS", "message": "登录任务运行中", "session_key": req.session_key}

    if sess.storage_path.exists() and not sess.need_reauth and sess.device_list:
        logger.debug(f"[/auth/ensure] 会话有效且已有设备列表，跳过登录")
        return {"ok": True, "status": "ALREADY_READY", "message": "会话有效", "session_key": req.session_key}

    if sess.storage_path.exists() and not sess.need_reauth:
        logger.debug(f"[/auth/ensure] 会话有效")
        return {"ok": True, "status": "SESSION_VALID", "message": "会话有效", "session_key": req.session_key}

    trigger_refresh_login_nowait(sess, reason="MANUAL_AUTH_ENSURE")

    return {"ok": True, "status": "LOGIN_TRIGGERED", "message": "已触发后台登录", "session_key": req.session_key}

@app.post("/login")
async def login(req: LoginReq):
    return await auth_ensure(req)

async def _get_share_grant_info(cookies: Dict, sess: SessionState) -> List[Dict]:
    """调用 getShareGrantInfo 获取共享给我的设备授权列表"""
    result = await call_huawei_api(
        "https://cloud.huawei.com/findDevice/getShareGrantInfo",
        {"traceId": trace_id()},
        cookies,
        sess,
        timeout=5.0
    )
    if not result or _safe_int(result.get("code")) != 0:
        logger.warning(
            f"[ShareGrant] getShareGrantInfo 失败: "
            f"code={result.get('code') if result else 'None'}, "
            f"info={result.get('info') if result else 'None'}"
        )
        return []
    grants = result.get("shareGrantInfoList") or []
    logger.debug(f"[ShareGrant] 原始授权条数: {len(grants)}")
    return grants


def _map_grants_to_shared_devices(grants: List[Dict]) -> List[Dict]:
    """将 shareGrantInfoList 映射为统一设备格式（is_shared=True）"""
    devices = []
    for g in grants:
        device_id = g.get("senderDeviceId")
        sender_user_id = g.get("senderUserId")
        if not device_id or not sender_user_id:
            logger.debug(f"[ShareGrant] 跳过无效授权条目: {list(g.keys())}")
            continue
        devices.append({
            "deviceId": device_id,
            "deviceType": g.get("senderDeviceType", 9),
            "deviceAliasName": g.get("senderDeviceName") or "",
            "deviceName": g.get("senderDeviceName") or "",
            "name": g.get("senderDeviceName") or "",
            "senderUserId": sender_user_id,
            "relationType": 2,
            "is_shared": True,
            "unique_key": f"{device_id}__{sender_user_id}",
        })
    return devices


def _build_locate_payload(dev_info: Dict) -> Dict:
    """构建 locate 请求 payload，共享设备额外附加 senderUserId/relationType"""
    payload = {
        "deviceType": dev_info.get("deviceType", 9),
        "deviceId": dev_info.get("deviceId", ""),
        "perDeviceType": "0",
        "cptList": "",
        "traceId": trace_id(),
    }
    if dev_info.get("is_shared"):
        payload["senderUserId"] = dev_info["senderUserId"]
        payload["relationType"] = 2
    return payload


def _build_query_payload(dev_info: Dict, sequence: int = 0) -> Dict:
    """构建 queryLocateResult 请求 payload，共享设备额外附加 senderUserId/relationType"""
    payload = {
        "traceId": trace_id(),
        "deviceId": dev_info.get("deviceId", ""),
        "deviceType": dev_info.get("deviceType", 9),
        "perDeviceType": "0",
        "sequence": sequence,
        "presetDevice": False,
    }
    if dev_info.get("is_shared"):
        payload["senderUserId"] = dev_info["senderUserId"]
        payload["relationType"] = 2
    return payload


@app.post("/sync")
async def sync(req: SyncReq):
    start = time.time()
    sess = state.get_session(req.session_key)

    logger.info(f"[/sync] ========== 收到同步请求 ==========")
    logger.info(f"[/sync] session={req.session_key[:8]}, force_locate={req.force_locate}")
    logger.info(f"[/sync] storage_path={sess.storage_path}")
    logger.info(f"[/sync] storage_exists={sess.storage_path.exists()}")

    if sess.login_task and not sess.login_task.done():
        logger.info(f"[/sync] session={req.session_key[:8]} 登录任务运行中")
        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "LOGIN_IN_PROGRESS",
            "message": "后台登录中，请稍候",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    if not sess.storage_path.exists():
        logger.warning(f"[/sync] session={req.session_key[:8]} storage_state 不存在")

        if sess.credentials.get("username"):
            trigger_refresh_login_nowait(sess, reason="NO_STORAGE_STATE")
            return {
                "code": 990,
                "ok": False,
                "need_reauth": True,
                "reason": "LOGIN_IN_PROGRESS",
                "message": "后台登录中，请稍候",
                "devices": [],
                "cost_ms": int((time.time() - start) * 1000),
                "session_key": req.session_key
            }

        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "NO_SESSION",
            "message": "会话不存在，请配置凭据",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }
    
    cookies = await get_cookies_from_storage(sess.storage_path)
    if not cookies:
        logger.error(f"[/sync] session={req.session_key[:8]} cookies 解析失败")

        if sess.credentials.get("username"):
            trigger_refresh_login_nowait(sess, reason="COOKIES_PARSE_FAILED")
            return {
                "code": 990,
                "ok": False,
                "need_reauth": True,
                "reason": "LOGIN_IN_PROGRESS",
                "message": "后台登录中，请稍候",
                "devices": [],
                "cost_ms": int((time.time() - start) * 1000),
                "session_key": req.session_key
            }

        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "NOT_LOGGED_IN",
            "message": "Cookies 解析失败，请配置凭据",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    hydrate_result = hydrate_tokens_from_cookies(sess, cookies)
    logger.debug(f"[/sync] hydrate 结果: csrf_ok={hydrate_result['csrf_ok']}, user_ok={hydrate_result['user_ok']}")

    device_list_result = await call_huawei_api(
        "https://cloud.huawei.com/findDevice/getMobileDeviceList",
        {"traceId": trace_id(), "tabLocation": 2, "portalType": 0},
        cookies,
        sess,
        timeout=5.0
    )

    if not device_list_result:
        logger.error(f"[/sync] getMobileDeviceList 返回 None")
        return {
            "code": -1,
            "ok": False,
            "need_reauth": False,
            "reason": "API_CALL_FAILED",
            "message": "调用华为 API 失败",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    raw_code = device_list_result.get("code")
    code = _safe_int(raw_code)
    if code == -1 and raw_code is not None:
        logger.warning(f"[/sync] code 类型转换失败: raw_code={raw_code}, type={type(raw_code)}")
    info = device_list_result.get("info", "")

    if code == 990:
        logger.warning(f"[/sync] getDeviceList code=990（鉴权失败），尝试 bootstrap 重试")

        sess.user_id = ""
        sess.csrf_token = ""
        bootstrap_start = time.time()
        bootstrap_retry_ok = await ensure_api_tokens(sess, cookies)
        bootstrap_elapsed = int((time.time() - bootstrap_start) * 1000)

        if bootstrap_retry_ok and sess.user_id and sess.csrf_token:
            logger.info(f"[/sync] bootstrap 重试成功（{bootstrap_elapsed}ms），重新调用 getMobileDeviceList")
            device_list_result = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/getMobileDeviceList",
                {"traceId": trace_id(), "tabLocation": 2, "portalType": 0},
                cookies,
                sess,
                timeout=8.0
            )
            raw_code = device_list_result.get("code", -1) if device_list_result else -1
            try:
                code = int(raw_code) if raw_code is not None else -1
            except (ValueError, TypeError):
                code = -1
            info = device_list_result.get("info", "") if device_list_result else ""

            if code == 0:
                logger.info(f"[/sync] bootstrap 重试后成功")
            else:
                logger.error(f"[/sync] bootstrap 重试后仍失败 code={code}，触发登录")
                if sess.credentials.get("username"):
                    trigger_refresh_login_nowait(sess, reason="AUTH_FAILED_990_AFTER_RETRY")
                    return {
                        "code": 990,
                        "ok": False,
                        "need_reauth": True,
                        "reason": "LOGIN_IN_PROGRESS",
                        "message": "鉴权失败，后台登录中",
                        "devices": [],
                        "cost_ms": int((time.time() - start) * 1000),
                        "session_key": req.session_key
                    }
                return {
                    "code": 990,
                    "ok": False,
                    "need_reauth": True,
                    "reason": info or "AUTH_EXPIRED_AFTER_RETRY",
                    "message": "鉴权失败，请配置凭据",
                    "devices": [],
                    "cost_ms": int((time.time() - start) * 1000),
                    "session_key": req.session_key
                }
        else:
            logger.error(f"[/sync] bootstrap 重试失败（{bootstrap_elapsed}ms），触发登录")
            if sess.credentials.get("username"):
                trigger_refresh_login_nowait(sess, reason="AUTH_FAILED_990")
                return {
                    "code": 990,
                    "ok": False,
                    "need_reauth": True,
                    "reason": "LOGIN_IN_PROGRESS",
                    "message": "鉴权失败，后台登录中",
                    "devices": [],
                    "cost_ms": int((time.time() - start) * 1000),
                    "session_key": req.session_key
                }
            return {
                "code": 990,
                "ok": False,
                "need_reauth": True,
                "reason": info or "AUTH_EXPIRED",
                "message": "鉴权失败，请配置凭据",
                "devices": [],
                "cost_ms": int((time.time() - start) * 1000),
                "session_key": req.session_key
            }
    elif code == -1:
        logger.error(f"[/sync] getMobileDeviceList code=-1: {info}")
        return {
            "code": -1,
            "ok": False,
            "need_reauth": False,
            "reason": info or "NETWORK_ERROR",
            "message": f"网络错误: {info}",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }
    elif code != 0:
        logger.error(f"[/sync] getMobileDeviceList code={code}, info={info}")
        return {
            "code": code,
            "ok": False,
            "need_reauth": False,
            "reason": f"API_ERROR_{code}",
            "message": f"API 错误 (code={code}): {info}",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    my_device_list = device_list_result.get("deviceList") or []
    logger.info(f"[/sync] ✅ getMobileDeviceList 成功 code=0, my_devices_count={len(my_device_list)}")

    # 获取共享设备
    shared_grants = await _get_share_grant_info(cookies, sess)
    shared_devices = _map_grants_to_shared_devices(shared_grants)
    logger.info(f"[/sync] shared_devices_count={len(shared_devices)}")

    # 标记我的设备
    for d in my_device_list:
        d.setdefault("is_shared", False)
        d["unique_key"] = d.get("deviceId", "")

    all_devices = my_device_list + shared_devices

    # 去重：同一 deviceId 在自有/共享列表均出现时，优先保留自有设备
    _seen_dedup: set = set()
    _deduped: list = []
    for _d in all_devices:
        _did = _d.get("deviceId")
        if _did and _did in _seen_dedup:
            logger.warning(f"[/sync] device={mask(_did)} 去重：跳过重复条目 is_shared={_d.get('is_shared')}")
            continue
        if _did:
            _seen_dedup.add(_did)
        _deduped.append(_d)
    all_devices = _deduped

    sess.device_list = all_devices.copy()

    if not all_devices:
        logger.debug(f"[/sync] 设备列表为空，跳过坐标轮询")
        return {
            "code": 0,
            "ok": True,
            "need_reauth": False,
            "message": "获取设备列表成功（无设备）",
            "devices": [],
            "device_count": 0,
            "active": False,
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    active_locate_triggered = False
    if req.force_locate:
        logger.info(f"[/sync] force_locate=true，触发主动定位")
        for dev_info in all_devices:
            dev_id = dev_info.get("deviceId")
            if not dev_id:
                continue
            is_shared = dev_info.get("is_shared", False)
            logger.debug(f"[/sync] device={mask(dev_id)} is_shared={is_shared} 触发定位")
            locate_trigger = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/locate",
                _build_locate_payload(dev_info),
                cookies,
                sess,
                timeout=5.0
            )
            trigger_code = str(locate_trigger.get("code")) if locate_trigger else "-1"
            if trigger_code == "0":
                active_locate_triggered = True
                logger.info(f"[/sync] device={mask(dev_id)} 主动定位触发成功")
            else:
                logger.warning(f"[/sync] device={mask(dev_id)} 主动定位触发失败 code={trigger_code}")

    devices = []
    for dev_info in all_devices:
        dev_id = dev_info.get("deviceId")
        if not dev_id:
            continue

        unique_key = dev_info.get("unique_key", dev_id)
        is_shared = dev_info.get("is_shared", False)
        logger.debug(f"[/sync] 处理设备 device={mask(dev_id)} is_shared={is_shared}")

        max_poll = 15
        lat, lng, battery, locate_time, accuracy = None, None, None, None, None
        code, info = -1, ""
        _is_fresh = False
        _stale_reason = ""

        for poll_idx in range(max_poll):
            # 固定 2s 间隔（force_locate 时），首次不等待
            if req.force_locate and poll_idx > 0:
                await asyncio.sleep(2.0)

            result = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/queryLocateResult",
                _build_query_payload(dev_info, poll_idx),
                cookies,
                sess,
                timeout=3.0
            )

            raw_code = result.get("code", -1) if result else -1
            try:
                code = int(raw_code) if raw_code is not None else -1
            except (ValueError, TypeError):
                code = -1
            info = result.get("info", "")

            if code == 990:
                logger.warning(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} code=990（定位权限可能未激活）")
                _stale_reason = "AUTH_EXPIRED"
                break

            if code == -1:
                logger.error(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} code=-1（网络错误）: {info}")
                _stale_reason = "NETWORK_ERROR"
                break

            if code not in (0, 1):
                logger.error(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} code={code}")
                _stale_reason = f"API_ERROR_{code}"
                break

            # --- 解析 locateInfo（可能是 JSON 字符串）---
            loc = result.get("locateInfo", {})
            _loc_type = type(loc).__name__
            if isinstance(loc, str):
                try:
                    loc = json.loads(loc)
                    logger.debug(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} locateInfo: str→dict (len={len(result.get('locateInfo',''))})")
                except json.JSONDecodeError as e:
                    logger.warning(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} locateInfo JSON解析失败: {e}, value={str(result.get('locateInfo',''))[:100]}")
                    loc = {}
            elif not isinstance(loc, dict):
                logger.warning(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} locateInfo 类型异常: type={_loc_type}")
                loc = {}

            # --- 解析 coordinateInfo（第二层 JSON 字符串）---
            coord: Dict = {}
            _coord_raw = loc.get("coordinateInfo")
            if isinstance(_coord_raw, str) and _coord_raw:
                try:
                    coord = json.loads(_coord_raw)
                    logger.debug(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} coordinateInfo: str→dict keys={list(coord.keys())}")
                except json.JSONDecodeError as e:
                    logger.debug(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} coordinateInfo JSON解析失败: {e}")
            elif isinstance(_coord_raw, dict):
                coord = _coord_raw
                logger.debug(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} coordinateInfo: already dict")

            # exeResult 检查（"0"=完成，其他=仍在进行中）
            exe_result = str(result.get("exeResult", loc.get("exeResult", "")))

            # --- 坐标提取（优先级：locateInfo.WGS84 > coordinateInfo > locateInfo.GCJ02）---
            _lat_wgs = loc.get("latitude_WGS")
            _lng_wgs = loc.get("longitude_WGS")
            _lat_coord = coord.get("latitude")
            _lng_coord = coord.get("longitude")
            # sysType: "0"=GCJ-02, "1"=WGS-84, "2"=BD-09；未知时按 GCJ-02 处理
            _sys_type = str(coord.get("sysType", "")) if coord else ""
            _lat_gcj_top = loc.get("latitude")
            _lng_gcj_top = loc.get("longitude")

            _parse_path = "none"
            if _lat_wgs is not None and _lng_wgs is not None:
                lat = float(_lat_wgs)
                lng = float(_lng_wgs)
                _parse_path = "top-level WGS84"
                logger.debug(f"[/sync] device={mask(dev_id)} 坐标来源: {_parse_path}")
            elif _lat_coord is not None and _lng_coord is not None:
                if _sys_type == "1":
                    lat = float(_lat_coord)
                    lng = float(_lng_coord)
                    _parse_path = "coordinateInfo WGS84 (sysType=1)"
                elif _sys_type == "2":
                    gcj_lng, gcj_lat = bd09_to_gcj02(float(_lng_coord), float(_lat_coord))
                    lng, lat = gcj02_to_wgs84(gcj_lng, gcj_lat)
                    _parse_path = "coordinateInfo BD09→GCJ02→WGS84 (sysType=2)"
                else:
                    lng, lat = gcj02_to_wgs84(float(_lng_coord), float(_lat_coord))
                    _parse_path = f"coordinateInfo GCJ02→WGS84 (sysType={_sys_type or '?'})"
                logger.debug(f"[/sync] device={mask(dev_id)} 坐标来源: {_parse_path}")
            elif _lat_gcj_top is not None and _lng_gcj_top is not None:
                lng, lat = gcj02_to_wgs84(float(_lng_gcj_top), float(_lat_gcj_top))
                _parse_path = "top-level GCJ02→WGS84 fallback"
                logger.debug(f"[/sync] device={mask(dev_id)} 坐标来源: {_parse_path}")
            # --- DEBUG: 打印坐标数值（输入/输出）---
            if logger.isEnabledFor(logging.DEBUG) and lat is not None and lng is not None:
                try:
                    if "WGS84" in _parse_path and "GCJ02" not in _parse_path:
                        logger.debug(
                            f"[/sync] device={mask(dev_id)} COORD OUT(WGS84) lat={float(lat):.6f}, lng={float(lng):.6f}"
                        )
                    elif _lat_coord is not None and _lng_coord is not None and "coordinateInfo" in _parse_path:
                        logger.debug(
                            f"[/sync] device={mask(dev_id)} COORD IN(GCJ02)  lat={float(_lat_coord):.6f}, lng={float(_lng_coord):.6f}"
                        )
                        logger.debug(
                            f"[/sync] device={mask(dev_id)} COORD OUT(WGS84) lat={float(lat):.6f}, lng={float(lng):.6f}"
                        )
                    elif _lat_gcj_top is not None and _lng_gcj_top is not None:
                        logger.debug(
                            f"[/sync] device={mask(dev_id)} COORD IN(GCJ02)  lat={float(_lat_gcj_top):.6f}, lng={float(_lng_gcj_top):.6f}"
                        )
                        logger.debug(
                            f"[/sync] device={mask(dev_id)} COORD OUT(WGS84) lat={float(lat):.6f}, lng={float(lng):.6f}"
                        )
                except Exception as e:
                    logger.debug(f"[/sync] device={mask(dev_id)} 坐标打印失败: {e}")
            # accuracy（优先 coordinateInfo）
            accuracy = coord.get("accuracy") if coord.get("accuracy") is not None else loc.get("accuracy")

            # battery
            battery = loc.get("battery")
            if not battery:
                battery_status = loc.get("batteryStatus")
                if isinstance(battery_status, str):
                    try:
                        battery_obj = json.loads(battery_status)
                        battery = battery_obj.get("percentage")
                    except (json.JSONDecodeError, AttributeError):
                        pass

            locate_time = coord.get("time") if coord else None
            if locate_time is None and coord:
                locate_time = coord.get("currentTime")
            if locate_time is None:
                for _tf in ["executeTime", "locateTime", "updateTime", "lastUpdateTime", "timeStamp", "timestamp", "time"]:
                    if _tf in loc:
                        locate_time = loc.get(_tf)
                        break

            if lat is not None and lng is not None:
                _is_fresh = True
                logger.info(f"[/sync] device={mask(dev_id)} poll={poll_idx+1}/{max_poll} ✓ 获取坐标 path={_parse_path}, battery={battery}, time={locate_time}")
                break

            # exeResult=="0" 且没坐标：定位已完成但无结果，不必继续轮询
            if exe_result == "0" and lat is None:
                logger.debug(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} exeResult=0 但无坐标，停止轮询")
                _stale_reason = "定位完成但无坐标"
                break

            logger.debug(f"[/sync] device={mask(dev_id)} poll={poll_idx+1} 无坐标 exeResult={exe_result!r}, 继续轮询...")

            if poll_idx < max_poll - 1 and not req.force_locate:
                await asyncio.sleep(0.4 + 0.2 * (poll_idx % 3) / 3)

        # 超时未获坐标
        if lat is None and not _stale_reason:
            _stale_reason = "定位超时"

        # --- 错误码降级：从缓存取旧数据保持实体可用 ---
        if code == 990:
            cached = sess.device_cache.get(unique_key)
            if cached:
                devices.append({**cached, "stale": True, "is_fresh": False,
                                 "stale_reason": "AUTH_EXPIRED", "reason": "AUTH_EXPIRED"})
            continue

        if code == -1:
            cached = sess.device_cache.get(unique_key)
            if cached:
                devices.append({**cached, "stale": True, "is_fresh": False,
                                 "stale_reason": info or "NETWORK_ERROR", "reason": info or "NETWORK_ERROR"})
            continue

        if code not in (0, 1):
            cached = sess.device_cache.get(unique_key)
            if cached:
                devices.append({**cached, "stale": True, "is_fresh": False,
                                 "stale_reason": info or f"API_ERROR_{code}",
                                 "reason": info or f"API_ERROR_{code}"})
            continue

        # --- 坐标为空时：降级到缓存中的旧坐标（is_fresh=False）---
        if lat is None:
            cached = sess.device_cache.get(unique_key)
            if cached and cached.get("latitude") is not None:
                lat = cached["latitude"]
                lng = cached["longitude"]
                logger.info(f"[/sync] device={mask(dev_id)} 定位未完成（{_stale_reason}），使用缓存坐标 lat={lat}")
            else:
                logger.info(f"[/sync] device={mask(dev_id)} 定位未完成（{_stale_reason}），无缓存坐标")

        model = (
            dev_info.get("modelName") or
            dev_info.get("model") or
            None
        )

        device_name = (
            dev_info.get("deviceAliasName") or
            dev_info.get("deviceName") or
            dev_info.get("name") or
            None
        )

        phone = dev_info.get("phone") or dev_info.get("msisdn", "")

        if not model:
            all_keys = list(dev_info.keys())
            logger.warning(
                f"[/sync] device={mask(dev_id)} ⚠️ 华为 API 未返回 model 相关字段 "
                f"(modelName/model)，可用字段({len(all_keys)}个):"
            )
            logger.warning(f"[/sync] device={mask(dev_id)} 字段列表: {all_keys}")

            interesting_fields = ["deviceType", "deviceTypeName", "phoneModel",
                                  "productModel", "manufacturer", "brand"]
            for field in interesting_fields:
                if field in dev_info:
                    logger.info(f"[/sync] device={mask(dev_id)} {field}={dev_info.get(field)}")

            logger.info(
                f"[/sync] device={mask(dev_id)} 后备方案: "
                f"device_name={device_name or 'None'}"
            )

        if device_name and device_name.strip():
            name = device_name.strip()
        elif model and model.strip():
            name = model.strip()
        else:
            short_id = dev_id[-8:] if len(dev_id) >= 8 else dev_id
            name = f"Huawei Device {short_id.upper()}"

        logger.info(
            f"[/sync] device={mask(dev_id)} is_shared={is_shared} is_fresh={_is_fresh} "
            f"name={name}, locate_time={locate_time}"
        )

        if locate_time is not None:
            try:
                ts = int(locate_time) if int(locate_time) < 10000000000 else int(locate_time) // 1000
            except (ValueError, TypeError):
                ts = int(time.time())
        else:
            ts = int(time.time())

        data = {
            "device_id": unique_key,
            "name": name,
            "model": model or name,
            "deviceAliasName": device_name,
            "phone": phone,
            "latitude": lat,
            "longitude": lng,
            "accuracy": accuracy,
            "battery": battery,
            "stale": not _is_fresh,
            "is_fresh": _is_fresh,
            "stale_reason": _stale_reason if not _is_fresh else "",
            "ts": ts,
            "is_shared": is_shared,
        }
        if is_shared:
            data["senderUserId"] = dev_info.get("senderUserId", "")

        # 只有拿到新坐标时才更新缓存，避免用空坐标覆盖好的缓存
        if _is_fresh:
            sess.device_cache[unique_key] = data
        elif unique_key not in sess.device_cache:
            sess.device_cache[unique_key] = data

        devices.append(data)

        logger.debug(f"[/sync] device={mask(dev_id)} is_shared={is_shared}: has_location={lat is not None}, is_fresh={_is_fresh}, bat={battery}")
    
    cost_ms = int((time.time() - start) * 1000)
    logger.info(f"[/sync] ✅ 成功，device_count={len(devices)}, {cost_ms}ms")

    sess.device_list = devices.copy()

    return {
        "code": 0,  # 成功
        "ok": True,
        "need_reauth": False,
        "message": f"获取设备列表成功（{len(devices)} 台设备）",
        "devices": devices,
        "device_count": len(devices),
        "active": active_locate_triggered,
        "cost_ms": cost_ms,
        "session_key": req.session_key
    }

@app.post("/locate")
async def active_locate(req: SyncReq):
    start = time.time()
    sess = state.get_session(req.session_key)

    logger.info(f"[/locate] 收到主动定位请求 session={req.session_key[:8]}")

    last_locate_time = sess.last_locate_time if hasattr(sess, 'last_locate_time') else 0
    now = time.time()
    if (now - last_locate_time) < 60:
        wait_time = int(60 - (now - last_locate_time))
        logger.warning(f"[/locate] 限流保护：距离上次定位仅 {int(now - last_locate_time)} 秒，需等待 {wait_time} 秒")
        return {
            "ok": False,
            "code": -2,
            "message": f"请求过于频繁，请等待 {wait_time} 秒后重试",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    sess.last_locate_time = now

    if not sess.storage_path.exists():
        return {
            "ok": False,
            "code": 990,
            "need_reauth": True,
            "reason": "NO_SESSION",
            "message": "会话不存在，请先登录",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    cookies = await get_cookies_from_storage(sess.storage_path)
    if not cookies:
        return {
            "ok": False,
            "code": 990,
            "need_reauth": True,
            "reason": "NOT_LOGGED_IN",
            "message": "Cookies 解析失败",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    hydrate_tokens_from_cookies(sess, cookies)

    device_list_result = await call_huawei_api(
        "https://cloud.huawei.com/findDevice/getMobileDeviceList",
        {"deviceType": 0},
        cookies,
        sess,
        timeout=5.0
    )

    result_code = _safe_int(device_list_result.get("code")) if device_list_result else -1

    if result_code == 990:
        logger.warning(f"[/locate] code=990，尝试 bootstrap 重试")
        sess.user_id = ""
        sess.csrf_token = ""
        bootstrap_ok = await ensure_api_tokens(sess, cookies)

        if bootstrap_ok and sess.user_id and sess.csrf_token:
            device_list_result = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/getMobileDeviceList",
                {"deviceType": 0},
                cookies,
                sess,
                timeout=5.0
            )
            result_code = _safe_int(device_list_result.get("code")) if device_list_result else -1

            if result_code != 0:
                return {
                    "ok": False,
                    "code": 990,
                    "need_reauth": True,
                    "message": "鉴权失败",
                    "devices": [],
                    "cost_ms": int((time.time() - start) * 1000),
                    "session_key": req.session_key
                }

    if result_code != 0:
        return {
            "ok": False,
            "code": result_code,
            "message": device_list_result.get("info") if device_list_result else "获取设备列表失败",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    device_list = device_list_result.get("deviceList", [])
    if not device_list:
        return {
            "ok": True,
            "code": 0,
            "message": "无设备可定位",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    devices_result = []

    for dev_info in device_list:
        dev_id = dev_info.get("deviceId")
        if not dev_id:
            continue

        locate_trigger = await call_huawei_api(
            "https://cloud.huawei.com/findDevice/locate",
            {
                "deviceType": 9,
                "deviceId": dev_id,
                "perDeviceType": "0",
                "cptList": "",
                "traceId": trace_id()
            },
            cookies,
            sess,
            timeout=5.0
        )

        if not locate_trigger or str(locate_trigger.get("code")) != "0":
            logger.warning(f"[/locate] device={mask(dev_id)} 触发定位失败，尝试获取缓存位置")

            fallback_result = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/queryLocateResult",
                {
                    "traceId": trace_id(),
                    "deviceId": dev_id,
                    "deviceType": 9,
                    "sequence": 0
                },
                cookies,
                sess,
                timeout=5.0
            )
            if fallback_result and str(fallback_result.get("code")) in ("0", "1"):
                loc = fallback_result.get("locateInfo", {})
                if isinstance(loc, str):
                    try:
                        loc = json.loads(loc)
                    except json.JSONDecodeError:
                        loc = {}
                if isinstance(loc, dict):
                    fb_lat = loc.get("latitude_WGS") or loc.get("latitude")
                    fb_lng = loc.get("longitude_WGS") or loc.get("longitude")
                    if fb_lat is not None and fb_lng is not None:
                        battery_status = loc.get("batteryStatus", "{}")
                        if isinstance(battery_status, str):
                            try:
                                battery_status = json.loads(battery_status)
                            except:
                                battery_status = {}
                        fb_battery = None
                        if isinstance(battery_status, dict):
                            bat_str = battery_status.get("percentage")
                            if bat_str:
                                try:
                                    fb_battery = int(bat_str)
                                except:
                                    pass
                        devices_result.append({
                            "device_id": dev_id,
                            "deviceId": dev_id,
                            "lat": float(fb_lat),
                            "lng": float(fb_lng),
                            "latitude": float(fb_lat),
                            "longitude": float(fb_lng),
                            "accuracy": int(loc.get("accuracy")) if loc.get("accuracy") else None,
                            "battery": fb_battery,
                            "name": dev_info.get("deviceAliasName") or dev_info.get("model", "Unknown")
                        })
                        logger.info(f"[/locate] device={mask(dev_id)} 使用缓存位置, battery={fb_battery}")
                        continue
            logger.warning(f"[/locate] device={mask(dev_id)} 缓存位置也不可用，跳过")
            continue

        max_poll = 15
        for poll_idx in range(max_poll):
            await asyncio.sleep(1)

            result = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/queryLocateResult",
                {
                    "traceId": trace_id(),
                    "deviceId": dev_id,
                    "deviceType": 9,
                    "sequence": poll_idx
                },
                cookies,
                sess,
                timeout=5.0
            )

            if not result:
                continue

            code = _safe_int(result.get("code"))

            if code in (0, 1):
                loc = result.get("locateInfo", {})
                if isinstance(loc, str):
                    try:
                        loc = json.loads(loc)
                    except json.JSONDecodeError:
                        loc = {}

                if not isinstance(loc, dict):
                    loc = {}

                lat = loc.get("latitude_WGS") or loc.get("latitude")
                lng = loc.get("longitude_WGS") or loc.get("longitude")
                accuracy = loc.get("accuracy")

                battery_status = loc.get("batteryStatus", "{}")
                if isinstance(battery_status, str):
                    try:
                        battery_status = json.loads(battery_status)
                    except:
                        battery_status = {}

                battery = None
                if isinstance(battery_status, dict):
                    battery_str = battery_status.get("percentage")
                    if battery_str:
                        try:
                            battery = int(battery_str)
                        except:
                            pass

                if lat is not None and lng is not None:
                    devices_result.append({
                        "device_id": dev_id,
                        "deviceId": dev_id,
                        "lat": float(lat),
                        "lng": float(lng),
                        "latitude": float(lat),
                        "longitude": float(lng),
                        "accuracy": int(accuracy) if accuracy else None,
                        "battery": battery,
                        "name": dev_info.get("deviceAliasName") or dev_info.get("model", "Unknown")
                    })
                    logger.info(f"[/locate] device={mask(dev_id)} poll={poll_idx+1}/{max_poll} ✓ 获取坐标, battery={battery}")
                    break
        else:
            logger.warning(f"[/locate] device={mask(dev_id)} 轮询超时（{max_poll}次）")

    cost_ms = int((time.time() - start) * 1000)
    logger.info(f"[/locate] 完成 | 成功={len(devices_result)}, 耗时={cost_ms}ms")

    return {
        "ok": True,
        "code": 0,
        "message": f"定位成功（{len(devices_result)} 台设备）",
        "devices": devices_result,
        "cost_ms": cost_ms,
        "session_key": req.session_key
    }


@app.post("/findDevice/locate")
async def trigger_locate(req: SyncReq):
    start = time.time()
    sess = state.get_session(req.session_key)

    logger.info(f"[/locate] 收到主动定位请求 session={req.session_key[:8]}")

    if not sess.storage_path.exists():
        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "NO_SESSION",
            "message": "会话不存在，请先登录",
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    cookies = await get_cookies_from_storage(sess.storage_path)
    if not cookies:
        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "NOT_LOGGED_IN",
            "message": "Cookies 解析失败",
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    hydrate_tokens_from_cookies(sess, cookies)
    logger.info(f"[/locate] 开始获取设备列表 (userId={mask(sess.user_id) if sess.user_id else 'None'}, csrfToken={'exists' if sess.csrf_token else 'None'})")

    device_list_result = await call_huawei_api(
        "https://cloud.huawei.com/findDevice/getMobileDeviceList",
        {"deviceType": 0},
        cookies,
        sess,
        timeout=5.0
    )

    logger.info(f"[/locate] getMobileDeviceList 响应: code={device_list_result.get('code') if device_list_result else 'None'}, "
                f"info={device_list_result.get('info') if device_list_result else 'None'}, "
                f"deviceCount={len(device_list_result.get('deviceList', [])) if device_list_result else 0}, "
                f"完整响应键: {list(device_list_result.keys()) if device_list_result else 'None'}")

    result_code = _safe_int(device_list_result.get("code")) if device_list_result else -1

    if result_code == 990:
        logger.warning(f"[/locate] getMobileDeviceList code=990（鉴权失败），尝试 bootstrap 重试")

        sess.user_id = ""
        sess.csrf_token = ""
        bootstrap_ok = await ensure_api_tokens(sess, cookies)

        if bootstrap_ok and sess.user_id and sess.csrf_token:
            logger.info(f"[/locate] bootstrap 重试成功，重新调用 getMobileDeviceList")
            device_list_result = await call_huawei_api(
                "https://cloud.huawei.com/findDevice/getMobileDeviceList",
                {"deviceType": 0},
                cookies,
                sess,
                timeout=5.0
            )

            retry_code = _safe_int(device_list_result.get("code")) if device_list_result else -1
            if retry_code != 0:
                logger.error(f"[/locate] bootstrap 重试后仍失败，触发后台登录")
                if sess.credentials.get("username"):
                    trigger_refresh_login_nowait(sess, reason="LOCATE_AUTH_FAILED_990_AFTER_RETRY")
                return {
                    "code": 990,
                    "ok": False,
                    "need_reauth": True,
                    "message": "鉴权失败，后台登录中",
                    "cost_ms": int((time.time() - start) * 1000),
                    "session_key": req.session_key
                }
        else:
            logger.error(f"[/locate] bootstrap 重试失败，触发后台登录")
            if sess.credentials.get("username"):
                trigger_refresh_login_nowait(sess, reason="LOCATE_AUTH_FAILED_990")
            return {
                "code": 990,
                "ok": False,
                "need_reauth": True,
                "message": "鉴权失败，后台登录中",
                "cost_ms": int((time.time() - start) * 1000),
                "session_key": req.session_key
            }

    if result_code != 0:
        error_info = device_list_result.get("info") if device_list_result else "网络错误"

        logger.error(f"[/locate] 获取设备列表失败 code={result_code}, info={error_info}")
        logger.error(f"[/locate] 完整响应数据: {device_list_result}")
        logger.error(f"[/locate] Session状态: userId={'exists' if sess.user_id else 'None'}, csrfToken={'exists' if sess.csrf_token else 'None'}")
        logger.error(f"[/locate] Cookies数量: {len(cookies) if cookies else 0}")

        if result_code == -1:
            error_msg = f"获取设备列表失败: {error_info}"
        else:
            error_msg = f"获取设备列表失败 (code={result_code}): {error_info}"

        return {
            "code": -1,
            "ok": False,
            "message": error_msg,
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    device_list = device_list_result.get("deviceList", [])
    if not device_list:
        return {
            "code": 0,
            "ok": True,
            "message": "无设备可定位",
            "devices_triggered": 0,
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    success_count = 0
    failed_count = 0
    results = []

    for dev_info in device_list:
        dev_id = dev_info.get("deviceId")
        if not dev_id:
            continue

        locate_result = await call_huawei_api(
            "https://cloud.huawei.com/findDevice/locate",
            {
                "deviceType": 9,
                "deviceId": dev_id,
                "perDeviceType": "0",
                "cptList": "",
                "traceId": trace_id()
            },
            cookies,
            sess,
            timeout=5.0
        )

        if locate_result and str(locate_result.get("code")) == "0":
            success_count += 1
            device_name = dev_info.get("deviceAliasName") or dev_info.get("model", "Unknown")

            trigger_time = time.time()

            results.append({
                "device_id": dev_id,
                "status": "triggered",
                "device_name": device_name,
                "trigger_time": int(trigger_time),
                "api_response": locate_result.get("info", "Success")
            })
            logger.info(f"[/locate] ✅ 定位指令已发送: device={mask(dev_id)}, name={device_name}, api_code={locate_result.get('code')}")
        else:
            failed_count += 1
            error_msg = locate_result.get("info") if locate_result else "网络错误"
            results.append({
                "device_id": dev_id,
                "status": "failed",
                "device_name": dev_info.get("deviceAliasName") or dev_info.get("model", "Unknown"),
                "error": error_msg
            })
            logger.warning(f"[/locate] ❌ 定位指令发送失败: device={mask(dev_id)}, error={error_msg}, api_response={locate_result}")

    cost_ms = int((time.time() - start) * 1000)
    logger.info(f"[/locate] 完成 | 成功={success_count}, 失败={failed_count}, 耗时={cost_ms}ms")

    return {
        "code": 0,
        "ok": True,
        "message": f"已触发 {success_count} 台设备定位，失败 {failed_count} 台",
        "devices_triggered": success_count,
        "devices_failed": failed_count,
        "results": results,
        "cost_ms": cost_ms,
        "session_key": req.session_key
    }


@app.post("/findDevice/queryLocateResult")
async def query_locate_result(req: SyncReq):
    start = time.time()
    sess = state.get_session(req.session_key)

    logger.info(f"[/queryLocateResult] 收到查询请求 session={req.session_key[:8]}")

    if not sess.storage_path.exists():
        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "NO_SESSION",
            "message": "会话不存在",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    cookies = await get_cookies_from_storage(sess.storage_path)
    if not cookies:
        return {
            "code": 990,
            "ok": False,
            "need_reauth": True,
            "reason": "NOT_LOGGED_IN",
            "message": "Cookies 解析失败",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    hydrate_tokens_from_cookies(sess, cookies)

    device_list_result = await call_huawei_api(
        "https://cloud.huawei.com/findDevice/getMobileDeviceList",
        {"deviceType": 0},
        cookies,
        sess,
        timeout=5.0
    )

    result_code = _safe_int(device_list_result.get("code")) if device_list_result else -1
    if not device_list_result or result_code != 0:
        return {
            "code": -1,
            "ok": False,
            "message": "获取设备列表失败",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    device_list = device_list_result.get("deviceList", [])
    if not device_list:
        return {
            "code": 0,
            "ok": True,
            "message": "无设备",
            "devices": [],
            "cost_ms": int((time.time() - start) * 1000),
            "session_key": req.session_key
        }

    devices = []

    for dev_info in device_list:
        dev_id = dev_info.get("deviceId")
        if not dev_id:
            continue

        result = await call_huawei_api(
            "https://cloud.huawei.com/findDevice/queryLocateResult",
            {
                "traceId": trace_id(),
                "deviceId": dev_id,
                "deviceType": 9,
                "sequence": 0
            },
            cookies,
            sess,
            timeout=3.0
        )

        code = int(result.get("code", -1)) if result else -1

        if code in (0, 1):
            loc = result.get("locateInfo", {})
            if isinstance(loc, str):
                try:
                    loc = json.loads(loc)
                except json.JSONDecodeError:
                    loc = {}

            lat_wgs = loc.get("latitude_WGS")
            lng_wgs = loc.get("longitude_WGS")
            lat_gcj = loc.get("latitude")
            lng_gcj = loc.get("longitude")

            if lat_wgs is not None and lng_wgs is not None:
                lat = lat_wgs
                lng = lng_wgs
            elif lat_gcj is not None and lng_gcj is not None:
                lng, lat = gcj02_to_wgs84(float(lng_gcj), float(lat_gcj))
            else:
                lat = None
                lng = None

            battery = loc.get("battery")
            if not battery:
                battery_status = loc.get("batteryStatus")
                if isinstance(battery_status, str):
                    try:
                        battery_obj = json.loads(battery_status)
                        battery = battery_obj.get("battery")
                    except json.JSONDecodeError:
                        pass

            ts = loc.get("timestamp")
            if ts:
                try:
                    ts = int(ts) / 1000 if ts > 9999999999 else int(ts)
                except (ValueError, TypeError):
                    ts = None

            device_data = {
                "device_id": dev_id,
                "deviceId": dev_id,
                "deviceAliasName": dev_info.get("deviceAliasName", ""),
                "model": dev_info.get("model", ""),
                "name": dev_info.get("name", ""),
                "phone": dev_info.get("phone", ""),
                "latitude": lat,
                "longitude": lng,
                "battery": battery,
                "accuracy": loc.get("accuracy"),
                "ts": ts,
                "locate_code": code
            }

            devices.append(device_data)
            logger.debug(f"[/queryLocateResult] device={mask(dev_id)} has_location=True, battery={battery}")
        else:
            devices.append({
                "device_id": dev_id,
                "deviceId": dev_id,
                "deviceAliasName": dev_info.get("deviceAliasName", ""),
                "model": dev_info.get("model", ""),
                "name": dev_info.get("name", ""),
                "phone": dev_info.get("phone", ""),
                "latitude": None,
                "longitude": None,
                "battery": None,
                "accuracy": None,
                "ts": None,
                "locate_code": code
            })
            logger.warning(f"[/queryLocateResult] device={mask(dev_id)} code={code}（定位未完成或失败）")

    cost_ms = int((time.time() - start) * 1000)
    logger.info(f"[/queryLocateResult] 完成 | 设备数={len(devices)}, 耗时={cost_ms}ms")

    return {
        "code": 0,
        "ok": True,
        "message": f"查询成功（{len(devices)} 台设备）",
        "devices": devices,
        "device_count": len(devices),
        "cost_ms": cost_ms,
        "session_key": req.session_key
    }


# ────────────────────────────────────────────────────────────────
# /ring  响铃（找手机）
# HAR 来源: cloud.huawei.com.har  POST /findDevice/portalBellReq
# ────────────────────────────────────────────────────────────────

_BELL_URL = "https://cloud.huawei.com/findDevice/portalBellReq"
_BELL_RATE_LIMIT_SEC = 30  # 同一设备 start 最短间隔（秒）

_BELL_EXTRA_HEADERS: Dict[str, str] = {
    "x-hw-framework-type": "0",
    "x-hw-model": _HW_MODEL,
}


class RingReq(BaseModel):
    session_key: str
    device: str              # 完整 deviceId 或末尾若干位，后端模糊匹配
    action: str = "start"   # "start" | "stop"（stop 尚无 HAR 样本）


def _find_device_by_id(device_list: List[Dict], device: str) -> Optional[Dict]:
    for d in device_list:
        if (d.get("deviceId") == device
                or d.get("uniqResource") == device
                or d.get("unique_key") == device):   # 共享设备 unique_key = "deviceId__senderUserId"
            return d
    if len(device) >= 4:
        for d in device_list:
            for f in ("deviceId", "uniqResource", "deviceSn"):
                val = str(d.get(f, ""))
                if val and val.endswith(device):
                    return d
    return None


def _build_bell_body(dev_info: Dict) -> Dict:
    """构造 portalBellReq body；共享设备补加 senderUserId + relationType（与 locate 保持一致）。"""
    body = {
        "traceId": trace_id(),
        "deviceId": dev_info.get("deviceId", ""),
        "deviceType": dev_info.get("deviceType", 9),
        "perDeviceType": str(dev_info.get("perDeviceType", "0")),
        "cptList": "",
    }
    if dev_info.get("is_shared"):
        body["senderUserId"] = dev_info["senderUserId"]
        body["relationType"] = 2
    return body


async def _call_portal_bell_req(
    dev_info: Dict,
    cookies: Dict[str, str],
    sess: SessionState,
) -> Dict:
    body = _build_bell_body(dev_info)
    result = await call_huawei_api(
        _BELL_URL, body, cookies, sess,
        timeout=8.0,
        extra_headers=_BELL_EXTRA_HEADERS,
    )

    code = _safe_int(result.get("code") if result else -1)
    if code == 990:
        logger.warning(f"[/ring] portalBellReq code=990，触发重登录并重试")
        if sess.credentials.get("username"):
            trigger_refresh_login_nowait(sess, reason="BELL_AUTH_990")
        bootstrap_ok = await ensure_api_tokens(sess, cookies)
        if bootstrap_ok and sess.csrf_token:
            body = _build_bell_body(dev_info)
            result = await call_huawei_api(
                _BELL_URL, body, cookies, sess,
                timeout=8.0,
                extra_headers=_BELL_EXTRA_HEADERS,
            )

    return result or {"code": -1, "info": "NO_RESPONSE"}


@app.post("/ring")
async def ring(req: RingReq, request: Request):
    if _API_KEY and request.headers.get("X-API-Key", "") != _API_KEY:
        return {"code": 403, "msg": "Unauthorized", "device_id": req.device, "triggered": False}

    sess = state.get_session(req.session_key)
    device = req.device.strip()
    action = req.action.lower()

    logger.info(f"[/ring] session={req.session_key[:8]} device={mask(device)} action={action}")

    if action == "stop":
        return {"code": -2, "msg": "stop 暂不支持", "device_id": device, "triggered": False}
    if action != "start":
        return {"code": -2, "msg": f"未知 action={action!r}", "device_id": device, "triggered": False}

    matched = _find_device_by_id(sess.device_list, device)
    if matched:
        dev_info = matched
        dev_id = matched["deviceId"]
    else:
        logger.debug(f"[/ring] 设备未在缓存中找到，使用原值 device={mask(device)}")
        dev_info = {"deviceId": device, "deviceType": 9, "perDeviceType": "0"}
        dev_id = device

    elapsed = time.time() - sess.bell_last_start.get(dev_id, 0.0)
    if elapsed < _BELL_RATE_LIMIT_SEC:
        wait = int(_BELL_RATE_LIMIT_SEC - elapsed)
        logger.warning(f"[/ring] device={mask(dev_id)} 限流 {int(elapsed)}s，需等 {wait}s")
        return {"code": -3, "msg": f"请 {wait}s 后再试", "device_id": dev_id, "triggered": False, "cooldown_left": wait}

    if not sess.storage_path.exists():
        if sess.credentials.get("username"):
            trigger_refresh_login_nowait(sess, reason="RING_NO_STORAGE")
        return {"code": 990, "msg": "会话不存在", "device_id": dev_id, "triggered": False}

    cookies = await get_cookies_from_storage(sess.storage_path)
    if not cookies:
        return {"code": 990, "msg": "cookie 解析失败", "device_id": dev_id, "triggered": False}

    hydrate_tokens_from_cookies(sess, cookies)

    result = await _call_portal_bell_req(dev_info, cookies, sess)
    code = _safe_int(result.get("code", -1))
    triggered = code == 0

    if triggered:
        sess.bell_last_start[dev_id] = time.time()
        logger.info(f"[/ring] ✅ 响铃成功 device={mask(dev_id)}")
    else:
        logger.warning(f"[/ring] ❌ 响铃失败 code={code} info={result.get('info')}")

    return {
        "code": code,
        "msg": result.get("info", ""),
        "device_id": dev_id,
        "triggered": triggered,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": VERSION}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
