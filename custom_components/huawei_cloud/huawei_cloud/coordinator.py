from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta, datetime
from typing import Any

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.components.persistent_notification import async_create

from .const import (
    CONF_AMAP_API_KEY,
    CONF_BASE_URL,
    CONF_INTERVAL,
    CONF_SESSION_KEY,
    CONF_LOW_BATT_INTERVAL,
    CONF_LOW_BATT_THRESHOLD,
    CONF_ENABLE_LOW_BATT_UPDATE,
    CONF_USE_PAGE_LOCATION,
    DEFAULT_INTERVAL,
    DEFAULT_LOW_BATT_INTERVAL,
    DEFAULT_LOW_BATT_THRESHOLD,
    DEFAULT_USE_PAGE_LOCATION,
)

_LOGGER = logging.getLogger(__name__)


class SyncCoordinator(DataUpdateCoordinator):

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        interval = entry.options.get(CONF_INTERVAL, entry.data.get(CONF_INTERVAL, DEFAULT_INTERVAL))

        super().__init__(
            hass, _LOGGER, name="华为云同步",
            update_interval=timedelta(seconds=interval),
        )

        self.entry = entry
        self.hass = hass
        self._base_url = entry.data[CONF_BASE_URL].rstrip("/")
        self._session_key = entry.data[CONF_SESSION_KEY]
        self._need_reauth_notified = False
        self._credentials_sent = False
        self._refresh_lock = asyncio.Lock()

        self._geocode_cache: dict[str, dict[str, Any]] = {}
        self._geocode_min_interval = 60

        self._last_locate_time = 0
        self._min_locate_interval = 60

        self._last_device_count = 0
        self._current_interval = interval

        self._last_known_devices: dict[str, dict[str, Any]] = {}
        self._last_known_timestamps: dict[str, float] = {}
        self._device_cache_ttl = 3600

    def _get_amap_api_key(self) -> str:
        return self.entry.options.get(CONF_AMAP_API_KEY, "") or self.entry.data.get(CONF_AMAP_API_KEY, "")

    def _merge_with_last_known(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from .device_tracker import _get_stable_device_id

        now = time.time()
        current_ids = set()
        for dev in devices:
            dev_id = _get_stable_device_id(dev)
            if dev_id:
                current_ids.add(dev_id)
                is_fresh = dev.get("is_fresh", True)
                if is_fresh or dev_id not in self._last_known_devices:
                    # 新坐标或首次见到：整体覆盖
                    self._last_known_devices[dev_id] = dev.copy()
                else:
                    # 非新坐标：保留缓存中的 latitude/longitude/ts，其余字段更新
                    merged = self._last_known_devices[dev_id].copy()
                    for k, v in dev.items():
                        if k not in ("latitude", "longitude", "ts"):
                            merged[k] = v
                    self._last_known_devices[dev_id] = merged
                self._last_known_timestamps[dev_id] = now

        merged = list(devices)
        expired_ids = []
        for cached_id, cached_dev in self._last_known_devices.items():
            if cached_id not in current_ids:
                cached_time = self._last_known_timestamps.get(cached_id, 0)
                age = now - cached_time
                if age < self._device_cache_ttl:
                    _LOGGER.debug(f"[DeviceCache] {cached_id[:12]}... 使用缓存（{int(age)}s 前）")
                    merged.append(cached_dev)
                else:
                    expired_ids.append(cached_id)

        for eid in expired_ids:
            self._last_known_devices.pop(eid, None)
            self._last_known_timestamps.pop(eid, None)

        return merged

    def _should_use_low_battery_interval(self, devices: list[dict[str, Any]]) -> bool:
        if not self.entry.options.get(CONF_ENABLE_LOW_BATT_UPDATE, True):
            return False

        threshold = self.entry.options.get(CONF_LOW_BATT_THRESHOLD, DEFAULT_LOW_BATT_THRESHOLD)
        for device in devices:
            battery = device.get("battery")
            if battery is not None:
                try:
                    if int(battery) < threshold:
                        return True
                except (ValueError, TypeError):
                    pass
        return False

    def _update_interval_dynamically(self, devices: list[dict[str, Any]]) -> None:
        normal_interval = self.entry.options.get(CONF_INTERVAL, DEFAULT_INTERVAL)
        low_batt_interval = self.entry.options.get(CONF_LOW_BATT_INTERVAL, DEFAULT_LOW_BATT_INTERVAL)

        target = low_batt_interval if self._should_use_low_battery_interval(devices) else normal_interval

        if target != self._current_interval:
            self._current_interval = target
            self.update_interval = timedelta(seconds=target)
            _LOGGER.info(f"[Coordinator] 轮询间隔调整为 {target}s")

    async def async_request_active_locate(self, force: bool = False) -> dict[str, Any]:
        async with self._refresh_lock:
            now = time.time()
            if not force and (now - self._last_locate_time) < self._min_locate_interval:
                wait_time = int(self._min_locate_interval - (now - self._last_locate_time))
                _LOGGER.warning(f"[ActiveLocate] 限频：需等待 {wait_time}s")
                if self.data:
                    return self.data
                raise UpdateFailed(f"限频保护：请等待 {wait_time} 秒后重试")

            result = await self._call_sync(force_locate=True)
            self._last_locate_time = time.time()
            result = await self._process_sync_result(result)
            self.async_set_updated_data(result)
            return result

    async def _async_update_data(self) -> dict[str, Any]:
        if self._refresh_lock.locked():
            if self.data:
                return self.data
            raise UpdateFailed("同步任务已在进行中")

        async with self._refresh_lock:
            start_time = time.time()

            if not self._credentials_sent:
                await self._send_credentials()
                self._credentials_sent = True

            use_page_location = self.entry.options.get(CONF_USE_PAGE_LOCATION, DEFAULT_USE_PAGE_LOCATION)
            force_locate = False

            if use_page_location:
                now = time.time()
                if (now - self._last_locate_time) >= self._min_locate_interval:
                    force_locate = True

            raw_result = await self._call_sync(force_locate=force_locate)

            if force_locate and raw_result.get("code") == 0:
                self._last_locate_time = time.time()

            result = await self._process_sync_result(raw_result)

            elapsed = int((time.time() - start_time) * 1000)
            devices = result.get("devices", [])
            active = result.get("active", False)

            if devices:
                self._update_interval_dynamically(devices)

            if len(devices) != self._last_device_count or elapsed > 1000:
                fresh_count = sum(1 for d in devices if d.get("is_fresh", True))
                _LOGGER.info(
                    f"[Sync] 设备={len(devices)} | active={active} | "
                    f"is_fresh={fresh_count}/{len(devices)} | {elapsed}ms"
                )
                self._last_device_count = len(devices)

            return result

    async def _process_sync_result(self, result: dict[str, Any]) -> dict[str, Any]:
        code = result.get("code", -1)
        message = result.get("message", "")

        if code == 990 or result.get("need_reauth"):
            reason = result.get("reason", "AUTH_EXPIRED")
            _LOGGER.info(f"[Sync] 需要认证 | code={code} | reason={reason}")

            if reason == "CAPTCHA_REQUIRED" and not self._need_reauth_notified:
                async_create(
                    self.hass,
                    f"华为云服务需要验证码认证。\n\n后端无法自动登录，请手动访问：\n{self._base_url}/auth/ensure",
                    title="华为云服务 - 需要验证码",
                    notification_id=f"huawei_cloud_captcha_{self.entry.entry_id}",
                )
                self._need_reauth_notified = True
            elif reason in ["NO_SESSION", "AUTH_EXPIRED", "NOT_LOGGED_IN"] and not self._need_reauth_notified:
                async_create(
                    self.hass,
                    "华为云服务后台登录中...\n\n首次登录可能需要 60-120 秒，请稍候。",
                    title="华为云服务 - 后台登录",
                    notification_id=f"huawei_cloud_login_{self.entry.entry_id}",
                )
                self._need_reauth_notified = True

            return result

        if code == -1:
            _LOGGER.debug(f"[Sync] 网络错误: {message}")
            if self._last_known_devices:
                result["devices"] = list(self._last_known_devices.values())
            return result

        if code == 0:
            self._need_reauth_notified = False
            devices = result.get("devices", [])

            if devices:
                result["devices"] = self._merge_with_last_known(devices)
            elif self._last_known_devices:
                result["devices"] = list(self._last_known_devices.values())

            devices = result.get("devices", [])
            amap_key = self._get_amap_api_key()
            if amap_key and devices:
                await self._geocode_devices(devices)

            return result

        _LOGGER.warning(f"[Sync] 未知状态 | code={code} | message={message}")
        if not result.get("devices") and self._last_known_devices:
            result["devices"] = list(self._last_known_devices.values())
        return result

    async def _send_credentials(self):
        try:
            from .const import CONF_USERNAME, CONF_PASSWORD

            username = self.entry.options.get(CONF_USERNAME, "")
            password = self.entry.options.get(CONF_PASSWORD, "")

            if not username or not password:
                _LOGGER.warning("[Sync] 未配置用户名/密码")
                return

            url = f"{self._base_url}/auth/ensure"
            body = {"session_key": self._session_key, "username": username, "password": password}

            session = aiohttp_client.async_get_clientsession(self.hass)
            async with session.post(url, json=body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    _LOGGER.info("[Sync] 凭据已发送到后端")
                else:
                    _LOGGER.warning(f"[Sync] 发送凭据失败 HTTP {resp.status}")
        except Exception as e:
            _LOGGER.error(f"[Sync] 发送凭据异常: {e}")

    async def _call_sync(self, force_locate: bool = False) -> dict[str, Any]:
        url = f"{self._base_url}/sync"
        body = {"session_key": self._session_key, "force_locate": force_locate}
        # force_locate：后端最多 15 次轮询×2s，留余量
        timeout = 65 if force_locate else 15

        session = aiohttp_client.async_get_clientsession(self.hass)

        try:
            async with session.post(
                url, json=body, timeout=aiohttp.ClientTimeout(total=timeout)
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    _LOGGER.warning(f"[Sync] HTTP {resp.status}: {text[:100]}")
                    raise UpdateFailed(f"HTTP {resp.status}")
                return await resp.json()

        except asyncio.TimeoutError as err:
            _LOGGER.debug(f"[Sync] 超时 (force_locate={force_locate})")
            raise UpdateFailed("请求超时") from err
        except aiohttp.ClientError as err:
            _LOGGER.debug(f"[Sync] 网络错误: {err}")
            raise UpdateFailed(f"网络错误: {err}") from err

    async def _geocode_devices(self, devices: list[dict[str, Any]]) -> None:
        for device in devices:
            device_id = device.get("device_id")
            if not device_id:
                continue

            wgs_lat = device.get("latitude")
            wgs_lng = device.get("longitude")
            if wgs_lat is None or wgs_lng is None:
                continue

            cached = self._geocode_cache.get(device_id)
            now = datetime.now().timestamp()

            if cached:
                if (cached.get("lat") == wgs_lat
                    and cached.get("lng") == wgs_lng
                    and (now - cached.get("timestamp", 0)) < self._geocode_min_interval):
                    device["address"] = cached.get("address", "")
                    continue

            try:
                address = await self._gaode_reverse_geocode(wgs_lng, wgs_lat)
                device["address"] = address
                self._geocode_cache[device_id] = {
                    "lat": wgs_lat, "lng": wgs_lng,
                    "address": address, "timestamp": now,
                }
                device["address_time"] = int(now)
            except Exception as e:
                _LOGGER.warning(f"[Geocode] 失败: device={device_id[:12]}..., error={e}")

    async def _gaode_reverse_geocode(self, lng: float, lat: float) -> str:
        from .device_tracker import wgs84_to_gcj02
        gcj_lng, gcj_lat = wgs84_to_gcj02(lng, lat)

        params = {
            "key": self._get_amap_api_key(),
            "location": f"{gcj_lng},{gcj_lat}",
            "extensions": "base",
            "output": "json",
        }

        session = aiohttp_client.async_get_clientsession(self.hass)
        async with session.get(
            "https://restapi.amap.com/v3/geocode/regeo",
            params=params, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status != 200:
                raise Exception(f"HTTP {resp.status}")

            data = await resp.json()
            if data.get("status") != "1":
                raise Exception(f"高德 API 错误: {data.get('info', '未知')}")

            address = data.get("regeocode", {}).get("formatted_address", "")
            if not address:
                raise Exception("未返回地址信息")
            return address


class StatusCoordinator(DataUpdateCoordinator):

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass, _LOGGER, name="华为云状态",
            update_interval=timedelta(seconds=60),
        )
        self.entry = entry
        self.hass = hass
        self._base_url = entry.data[CONF_BASE_URL].rstrip("/")
        self._session_key = entry.data[CONF_SESSION_KEY]

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            session = aiohttp_client.async_get_clientsession(self.hass)
            async with session.get(
                f"{self._base_url}/status",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return {"logged_in": False, "error": f"HTTP {resp.status}"}
                return await resp.json()
        except Exception as err:
            _LOGGER.debug(f"[Status] 检查失败: {err}")
            return {"logged_in": False, "error": str(err)}
