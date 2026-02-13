from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.components import persistent_notification
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import (
    DOMAIN,
    PLATFORMS,
    CONF_BASE_URL,
    CONF_USERNAME,
    CONF_SESSION_KEY,
    CONF_AMAP_API_KEY,
    CONF_PASSWORD,
    CONF_INTERVAL,
    CONF_LOW_BATT_THRESHOLD,
    CONF_ENABLE_LOW_BATT_UPDATE,
    CONF_LOW_BATT_INTERVAL,
    CONF_ENABLE_GAODE_MORE_INFO,
)
from .coordinator import StatusCoordinator, SyncCoordinator
from .exceptions import TemporaryError

_LOGGER = logging.getLogger(__name__)


def _mask_sensitive_info(text: str) -> str:
    if not text:
        return text
    if len(text) > 3:
        return text[:3] + "*" * (len(text) - 3)
    return "***"


def _schedule_fast_retry(hass: HomeAssistant, entry: ConfigEntry, coordinator: SyncCoordinator) -> None:
    import asyncio
    from homeassistant.helpers.event import async_call_later

    entry_id = entry.entry_id
    domain_data = hass.data.get(DOMAIN, {}).get(entry_id, {})

    old_task = domain_data.get("fast_retry_task")
    if old_task:
        old_task()

    retry_count = domain_data.get("fast_retry_count", 0)
    max_retries = 12

    if retry_count >= max_retries:
        _LOGGER.warning(f"[FastRetry] 已达到最大重试次数 ({max_retries})")
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_initializing_{entry_id}")
        persistent_notification.async_create(
            hass,
            title="华为云服务初始化超时",
            message=(
                "后端登录耗时过长。\n\n"
                "集成已加载，设备数据获取后实体将自动出现。\n"
                "您可以：\n"
                "- 等待几分钟后手动刷新页面\n"
                "- 重新加载集成（设置 → 华为云服务 → 重新加载）\n"
                "- 检查后端服务状态和日志"
            ),
            notification_id=f"{DOMAIN}_fallback_{entry_id}",
        )
        return

    async def _do_fast_retry(_now=None):
        domain_data = hass.data.get(DOMAIN, {}).get(entry_id)
        if not domain_data:
            return

        retry_count = domain_data.get("fast_retry_count", 0)
        domain_data["fast_retry_count"] = retry_count + 1

        _LOGGER.info(f"[FastRetry] {retry_count + 1}/{max_retries}")

        progress_pct = int((retry_count + 1) / max_retries * 100)
        progress_bar = "=" * (progress_pct // 10) + "-" * (10 - progress_pct // 10)

        persistent_notification.async_create(
            hass,
            title=f"华为云服务初始化中 ({progress_pct}%)",
            message=(
                f"正在初始化华为云服务...\n\n"
                f"后台登录进度：[{progress_bar}] {retry_count + 1}/{max_retries}\n"
                f"预计还需 {(max_retries - retry_count - 1) * 10} 秒\n\n"
                f"初始化完成后此通知会自动关闭。"
            ),
            notification_id=f"{DOMAIN}_initializing_{entry_id}",
        )

        try:
            await coordinator.async_refresh()

            sync_data = coordinator.data
            if sync_data:
                reason = sync_data.get("reason", "")
                devices = sync_data.get("devices", [])
                code = sync_data.get("code", 0)

                _LOGGER.info(
                    f"[FastRetry] code={code}, devices={len(devices)}, reason={reason}"
                )

                if code == 0 and devices and reason not in ["NO_SESSION", "LOGIN_IN_PROGRESS"]:
                    _LOGGER.info(f"[FastRetry] 成功获取 {len(devices)} 个设备")

                    old_task = domain_data.get("fast_retry_task")
                    if old_task:
                        old_task()
                        domain_data["fast_retry_task"] = None
                    domain_data["fast_retry_count"] = 0

                    persistent_notification.async_dismiss(hass, f"{DOMAIN}_initializing_{entry_id}")

                    entity_count = len(devices) * 3
                    persistent_notification.async_create(
                        hass,
                        title="华为云服务已就绪",
                        message=(
                            f"初始化完成！已加载 {len(devices)} 个设备，"
                            f"创建 {entity_count} 个实体。\n\n"
                            f"此通知将在 10 秒后自动关闭"
                        ),
                        notification_id=f"{DOMAIN}_ready_{entry_id}",
                    )

                    async def _auto_dismiss(_now=None):
                        persistent_notification.async_dismiss(hass, f"{DOMAIN}_ready_{entry_id}")

                    from homeassistant.helpers.event import async_call_later
                    async_call_later(hass, 10, _auto_dismiss)
                    return

            _LOGGER.info(
                f"[FastRetry] 未达成功条件，继续重试 "
                f"(code={code}, devices={len(devices)}, reason={reason})"
            )
            _schedule_fast_retry(hass, entry, coordinator)

        except Exception as e:
            _LOGGER.warning(f"[FastRetry] 异常: {type(e).__name__}: {e}")
            _schedule_fast_retry(hass, entry, coordinator)

    cancel_fn = async_call_later(hass, 10, _do_fast_retry)
    domain_data["fast_retry_task"] = cancel_fn


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    entry_id = entry.entry_id
    base_url = entry.data.get(CONF_BASE_URL, "").rstrip("/")
    username = entry.options.get(CONF_USERNAME, "")

    if not entry.options:
        new_options = {}
        for key in [CONF_USERNAME, CONF_PASSWORD, CONF_AMAP_API_KEY, CONF_INTERVAL,
                    CONF_LOW_BATT_THRESHOLD, CONF_ENABLE_LOW_BATT_UPDATE,
                    CONF_LOW_BATT_INTERVAL, CONF_ENABLE_GAODE_MORE_INFO]:
            if key in entry.data:
                new_options[key] = entry.data[key]
        if new_options:
            hass.config_entries.async_update_entry(entry, options=new_options)

    _LOGGER.debug(
        "设置华为云服务 (entry_id=%s, endpoint=%s, username=%s)",
        entry_id, base_url, _mask_sensitive_info(username),
    )

    import hashlib
    stable_session_key = hashlib.sha256(entry_id.encode()).hexdigest()[:32]
    if entry.data.get(CONF_SESSION_KEY) != stable_session_key:
        new_data = dict(entry.data)
        new_data[CONF_SESSION_KEY] = stable_session_key
        hass.config_entries.async_update_entry(entry, data=new_data)

    try:
        status_coordinator = StatusCoordinator(hass, entry)
        sync_coordinator = SyncCoordinator(hass, entry)
    except Exception as e:
        _LOGGER.exception("创建协调器失败: %s", e)
        persistent_notification.async_create(
            hass,
            title="华为云服务 初始化失败",
            message=f"创建协调器失败: {e}\n\n请检查配置并重试。",
            notification_id=f"{DOMAIN}_setup_error_{entry_id}",
        )
        return False

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry_id] = {
        "status_coordinator": status_coordinator,
        "sync_coordinator": sync_coordinator,
        "timeout_count": 0,
        "last_timeout_traceback": False,
        "fast_retry_count": 0,
        "fast_retry_task": None,
        "platforms_setup": False,
    }

    persistent_notification.async_create(
        hass,
        title="华为云服务 正在初始化...",
        message=(
            f"正在连接华为云服务...\n\n"
            f"账号: {_mask_sensitive_info(username)}\n"
            f"后端: {base_url}\n\n"
            f"首次登录需要 30-60 秒，请耐心等待..."
        ),
        notification_id=f"{DOMAIN}_initializing_{entry_id}",
    )

    need_fast_retry = False

    try:
        await sync_coordinator.async_config_entry_first_refresh()
    except (TemporaryError, UpdateFailed) as e:
        _LOGGER.warning("首次同步失败: %s，将启动快速重试", e)
        need_fast_retry = True
    except Exception as e:
        _LOGGER.warning("首次同步异常: %s，将启动快速重试", e)
        need_fast_retry = True

    sync_data = sync_coordinator.data
    reason = sync_data.get("reason", "") if sync_data else ""
    code = sync_data.get("code", 0) if sync_data else -1
    devices = sync_data.get("devices", []) if sync_data else []

    if not sync_data or not devices:
        need_fast_retry = True
    elif reason in ["NO_SESSION", "LOGIN_IN_PROGRESS"] or code == 990:
        need_fast_retry = True
    elif devices:
        _LOGGER.info(f"华为云服务集成已加载，获取到 {len(devices)} 个设备")

    hass.data[DOMAIN][entry_id]["timeout_count"] = 0
    hass.data[DOMAIN][entry_id]["last_timeout_traceback"] = False
    hass.data[DOMAIN][entry_id]["fast_retry_count"] = 0

    if need_fast_retry:
        _schedule_fast_retry(hass, entry, sync_coordinator)
        persistent_notification.async_create(
            hass,
            title="华为云服务 后台登录中...",
            message=(
                f"正在等待后端登录华为账号...\n\n"
                f"当前状态: {reason or 'CONNECTING'}\n"
                f"预计耗时: 30-60 秒\n\n"
                f"设备数据加载完成后，实体将自动出现。\n"
                f"请勿重新加载集成。"
            ),
            notification_id=f"{DOMAIN}_initializing_{entry_id}",
        )
    else:
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_initializing_{entry_id}")
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_fallback_{entry_id}")

    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        hass.data[DOMAIN][entry_id]["platforms_setup"] = True
    except Exception as e:
        _LOGGER.exception("设置平台失败: %s", e)
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_initializing_{entry_id}")
        persistent_notification.async_create(
            hass,
            title="华为云服务 设置平台失败",
            message=f"设置平台失败: {e}\n\n请检查日志。",
            notification_id=f"{DOMAIN}_platform_error_{entry_id}",
        )
        return False

    async def handle_force_sync(call):
        mode = call.data.get("mode", "normal")
        _LOGGER.info(f"[Service] 手动触发同步 (mode={mode})")

        if sync_coordinator._refresh_lock.locked():
            _LOGGER.warning("[Service] 已有同步任务在执行，跳过")
            persistent_notification.async_create(
                hass,
                title="华为云服务 同步",
                message="已有同步任务在执行中，请稍后再试",
                notification_id=f"{DOMAIN}_force_sync_busy",
            )
            return

        try:
            if mode == "active":
                await sync_coordinator.async_request_active_locate(force=False)
            else:
                await sync_coordinator.async_refresh()

            devices_count = len(sync_coordinator.data.get("devices", [])) if sync_coordinator.data else 0
            _LOGGER.info(f"[Service] 手动同步完成，设备数={devices_count}")

            persistent_notification.async_create(
                hass,
                title="华为云服务 同步完成",
                message=f"同步完成，当前设备数：{devices_count}",
                notification_id=f"{DOMAIN}_force_sync_done",
            )
            import asyncio
            await asyncio.sleep(3)
            persistent_notification.async_dismiss(hass, f"{DOMAIN}_force_sync_done")

        except Exception as e:
            _LOGGER.error(f"[Service] 手动同步失败: {e}")
            persistent_notification.async_create(
                hass,
                title="华为云服务 同步失败",
                message=f"同步失败：{str(e)}",
                notification_id=f"{DOMAIN}_force_sync_error",
            )

    if not hass.services.has_service(DOMAIN, "force_sync"):
        hass.services.async_register(DOMAIN, "force_sync", handle_force_sync)

    return True


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    entry_id = entry.entry_id
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        if DOMAIN in hass.data and entry_id in hass.data[DOMAIN]:
            coordinators = hass.data[DOMAIN].pop(entry_id)
            try:
                await coordinators["status_coordinator"].async_shutdown()
                await coordinators["sync_coordinator"].async_shutdown()
            except Exception as e:
                _LOGGER.warning("关闭协调器时出错: %s", e)

        persistent_notification.async_dismiss(hass, f"{DOMAIN}_initializing_{entry_id}")
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_fallback_{entry_id}")
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_ready_{entry_id}")
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_setup_error_{entry_id}")
        persistent_notification.async_dismiss(hass, f"{DOMAIN}_platform_error_{entry_id}")

    return unload_ok
