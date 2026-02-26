from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp
from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_BASE_URL, CONF_SESSION_KEY, CONF_API_KEY, DOMAIN
from .coordinator import SyncCoordinator
from .device_tracker import _get_stable_device_id

_LOGGER = logging.getLogger(__name__)
_RING_COOLDOWN_SEC = 30


def _create_ring_buttons(
    sync_coordinator: SyncCoordinator,
    entry: ConfigEntry,
    known_ids: set[str],
) -> list[HuaweiRingButton]:
    if not sync_coordinator.data:
        return []

    reason = sync_coordinator.data.get("reason", "")
    code = sync_coordinator.data.get("code", 0)
    if reason in ["NO_SESSION", "LOGIN_IN_PROGRESS"] or code == 990:
        return []

    devices = sync_coordinator.data.get("devices", [])
    entities = []

    for device in devices:
        device_id = _get_stable_device_id(device)
        if not device_id or device_id in known_ids:
            continue

        device_alias = device.get("deviceAliasName", "")
        model = device.get("model", "")
        name = device.get("name", "")
        if not (device_alias or model or name):
            continue

        final_name = device_alias or model or name or f"huawei_{device_id[:6]}"
        known_ids.add(device_id)
        entities.append(
            HuaweiRingButton(sync_coordinator, entry, device_id, final_name, model or final_name)
        )

    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinators = hass.data[DOMAIN][entry.entry_id]
    sync_coordinator: SyncCoordinator = coordinators["sync_coordinator"]
    known_ids: set[str] = set()

    entities = _create_ring_buttons(sync_coordinator, entry, known_ids)
    if entities:
        async_add_entities(entities)
        _LOGGER.info(f"[Button Setup] 成功创建 {len(entities)} 个响铃按钮")

    if not entities:
        _LOGGER.info("[Button Setup] 数据未就绪，已注册监听器等待设备数据")

        def _on_coordinator_update() -> None:
            new_entities = _create_ring_buttons(sync_coordinator, entry, known_ids)
            if new_entities:
                async_add_entities(new_entities)
                _LOGGER.info(f"[Button Setup] 延迟创建 {len(new_entities)} 个响铃按钮")

        entry.async_on_unload(sync_coordinator.async_add_listener(_on_coordinator_update))


class HuaweiRingButton(CoordinatorEntity, ButtonEntity):

    _attr_has_entity_name = True
    _attr_icon = "mdi:bell-ring"
    _attr_name = "响铃"

    def __init__(
        self,
        coordinator: SyncCoordinator,
        entry: ConfigEntry,
        device_id: str,
        device_name: str,
        model: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._device_id = device_id
        self._device_name = device_name
        self._model = model
        self._last_pressed: float = 0.0

        self._attr_unique_id = f"{DOMAIN}:{device_id}:ring"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            name=self._device_name,
            manufacturer="华为",
            model=self._model or "未知型号",
        )

    @property
    def available(self) -> bool:
        if not self.coordinator.data:
            return False
        code = self.coordinator.data.get("code", -1)
        reason = self.coordinator.data.get("reason", "")
        if code == 990 or reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            return False
        if self.coordinator.data.get("need_reauth"):
            return False
        if time.time() - self._last_pressed < _RING_COOLDOWN_SEC:
            return False
        return True

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        elapsed = time.time() - self._last_pressed
        if elapsed < _RING_COOLDOWN_SEC:
            return {"cooldown_remaining": int(_RING_COOLDOWN_SEC - elapsed)}
        return {}

    async def async_press(self) -> None:
        base_url = self._entry.data[CONF_BASE_URL].rstrip("/")
        session_key = self._entry.data[CONF_SESSION_KEY]
        api_key = (
            self._entry.options.get(CONF_API_KEY, "")
            or self._entry.data.get(CONF_API_KEY, "")
        )

        url = f"{base_url}/ring"
        body: dict[str, Any] = {
            "session_key": session_key,
            "device": self._device_id,
            "action": "start",
        }
        headers: dict[str, str] = {}
        if api_key:
            headers["X-API-Key"] = api_key

        _LOGGER.info(f"[Ring] 触发响铃 device=...{self._device_id[-4:]}")
        try:
            session = aiohttp_client.async_get_clientsession(self.hass)
            async with session.post(
                url, json=body, headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json()
        except Exception as e:
            _LOGGER.error(f"[Ring] 请求后端失败: {e}")
            return

        triggered = data.get("triggered", False)
        cooldown_left = data.get("cooldown_left")
        code = data.get("code", -1)

        if triggered:
            _LOGGER.info(f"[Ring] ✅ 响铃成功 device=...{self._device_id[-4:]}")
            self._last_pressed = time.time()
            self.async_write_ha_state()
        elif cooldown_left is not None:
            _LOGGER.info(f"[Ring] 后端限流，cooldown_left={cooldown_left}s，视为成功")
            self._last_pressed = time.time()
            self.async_write_ha_state()
        else:
            _LOGGER.warning(f"[Ring] ❌ 响铃失败: {data.get('msg')} (code={code})")
            return

        async def _do_locate() -> None:
            try:
                await self.coordinator.async_request_active_locate(force=True)
                _LOGGER.info(f"[Ring] ✅ 定位完成 device=...{self._device_id[-4:]}")
            except Exception as e:
                _LOGGER.warning(f"[Ring] 定位失败（不影响响铃）: {e}")

        self.hass.async_create_task(_do_locate())
