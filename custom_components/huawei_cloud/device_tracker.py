from __future__ import annotations

from datetime import datetime
import logging
import math
import re
from typing import Any

from homeassistant.components.device_tracker import SourceType, TrackerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, CONF_ENABLE_GAODE_MORE_INFO
from .coordinator import SyncCoordinator

_LOGGER = logging.getLogger(__name__)


def wgs84_to_gcj02(lng: float, lat: float) -> tuple[float, float]:
    """WGS84 → GCJ-02"""
    if not (72.004 <= lng <= 137.8347 and 0.8293 <= lat <= 55.8271):
        return lng, lat

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

    dlat = _transform_lat(lng - 105.0, lat - 35.0)
    dlng = _transform_lng(lng - 105.0, lat - 35.0)
    radlat = lat / 180.0 * math.pi
    magic = math.sin(radlat)
    magic = 1 - ee * magic * magic
    sqrtmagic = math.sqrt(magic)
    dlat = (dlat * 180.0) / ((a * (1 - ee)) / (magic * sqrtmagic) * math.pi)
    dlng = (dlng * 180.0) / (a / sqrtmagic * math.cos(radlat) * math.pi)

    gcj_lat = lat + dlat
    gcj_lng = lng + dlng

    return gcj_lng, gcj_lat


def _get_stable_device_id(device: dict[str, Any]) -> str | None:
    device_id = device.get("deviceId") or device.get("device_id")
    if device_id:
        return str(device_id)

    device_sn = device.get("deviceSn")
    if device_sn:
        return str(device_sn)

    uniq_resource = device.get("uniqResource")
    if uniq_resource:
        return str(uniq_resource)

    return None


def generate_slug(model: str, device_id: str = "") -> str:
    if not model or model.strip().lower() in ["unknown", ""]:
        if device_id and len(device_id) >= 6:
            short_id = device_id[:6].lower()
            return f"huawei_{short_id}"
        else:
            raise ValueError("无法生成 slug：model 和 device_id 均为空")

    text = model.lower().strip()
    text = re.sub(r'[^a-z0-9]+', '_', text)
    text = re.sub(r'_+', '_', text)
    text = text.strip('_')

    if not text.startswith("huawei_"):
        text = f"huawei_{text}"

    return text or f"huawei_{device_id[:6].lower()}"


def _create_tracker_entities(
    sync_coordinator: SyncCoordinator,
    entry: ConfigEntry,
    known_ids: set[str],
) -> list[HuaweiTrackerEntity]:
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
        slug = generate_slug(final_name, device_id)
        phone = device.get("phone", "")

        _LOGGER.info(
            f"[Tracker Setup] 创建设备追踪器: device_id={device_id[:20]}..., "
            f"final_name={final_name}, slug={slug}"
        )

        known_ids.add(device_id)
        entities.append(
            HuaweiTrackerEntity(
                sync_coordinator, entry, device_id,
                final_name, model or final_name, phone, slug,
            )
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

    entities = _create_tracker_entities(sync_coordinator, entry, known_ids)
    if entities:
        async_add_entities(entities, update_before_add=True)
        _LOGGER.info(f"[Tracker Setup] 成功创建 {len(entities)} 个设备追踪器")

    if not entities:
        _LOGGER.info("[Tracker Setup] 数据未就绪，已注册监听器等待设备数据")

        def _on_coordinator_update() -> None:
            new_entities = _create_tracker_entities(sync_coordinator, entry, known_ids)
            if new_entities:
                async_add_entities(new_entities, update_before_add=True)
                _LOGGER.info(f"[Tracker Setup] 延迟创建 {len(new_entities)} 个设备追踪器")

        entry.async_on_unload(sync_coordinator.async_add_listener(_on_coordinator_update))


class HuaweiTrackerEntity(CoordinatorEntity, TrackerEntity):

    _attr_has_entity_name = True
    _attr_icon = "mdi:cellphone-marker"

    def __init__(
        self,
        coordinator: SyncCoordinator,
        entry: ConfigEntry,
        device_id: str,
        device_name: str,
        model: str,
        phone: str,
        slug: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._device_id = device_id
        self._device_name = device_name
        self._model = model
        self._phone = phone
        self._slug = slug

        self._attr_unique_id = f"{DOMAIN}:{device_id}"
        self._attr_suggested_object_id = slug
        self._attr_name = None

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

        backend_code = self.coordinator.data.get("code", -1)
        backend_reason = self.coordinator.data.get("reason", "")

        if backend_code == 990 or backend_reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            return False

        if self.coordinator.data.get("need_reauth"):
            return False

        device = self._get_device_data()
        if not device:
            return False
        lat = device.get("latitude")
        lng = device.get("longitude")
        if lat is None or lng is None:
            return False

        return True

    @property
    def source_type(self) -> SourceType:
        return SourceType.GPS

    @property
    def latitude(self) -> float | None:
        device = self._get_device_data()
        if device:
            wgs_lat = device.get("latitude")
            if wgs_lat is not None:
                return float(wgs_lat)
        return None

    @property
    def longitude(self) -> float | None:
        device = self._get_device_data()
        if device:
            wgs_lng = device.get("longitude")
            if wgs_lng is not None:
                return float(wgs_lng)
        return None

    @property
    def location_accuracy(self) -> int:
        device = self._get_device_data()
        if device:
            accuracy = device.get("accuracy")
            if accuracy is not None:
                try:
                    return int(accuracy)
                except (ValueError, TypeError):
                    pass
        return 100

    @property
    def battery_level(self) -> int | None:
        device = self._get_device_data()
        if device:
            battery = device.get("battery")
            if battery is not None:
                try:
                    return int(battery)
                except (ValueError, TypeError):
                    pass
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = {}

        if not self.coordinator.data:
            attrs["status"] = "initializing"
            attrs["message"] = "等待后端初始化"
            return attrs

        backend_code = self.coordinator.data.get("code", -1)
        backend_reason = self.coordinator.data.get("reason", "")

        if backend_code == 990 or backend_reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            attrs["status"] = "initializing"
            attrs["message"] = "后台登录中，请稍候"
            attrs["last_backend_code"] = backend_code
            attrs["last_backend_reason"] = backend_reason
            return attrs

        device = self._get_device_data()
        if device:
            attrs["status"] = "online"
            attrs["device_id"] = self._device_id
            attrs["model"] = self._model

            wgs_lat = device.get("latitude")
            wgs_lng = device.get("longitude")
            if wgs_lat is not None and wgs_lng is not None:
                attrs["wgs84_latitude"] = float(wgs_lat)
                attrs["wgs84_longitude"] = float(wgs_lng)

                gcj_lng, gcj_lat = wgs84_to_gcj02(float(wgs_lng), float(wgs_lat))
                attrs["gcj02_latitude"] = gcj_lat
                attrs["gcj02_longitude"] = gcj_lng
                attrs["coordinate_system"] = "WGS84"
                attrs["coordinate_note"] = "GCJ-02 坐标见 gcj02_* 属性"

            phone = device.get("phone")
            if phone:
                attrs["phone"] = phone

            ts = device.get("ts")
            if ts:
                try:
                    dt = datetime.fromtimestamp(ts)
                    attrs["last_update"] = dt.strftime("%Y年%m月%d日 %H:%M:%S")
                    attrs["location_time"] = int(ts)
                except (ValueError, OSError):
                    attrs["last_update"] = ts

            address = device.get("address")
            if address:
                attrs["address"] = address

            if self._entry.options.get(CONF_ENABLE_GAODE_MORE_INFO, False):
                attrs["custom_ui_more_info"] = "gaode-map"
        else:
            attrs["status"] = "offline"
            attrs["message"] = "设备离线或数据不可用"

        return attrs

    def _get_device_data(self) -> dict[str, Any] | None:
        if not self.coordinator.data:
            return None

        devices = self.coordinator.data.get("devices", [])
        for device in devices:
            device_id = _get_stable_device_id(device)
            if device_id == self._device_id:
                return device

        return None
