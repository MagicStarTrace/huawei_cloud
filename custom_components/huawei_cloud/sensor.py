from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, ICON_BATTERY, CONF_ENABLE_GAODE_MORE_INFO, CONF_AMAP_API_KEY
from .coordinator import SyncCoordinator
from .device_tracker import _get_stable_device_id, generate_slug

_LOGGER = logging.getLogger(__name__)


def _create_sensor_entities(
    sync_coordinator: SyncCoordinator,
    entry: ConfigEntry,
    known_ids: set[str],
) -> list[HuaweiAddressSensor | HuaweiBatterySensor]:
    if not sync_coordinator.data:
        return []

    reason = sync_coordinator.data.get("reason", "")
    code = sync_coordinator.data.get("code", 0)
    if reason in ["NO_SESSION", "LOGIN_IN_PROGRESS"] or code == 990:
        return []

    devices = sync_coordinator.data.get("devices", [])
    entities: list[HuaweiAddressSensor | HuaweiBatterySensor] = []

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
            f"[Sensor Setup] 创建传感器实体: device_id={device_id[:20]}..., "
            f"final_name={final_name}, slug={slug}"
        )

        known_ids.add(device_id)
        entities.extend([
            HuaweiAddressSensor(
                sync_coordinator, entry, device_id,
                final_name, model or final_name, phone, slug,
            ),
            HuaweiBatterySensor(
                sync_coordinator, entry, device_id,
                final_name, model or final_name, phone, slug,
            ),
        ])

    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinators = hass.data[DOMAIN][entry.entry_id]
    sync_coordinator: SyncCoordinator = coordinators["sync_coordinator"]
    known_ids: set[str] = set()

    async_add_entities([HuaweiStatusSensor(sync_coordinator, entry)])

    entities = _create_sensor_entities(sync_coordinator, entry, known_ids)
    if entities:
        async_add_entities(entities, update_before_add=True)
        _LOGGER.info(f"[Sensor Setup] 成功创建 {len(entities)} 个传感器实体")

    if not entities:
        _LOGGER.info("[Sensor Setup] 数据未就绪，已注册监听器等待设备数据")

        def _on_coordinator_update() -> None:
            new_entities = _create_sensor_entities(sync_coordinator, entry, known_ids)
            if new_entities:
                async_add_entities(new_entities, update_before_add=True)
                _LOGGER.info(f"[Sensor Setup] 延迟创建 {len(new_entities)} 个传感器实体")

        entry.async_on_unload(sync_coordinator.async_add_listener(_on_coordinator_update))


class HuaweiAddressSensor(CoordinatorEntity, SensorEntity):

    _attr_has_entity_name = True
    _attr_icon = "mdi:map-marker"

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

        self._attr_unique_id = f"{DOMAIN}:{device_id}:address"
        self._attr_suggested_object_id = f"{slug}_address"
        self._attr_name = "地址"

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

        return True

    @property
    def native_value(self) -> str | None:
        if not self.coordinator.data:
            return None

        backend_code = self.coordinator.data.get("code", -1)
        backend_reason = self.coordinator.data.get("reason", "")

        if backend_code == 990 or backend_reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            return "初始化中"

        device = self._get_device_data()
        if not device:
            return "设备离线"

        address = device.get("address")
        if address and address.strip():
            return address

        amap_key = self._entry.options.get(CONF_AMAP_API_KEY, "") or self._entry.data.get(CONF_AMAP_API_KEY, "")
        if not amap_key:
            return "未配置地图服务"

        lat = device.get("latitude")
        lng = device.get("longitude")
        if lat is None or lng is None:
            return "坐标不可用"

        return "等待地址解析"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = {}

        if not self.coordinator.data:
            attrs["status"] = "initializing"
            return attrs

        backend_code = self.coordinator.data.get("code", -1)
        backend_reason = self.coordinator.data.get("reason", "")

        if backend_code == 990 or backend_reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            attrs["status"] = "initializing"
            attrs["message"] = "后台登录中"
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

                from .device_tracker import wgs84_to_gcj02
                gcj_lng, gcj_lat = wgs84_to_gcj02(float(wgs_lng), float(wgs_lat))
                attrs["latitude"] = gcj_lat
                attrs["longitude"] = gcj_lng
                attrs["gcj02_latitude"] = gcj_lat
                attrs["gcj02_longitude"] = gcj_lng

            ts = device.get("ts")
            if ts:
                try:
                    attrs["location_time"] = int(ts)
                except (ValueError, TypeError):
                    pass

            address_time = device.get("address_time")
            if address_time:
                try:
                    attrs["address_time"] = int(address_time)
                except (ValueError, TypeError):
                    pass

            has_address = bool(device.get("address"))
            attrs["geocoding_enabled"] = has_address
            attrs["geocoding_source"] = "ha_side" if has_address else "none"

            amap_key = self._entry.options.get(CONF_AMAP_API_KEY, "") or self._entry.data.get(CONF_AMAP_API_KEY, "")
            if not amap_key:
                attrs["geocoding_note"] = "未配置高德API密钥，跳过地址解析"
        else:
            attrs["status"] = "offline"

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


class HuaweiBatterySensor(CoordinatorEntity, SensorEntity):

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_icon = ICON_BATTERY

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

        self._attr_unique_id = f"{DOMAIN}:{device_id}:battery"
        self._attr_suggested_object_id = f"{slug}_battery"
        self._attr_name = "电量"

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

        return True

    @property
    def native_value(self) -> int | None:
        if not self.coordinator.data:
            return None

        backend_code = self.coordinator.data.get("code", -1)
        backend_reason = self.coordinator.data.get("reason", "")

        if backend_code == 990 or backend_reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            return None

        device = self._get_device_data()
        if not device:
            return None

        battery = device.get("battery")
        if battery is not None:
            try:
                return int(battery)
            except (ValueError, TypeError):
                return None

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs = {}

        if not self.coordinator.data:
            attrs["status"] = "initializing"
            return attrs

        backend_code = self.coordinator.data.get("code", -1)
        backend_reason = self.coordinator.data.get("reason", "")

        if backend_code == 990 or backend_reason in ["LOGIN_IN_PROGRESS", "NO_SESSION"]:
            attrs["status"] = "initializing"
            attrs["message"] = "后台登录中"
            attrs["last_backend_code"] = backend_code
            attrs["last_backend_reason"] = backend_reason
            return attrs

        device = self._get_device_data()

        if device:
            attrs["status"] = "online"
            attrs["device_id"] = self._device_id
            attrs["model"] = self._model

            battery = device.get("battery")
            if battery is not None:
                try:
                    battery_int = int(battery)
                    attrs["is_low_battery"] = battery_int < 20
                except (ValueError, TypeError):
                    pass
        else:
            attrs["status"] = "offline"

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


class HuaweiStatusSensor(CoordinatorEntity, SensorEntity):

    _attr_has_entity_name = True
    _attr_icon = "mdi:cloud-sync"

    def __init__(
        self,
        coordinator: SyncCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{DOMAIN}:{entry.entry_id}:status"
        self._attr_suggested_object_id = "huawei_cloud_status"
        self._attr_name = "服务状态"

    @property
    def available(self) -> bool:
        return True

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name="华为云服务",
            manufacturer="华为",
            model="Cloud Service",
        )

    @property
    def native_value(self) -> str:
        if not self.coordinator.data:
            return "初始化中"

        code = self.coordinator.data.get("code", -1)
        reason = self.coordinator.data.get("reason", "")

        if reason == "NO_SESSION":
            return "等待登录"
        if reason == "LOGIN_IN_PROGRESS":
            return "登录中"
        if code == 990:
            return "需要认证"
        if self.coordinator.data.get("need_reauth"):
            return "认证过期"

        devices = self.coordinator.data.get("devices", [])
        if code == 0 and devices:
            return f"正常（{len(devices)}台设备）"
        if code == 0:
            return "正常"

        return f"异常（code={code}）"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if not self.coordinator.data:
            return {"hint": "后台正在登录华为账号，请耐心等待30-60秒"}

        code = self.coordinator.data.get("code", -1)
        reason = self.coordinator.data.get("reason", "")
        devices = self.coordinator.data.get("devices", [])

        attrs: dict[str, Any] = {
            "code": code,
            "device_count": len(devices),
        }

        if reason:
            attrs["reason"] = reason

        if reason in ["NO_SESSION", "LOGIN_IN_PROGRESS"] or code == 990:
            attrs["hint"] = "后台正在登录华为账号，请耐心等待30-60秒"

        return attrs
