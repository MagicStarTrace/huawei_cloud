from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "huawei_cloud"

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_BASE_URL = "service_base_url"
CONF_SESSION_KEY = "session_key"
CONF_AMAP_API_KEY = "amap_api_key"

CONF_INTERVAL = "interval"
CONF_LOW_BATT_INTERVAL = "low_battery_interval"
CONF_LOW_BATT_THRESHOLD = "low_battery_threshold"
CONF_ENABLE_LOW_BATT_UPDATE = "enable_low_battery_update"
CONF_DEVICE_FILTER = "device_filter"
CONF_USE_PAGE_LOCATION = "use_page_location"
CONF_ENABLE_GAODE_MORE_INFO = "enable_gaode_more_info"

DEFAULT_INTERVAL = 180
DEFAULT_LOW_BATT_INTERVAL = 300
DEFAULT_LOW_BATT_THRESHOLD = 30
DEFAULT_USE_PAGE_LOCATION = True

PLATFORMS = [
    Platform.DEVICE_TRACKER,
    Platform.SENSOR,
]

API_STATUS = "/status"
API_LOGIN = "/login"
API_SYNC = "/sync"

ATTR_ACCURACY = "accuracy"
ATTR_BATTERY = "battery"
ATTR_ADDRESS = "address"
ATTR_GCJ02_LAT = "gcj02_lat"
ATTR_GCJ02_LNG = "gcj02_lng"
ATTR_RAW = "raw"
ATTR_DEVICE_NAME = "device_name"
ATTR_LAST_UPDATE = "last_update"

DEVICE_CLASS_BATTERY = "battery"
DEVICE_CLASS_TIMESTAMP = "timestamp"

ICON_DEVICE_TRACKER = "mdi:cellphone"
ICON_BATTERY = "mdi:battery"
ICON_SYNC = "mdi:sync"
ICON_LOGIN = "mdi:login"
ICON_CLOCK = "mdi:clock"
ICON_COUNTER = "mdi:counter"
