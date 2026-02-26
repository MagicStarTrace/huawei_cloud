from __future__ import annotations

import logging
import uuid
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_AMAP_API_KEY,
    CONF_API_KEY,
    CONF_BASE_URL,
    CONF_ENABLE_GAODE_MORE_INFO,
    CONF_ENABLE_LOW_BATT_UPDATE,
    CONF_INTERVAL,
    CONF_LOW_BATT_INTERVAL,
    CONF_LOW_BATT_THRESHOLD,
    CONF_SESSION_KEY,
    CONF_USE_PAGE_LOCATION,
    DEFAULT_INTERVAL,
    DEFAULT_LOW_BATT_INTERVAL,
    DEFAULT_LOW_BATT_THRESHOLD,
    DEFAULT_USE_PAGE_LOCATION,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _mask_username(username: str) -> str:
    if not username or len(username) <= 3:
        return "***"
    return username[:3] + "*" * (len(username) - 3)


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_BASE_URL): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_AMAP_API_KEY, default=""): str,
        vol.Optional(CONF_ENABLE_GAODE_MORE_INFO, default=False): bool,
    }
)

STEP_OPTIONS_DATA_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_INTERVAL, default=DEFAULT_INTERVAL // 60): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=60)
        ),
        vol.Optional(CONF_LOW_BATT_THRESHOLD, default=DEFAULT_LOW_BATT_THRESHOLD): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=100)
        ),
        vol.Optional(CONF_AMAP_API_KEY, default=""): str,
        vol.Optional(CONF_ENABLE_GAODE_MORE_INFO, default=False): bool,
    }
)


class HuaweiCloudConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            base_url = user_input.get(CONF_BASE_URL, "").strip().rstrip("/")
            username = user_input.get(CONF_USERNAME, "").strip()
            password = user_input.get(CONF_PASSWORD, "").strip()

            if not base_url:
                errors["base"] = "base_url_required"
            elif not base_url.startswith(("http://", "https://")):
                errors["base"] = "invalid_url"
            elif not username:
                errors["base"] = "username_required"
            elif not password:
                errors["base"] = "password_required"

            if errors:
                return self.async_show_form(
                    step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors,
                )

            unique_id = f"{base_url}|{username}"
            await self.async_set_unique_id(unique_id)
            self._abort_if_unique_id_configured()

            progress_task = self.async_show_progress(
                step_id="user", progress_action="connecting",
            )

            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(
                            f"{base_url}/status",
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as resp:
                            if resp.status not in (200, 401, 403):
                                _LOGGER.warning(f"后端返回 {resp.status}")
                    except Exception as e:
                        _LOGGER.warning(f"连接测试失败: {e}")

                session_key = str(uuid.uuid4())

                data = {
                    CONF_BASE_URL: base_url,
                    CONF_SESSION_KEY: session_key,
                }

                options = {
                    CONF_USERNAME: username,
                    CONF_PASSWORD: password,
                    CONF_INTERVAL: DEFAULT_INTERVAL,
                    CONF_LOW_BATT_THRESHOLD: DEFAULT_LOW_BATT_THRESHOLD,
                    CONF_ENABLE_LOW_BATT_UPDATE: True,
                    CONF_LOW_BATT_INTERVAL: DEFAULT_LOW_BATT_INTERVAL,
                    CONF_USE_PAGE_LOCATION: DEFAULT_USE_PAGE_LOCATION,
                    CONF_AMAP_API_KEY: user_input.get(CONF_AMAP_API_KEY, ""),
                    CONF_ENABLE_GAODE_MORE_INFO: user_input.get(CONF_ENABLE_GAODE_MORE_INFO, False),
                }

                self.async_show_progress_done(next_step_id="user")

                return self.async_create_entry(
                    title=f"华为云服务 ({_mask_username(username)})",
                    data=data,
                    options=options,
                )
            except Exception as e:
                self.async_show_progress_done(next_step_id="user")
                _LOGGER.exception(f"配置失败: {e}")
                errors["base"] = "cannot_connect"
                return self.async_show_form(
                    step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors,
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors,
        )

    @staticmethod
    @config_entries.callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> OptionsFlowHandler:
        return OptionsFlowHandler()


class OptionsFlowHandler(config_entries.OptionsFlow):
    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            updated_options = dict(self.config_entry.options)
            updated_options.update(user_input)

            updated_options[CONF_INTERVAL] = user_input.get(CONF_INTERVAL, DEFAULT_INTERVAL // 60) * 60
            updated_options[CONF_LOW_BATT_INTERVAL] = user_input.get(CONF_LOW_BATT_INTERVAL, DEFAULT_LOW_BATT_INTERVAL // 60) * 60

            return self.async_create_entry(title="", data=updated_options)

        options = self.config_entry.options or {}

        current_interval_min = options.get(CONF_INTERVAL, DEFAULT_INTERVAL) // 60
        current_low_batt_min = options.get(CONF_LOW_BATT_INTERVAL, DEFAULT_LOW_BATT_INTERVAL) // 60

        schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME, default=options.get(CONF_USERNAME, "")): str,
                vol.Required(CONF_PASSWORD, default=options.get(CONF_PASSWORD, "")): str,
                vol.Optional(CONF_INTERVAL, default=current_interval_min): vol.All(
                    vol.Coerce(int), vol.Range(min=1, max=60)
                ),
                vol.Optional(
                    CONF_LOW_BATT_THRESHOLD,
                    default=options.get(CONF_LOW_BATT_THRESHOLD, DEFAULT_LOW_BATT_THRESHOLD)
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=100)),
                vol.Optional(
                    CONF_ENABLE_LOW_BATT_UPDATE,
                    default=options.get(CONF_ENABLE_LOW_BATT_UPDATE, True)
                ): bool,
                vol.Optional(CONF_LOW_BATT_INTERVAL, default=current_low_batt_min): vol.All(
                    vol.Coerce(int), vol.Range(min=1, max=60)
                ),
                vol.Optional(
                    CONF_USE_PAGE_LOCATION,
                    default=options.get(CONF_USE_PAGE_LOCATION, DEFAULT_USE_PAGE_LOCATION)
                ): bool,
                vol.Optional(CONF_AMAP_API_KEY, default=options.get(CONF_AMAP_API_KEY, "")): str,
                vol.Optional(
                    CONF_ENABLE_GAODE_MORE_INFO,
                    default=options.get(CONF_ENABLE_GAODE_MORE_INFO, False)
                ): bool,
                vol.Optional(CONF_API_KEY, default=options.get(CONF_API_KEY, "")): str,
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)
