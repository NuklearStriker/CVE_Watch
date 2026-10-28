"""Config flow et options de CVE Watch."""
from __future__ import annotations

import re
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    CONF_API_KEY,
    CONF_APPS,
    CONF_DAYS,
    CONF_INTERVAL_HOURS,
    CONF_MIN_SEVERITY,
    DEFAULT_DAYS,
    DEFAULT_INTERVAL_HOURS,
    DEFAULT_MIN_SEVERITY,
    DOMAIN,
    MAX_DAYS,
    SEVERITY_OPTIONS,
)


def _parse_apps(raw: str) -> list[str]:
    """Une application par ligne (ou séparées par des virgules / points-virgules)."""
    seen: dict[str, None] = {}
    for item in re.split(r"[\n,;]+", raw or ""):
        name = item.strip()
        if name:
            seen.setdefault(name, None)
    return list(seen)


def _schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_APPS, default=defaults.get(CONF_APPS, "")): TextSelector(
                TextSelectorConfig(multiline=True)
            ),
            vol.Required(
                CONF_DAYS, default=defaults.get(CONF_DAYS, DEFAULT_DAYS)
            ): NumberSelector(
                NumberSelectorConfig(
                    min=1, max=MAX_DAYS, step=1, mode=NumberSelectorMode.BOX
                )
            ),
            vol.Required(
                CONF_MIN_SEVERITY,
                default=defaults.get(CONF_MIN_SEVERITY, DEFAULT_MIN_SEVERITY),
            ): SelectSelector(
                SelectSelectorConfig(
                    options=SEVERITY_OPTIONS,
                    mode=SelectSelectorMode.DROPDOWN,
                    translation_key="severity",
                )
            ),
            vol.Required(
                CONF_INTERVAL_HOURS,
                default=defaults.get(CONF_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS),
            ): NumberSelector(
                NumberSelectorConfig(
                    min=1, max=72, step=1, mode=NumberSelectorMode.BOX
                )
            ),
            vol.Optional(
                CONF_API_KEY, default=defaults.get(CONF_API_KEY, "")
            ): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
        }
    )


def _normalize(user_input: dict[str, Any]) -> dict[str, Any]:
    return {
        CONF_APPS: _parse_apps(user_input[CONF_APPS]),
        CONF_DAYS: int(user_input[CONF_DAYS]),
        CONF_MIN_SEVERITY: user_input[CONF_MIN_SEVERITY],
        CONF_INTERVAL_HOURS: int(user_input[CONF_INTERVAL_HOURS]),
        CONF_API_KEY: (user_input.get(CONF_API_KEY) or "").strip(),
    }


class CveWatchConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input is not None:
            data = _normalize(user_input)
            if not data[CONF_APPS]:
                errors[CONF_APPS] = "no_apps"
            else:
                return self.async_create_entry(title="CVE Watch", data=data)
        return self.async_show_form(
            step_id="user", data_schema=_schema(user_input or {}), errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return CveWatchOptionsFlow()


class CveWatchOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        current = {**self.config_entry.data, **self.config_entry.options}
        if user_input is not None:
            data = _normalize(user_input)
            if not data[CONF_APPS]:
                errors[CONF_APPS] = "no_apps"
            else:
                return self.async_create_entry(title="", data=data)
            current = {**current, **user_input}
        else:
            current = {**current, CONF_APPS: "\n".join(current.get(CONF_APPS, []))}
        return self.async_show_form(
            step_id="init", data_schema=_schema(current), errors=errors
        )
