"""Intégration CVE Watch pour Home Assistant."""
from __future__ import annotations

from pathlib import Path

from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import CveWatchCoordinator

PLATFORMS = ["sensor"]

CARD_URL = f"/{DOMAIN}/cve-watch-card.js"
CARD_VERSION = "1.1.0"
_FRONTEND_FLAG = f"{DOMAIN}_frontend"


async def _async_register_card(hass: HomeAssistant) -> None:
    """Sert la carte Lovelace et la charge automatiquement (une seule fois)."""
    if hass.data.get(_FRONTEND_FLAG):
        return
    card = Path(__file__).parent / "www" / "cve-watch-card.js"
    await hass.http.async_register_static_paths(
        [StaticPathConfig(CARD_URL, str(card), cache_headers=False)]
    )
    add_extra_js_url(hass, f"{CARD_URL}?v={CARD_VERSION}")
    hass.data[_FRONTEND_FLAG] = True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    await _async_register_card(hass)

    coordinator = CveWatchCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


async def _async_reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unloaded
