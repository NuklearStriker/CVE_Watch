"""Capteurs CVE Watch : un par application + un capteur total."""
from __future__ import annotations

import re
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MAX_CVES_IN_ATTRIBUTES, SEVERITY_RANK
from .coordinator import CveWatchCoordinator


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "app"


def _worst(cves: list[dict[str, Any]]) -> str:
    if not cves:
        return "NONE"
    return max((c["severity"] for c in cves), key=lambda s: SEVERITY_RANK.get(s, 0))


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: CveWatchCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SensorEntity] = [CveTotalSensor(coordinator, entry)]
    entities += [CveAppSensor(coordinator, entry, app) for app in coordinator.apps]
    async_add_entities(entities)


class _Base(CoordinatorEntity[CveWatchCoordinator], SensorEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:shield-bug"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "CVE"

    def __init__(self, coordinator: CveWatchCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="CVE Watch",
            manufacturer="NVD (NIST)",
            entry_type=DeviceEntryType.SERVICE,
        )


class CveAppSensor(_Base):
    """Nombre de CVE récentes pour une application."""

    _unrecorded_attributes = frozenset({"cves"})

    def __init__(self, coordinator, entry, app: str) -> None:
        super().__init__(coordinator, entry)
        self._app = app
        self._attr_name = app
        self._attr_unique_id = f"{entry.entry_id}_{_slug(app)}"

    @property
    def _cves(self) -> list[dict[str, Any]]:
        return (self.coordinator.data or {}).get(self._app, [])

    @property
    def native_value(self) -> int:
        return len(self._cves)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        cves = self._cves
        scores = [c["score"] for c in cves if c["score"] is not None]
        return {
            "application": self._app,
            "period_days": self.coordinator.days,
            "max_score": max(scores) if scores else None,
            "max_severity": _worst(cves),
            "critical": sum(c["severity"] == "CRITICAL" for c in cves),
            "high": sum(c["severity"] == "HIGH" for c in cves),
            "kev": sum(c["kev"] for c in cves),
            "cves": cves[:MAX_CVES_IN_ATTRIBUTES],
        }


class CveTotalSensor(_Base):
    """Total toutes applications confondues."""

    _unrecorded_attributes = frozenset({"cves"})
    _attr_name = "Total"

    def __init__(self, coordinator, entry) -> None:
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_total"

    @property
    def native_value(self) -> int:
        return sum(len(v) for v in (self.coordinator.data or {}).values())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data or {}
        merged = [
            {**c, "application": app} for app, cves in data.items() for c in cves
        ]
        merged.sort(
            key=lambda c: (c["kev"], c["score"] or 0, c["published"] or ""),
            reverse=True,
        )
        return {
            "period_days": self.coordinator.days,
            "per_application": {app: len(cves) for app, cves in data.items()},
            "max_severity": _worst(merged),
            "kev": sum(c["kev"] for c in merged),
            "cves": merged[:MAX_CVES_IN_ATTRIBUTES],
        }
