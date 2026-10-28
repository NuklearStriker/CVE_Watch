"""Coordinateur : interroge l'API NVD pour chaque application suivie."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from aiohttp import ClientError

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_API_KEY,
    CONF_APPS,
    CONF_DAYS,
    CONF_INTERVAL_HOURS,
    CONF_MIN_SEVERITY,
    DEFAULT_DAYS,
    DEFAULT_INTERVAL_HOURS,
    DEFAULT_MIN_SEVERITY,
    DELAY_NO_KEY,
    DELAY_WITH_KEY,
    DOMAIN,
    MAX_DAYS,
    NVD_URL,
    SEVERITY_RANK,
    SUMMARY_LENGTH,
)

_LOGGER = logging.getLogger(__name__)


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any]:
    """Retourne score, sévérité, version et vecteur (CVSS 4.0 > 3.1 > 3.0 > 2.0)."""
    metrics = cve.get("metrics", {})
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if not entries:
            continue
        # On préfère l'évaluation "Primary" (NVD) si elle existe.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or "NONE"
        return {
            "score": data.get("baseScore"),
            "severity": str(severity).upper(),
            "cvss_version": version,
            "vector": data.get("vectorString"),
        }
    return {"score": None, "severity": "NONE", "cvss_version": None, "vector": None}


def _first_sentence(text: str, limit: int = 110) -> str:
    text = " ".join(text.split())
    cut = text.find(". ")
    title = text[: cut + 1] if 0 < cut <= limit else text
    return title if len(title) <= limit else title[: limit - 1].rstrip() + "…"


def _products(cve: dict[str, Any], limit: int = 5) -> list[str]:
    """Extrait 'éditeur produit' depuis les CPE des configurations."""
    found: dict[str, None] = {}

    def walk(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4 and match.get("vulnerable", True):
                    found.setdefault(f"{parts[3]} {parts[4]}".replace("_", " "), None)
            walk(node.get("nodes", []))

    for conf in cve.get("configurations", []):
        walk(conf.get("nodes", []))
    return list(found)[:limit]


def _parse_cve(raw: dict[str, Any]) -> dict[str, Any]:
    cve = raw.get("cve", {})
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    summary = " ".join(description.split())
    if len(summary) > SUMMARY_LENGTH:
        summary = summary[: SUMMARY_LENGTH - 1] + "…"

    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )
    refs = cve.get("references", [])
    has_exploit = any("Exploit" in r.get("tags", []) for r in refs)
    cve_id = cve.get("id")

    return {
        "id": cve_id,
        # NVD n'a pas de titre : nom CISA KEV si dispo, sinon 1re phrase.
        "title": cve.get("cisaVulnerabilityName") or _first_sentence(description),
        **_extract_cvss(cve),
        "published": (cve.get("published") or "")[:10],
        "modified": (cve.get("lastModified") or "")[:10],
        "status": cve.get("vulnStatus"),
        "cwe": cwes,
        "products": _products(cve),
        "kev": bool(cve.get("cisaExploitAdd")),
        "kev_due_date": cve.get("cisaActionDue"),
        "kev_action": cve.get("cisaRequiredAction"),
        "public_exploit": has_exploit,
        "references": len(refs),
        "summary": summary,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


class CveWatchCoordinator(DataUpdateCoordinator[dict[str, list[dict[str, Any]]]]):
    """Récupère les CVE récentes pour chaque application."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        opts = {**entry.data, **entry.options}
        self.apps: list[str] = list(opts.get(CONF_APPS, []))
        self.days: int = min(int(opts.get(CONF_DAYS, DEFAULT_DAYS)), MAX_DAYS)
        self.min_severity: str = opts.get(CONF_MIN_SEVERITY, DEFAULT_MIN_SEVERITY)
        self.api_key: str | None = opts.get(CONF_API_KEY) or None
        interval = int(opts.get(CONF_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS))
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(hours=interval),
        )

    async def _fetch_app(self, app: str, start: str, end: str) -> list[dict[str, Any]]:
        session = async_get_clientsession(self.hass)
        headers = {"apiKey": self.api_key} if self.api_key else {}
        results: list[dict[str, Any]] = []
        start_index = 0
        delay = DELAY_WITH_KEY if self.api_key else DELAY_NO_KEY

        while True:
            params = {
                "keywordSearch": app,
                "pubStartDate": start,
                "pubEndDate": end,
                "resultsPerPage": 200,
                "startIndex": start_index,
            }
            async with asyncio.timeout(60):
                async with session.get(NVD_URL, params=params, headers=headers) as resp:
                    if resp.status in (403, 429):
                        raise UpdateFailed(
                            "Quota NVD dépassé (HTTP %s). Ajoutez une clé API "
                            "ou allongez l'intervalle." % resp.status
                        )
                    resp.raise_for_status()
                    payload = await resp.json()

            vulns = payload.get("vulnerabilities", [])
            results.extend(_parse_cve(v) for v in vulns)
            start_index += len(vulns)
            if not vulns or start_index >= payload.get("totalResults", 0):
                break
            await asyncio.sleep(delay)
        return results

    async def _async_update_data(self) -> dict[str, list[dict[str, Any]]]:
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=self.days)).strftime("%Y-%m-%dT%H:%M:%S.000")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
        min_rank = SEVERITY_RANK.get(self.min_severity, 0)
        delay = DELAY_WITH_KEY if self.api_key else DELAY_NO_KEY

        data: dict[str, list[dict[str, Any]]] = {}
        for index, app in enumerate(self.apps):
            if index:
                await asyncio.sleep(delay)
            try:
                cves = await self._fetch_app(app, start, end)
            except UpdateFailed:
                raise
            except (ClientError, TimeoutError) as err:
                raise UpdateFailed(f"Erreur réseau NVD pour « {app} » : {err}") from err

            cves = [c for c in cves if SEVERITY_RANK.get(c["severity"], 0) >= min_rank]
            cves.sort(
                key=lambda c: (c["kev"], c["score"] or 0, c["published"] or ""),
                reverse=True,
            )
            data[app] = cves
        return data
