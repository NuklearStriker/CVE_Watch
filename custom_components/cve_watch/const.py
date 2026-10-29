"""Constantes de l'intégration CVE Watch."""
from __future__ import annotations

DOMAIN = "cve_watch"

CONF_APPS = "apps"
CONF_DAYS = "days"
CONF_MIN_SEVERITY = "min_severity"
CONF_API_KEY = "api_key"
CONF_INTERVAL_HOURS = "interval_hours"

DEFAULT_DAYS = 30
DEFAULT_MIN_SEVERITY = "ALL"
DEFAULT_INTERVAL_HOURS = 6

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Quotas NVD : 5 requêtes / 30 s sans clé, 50 requêtes / 30 s avec clé.
DELAY_NO_KEY = 6.5
DELAY_WITH_KEY = 0.7

# La fenêtre de dates de l'API NVD est limitée à 120 jours.
MAX_DAYS = 120

SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_OPTIONS = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Nombre de CVE gardées par ordre de tri (score, puis date) dans l'attribut `cves`.
# L'attribut contient l'union des deux listes : 50 CVE au maximum.
MAX_CVES_IN_ATTRIBUTES = 25
SUMMARY_LENGTH = 300
