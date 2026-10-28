# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versionnage [SemVer](https://semver.org/lang/fr/).

## [0.2.0] - 2026-10-28

### Ajouté
- Titre de chaque CVE : nom CISA KEV si connu, sinon première phrase de la description (NVD ne fournit pas de titre).
- Nouveaux champs par CVE : version et vecteur CVSS, date de dernière modification, statut NVD, types de faiblesse (CWE), produits concernés (d'après les CPE), échéance et action requise CISA KEV, présence d'un exploit public, nombre de références.
- Attribut `public_exploit` (compteur) sur les capteurs par application.
- Tableau Lovelace (Markdown) et tableau des champs disponibles dans le README.

### Modifié
- Les capteurs par application conservent désormais les 25 CVE les plus importantes (au lieu de 10).
- Résumé allongé à 300 caractères (au lieu de 180).
- Dates de publication et de modification au format `AAAA-MM-JJ`.
- `score` et `severity` sont maintenant des champs séparés de `cvss_version` et `vector` (extraction CVSS 4.0 > 3.1 > 3.0 > 2.0, évaluation « Primary » préférée).

## [0.1.0] - 2026-10-28

### Ajouté
- Première version de l'intégration Home Assistant **CVE Watch** (`custom_components/cve_watch`).
- Interrogation de l'API NVD (NIST) par mot-clé pour chaque application d'une liste saisie dans l'interface.
- Configuration via l'UI (config flow) et options modifiables : applications, période (1 à 120 jours), sévérité minimale, intervalle de mise à jour (6 h par défaut), clé API NVD optionnelle.
- Un capteur par application (nombre de CVE, score maximal, compteurs critiques/élevées/KEV, liste des CVE) et un capteur « Total ».
- Tri des CVE : catalogue CISA KEV d'abord, puis score CVSS décroissant.
- Respect des quotas NVD (délai entre requêtes avec ou sans clé API) et gestion des erreurs HTTP 403/429.
- Traductions française et anglaise, compatibilité HACS (`hacs.json`).
- README avec exemples d'automatisation et de carte Lovelace.

### Limites connues
- Recherche par mot-clé : un terme générique remonte du bruit, un produit au nom différent peut échapper.
- Filtre sur la date de publication : une CVE ancienne mise à jour récemment n'apparaît pas.
