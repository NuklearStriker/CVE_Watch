# CVE Watch pour Home Assistant

Surveille les CVE récentes (base NVD du NIST) pour une liste d'applications que vous choisissez.

## Installation

**Manuelle** : copiez le dossier `custom_components/cve_watch` dans le dossier `config/custom_components/` de Home Assistant, redémarrez, puis *Paramètres → Appareils et services → Ajouter une intégration → CVE Watch*.

**HACS** : poussez ce dépôt sur GitHub, puis ajoutez-le comme dépôt personnalisé (catégorie *Intégration*).

## Configuration

- **Applications** : une par ligne (ex. `stormshield`, `proxmox`, `prtg`, `wsus`).
- **Période** : nombre de jours à remonter (1 à 120, limite de l'API NVD).
- **Sévérité minimale** : filtre CVSS (toutes, faible+, moyenne+, élevée+, critique).
- **Intervalle** : fréquence d'interrogation (6 h par défaut).
- **Clé API NVD** (optionnelle) : gratuite sur https://nvd.nist.gov/developers/request-an-api-key. Sans clé, l'intégration espace ses requêtes (≈ 6,5 s entre deux applications) pour respecter le quota ; avec clé, c'est quasi instantané.

Tout se modifie ensuite via *Configurer* sur l'intégration.

## Entités

- `sensor.cve_watch_<application>` : nombre de CVE sur la période.
  Attributs : `max_score`, `max_severity`, `critical`, `high`, `kev`, `cves` (les 10 premières : id, score, sévérité, date, résumé, lien NVD).
- `sensor.cve_watch_total` : total tous produits confondus, avec `per_application`.

Les CVE sont triées : présentes dans le catalogue CISA KEV d'abord, puis par score CVSS décroissant.

## Limites à connaître

- La recherche NVD se fait par **mot-clé** : `proxmox` est précis, un terme générique (`windows`, `ssl`) remontera beaucoup de bruit, et un produit dont le nom diffère de celui de la CVE pourrait manquer. Utilisez des noms de produit assez spécifiques.
- La date utilisée est la date de **publication** de la CVE : une CVE ancienne mise à jour récemment n'apparaît pas.
- Les attributs `cves` ne sont pas conservés dans l'historique (recorder) pour éviter de gonfler la base.

## Exemple de notification (automatisation)

```yaml
alias: Alerte CVE critique
trigger:
  - platform: numeric_state
    entity_id: sensor.cve_watch_stormshield
    attribute: critical
    above: 0
action:
  - service: notify.notify
    data:
      title: "CVE critique : Stormshield"
      message: >
        {% set c = state_attr('sensor.cve_watch_stormshield', 'cves')[0] %}
        {{ c.id }} (CVSS {{ c.score }}) – {{ c.summary }}
```

## Champs disponibles pour chaque CVE (attribut `cves`)

| Champ | Contenu |
|---|---|
| `id`, `url` | Identifiant CVE et lien NVD |
| `title` | Nom CISA KEV si connu, sinon première phrase de la description (NVD ne fournit pas de titre) |
| `score`, `severity` | Score CVSS de base et sévérité |
| `cvss_version`, `vector` | Version (4.0 / 3.1 / 3.0 / 2.0) et vecteur d'attaque |
| `published`, `modified` | Dates de publication et de dernière modification |
| `status` | Statut NVD (Analyzed, Awaiting Analysis…) |
| `cwe` | Types de faiblesse (CWE-xxx) |
| `products` | Éditeur / produit concernés (d'après les CPE, 5 max) |
| `kev`, `kev_due_date`, `kev_action` | Présence au catalogue CISA KEV, échéance et action requise |
| `public_exploit` | Une référence « Exploit » existe |
| `references` | Nombre de références |
| `summary` | Description (300 caractères) |

## Exemple de carte Lovelace : tableau (Markdown)

```yaml
type: markdown
title: CVE – Stormshield
content: >
  {% set cves = state_attr('sensor.cve_watch_stormshield', 'cves') or [] %}
  | CVE | Score | Titre | Produits | Publiée | Infos |
  |---|---|---|---|---|---|
  {% for c in cves -%}
  | [{{ c.id }}]({{ c.url }}) | **{{ c.score }}** {{ c.severity }} | {{ c.title }} | {{ c.products | join(', ') }} | {{ c.published }} | {{ '🔥KEV ' if c.kev }}{{ '💣exploit ' if c.public_exploit }}{{ c.cwe | join(' ') }} |
  {% endfor %}
```

Pour tout voir d'un coup (toutes applications), utilisez `sensor.cve_watch_total` avec le champ `application` en plus.

Pour une vue brute, *Outils de développement → États* affiche tous les attributs.
