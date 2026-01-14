# VIGILANCE X - Changelog

Toutes les modifications notables du projet sont documentees dans ce fichier.

Le format est base sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhere au [Semantic Versioning](https://semver.org/spec/v2.0.0.html) modifie (X.YY.Z).

---

## [3.53.105] - 2026-01-14

### Fixed
- **Attack Map Date Picker**: Le backend supporte maintenant les parametres `start_time` et `end_time` pour filtrer les attaques par date specifique
- **Disconnect Button**: Le bouton "Disconnect" dans Settings > Integrations s'affiche maintenant correctement pour les APIs configurees
- **Attack History Modal**: La section "Attack History" s'affiche maintenant independamment du threat score dans le modal IP

### Changed
- Restructuration du rendu conditionnel dans IPThreatModal pour separer les sections independantes
- `handleEditPlugin` charge les configs avant d'ouvrir le modal (evite race condition)

### Technical
- Nouvelle methode `GetGeoHeatmapFilteredRange(ctx, startTime, endTime, attackTypes)` dans events service
- Nouvelle query repository avec `WHERE timestamp >= ? AND timestamp <= ?`

---

## [3.53.104] - 2026-01-13

### Added
- Bug fix pour input cursor jump dans Settings (notifications & retention)

---

## [3.53.103] - 2026-01-13

### Added
- **Neural-Sync XGS Integration**: Synchronisation automatique vers Sophos XGS Firewall
  - Groupe XGS `grp_VGX-CrowdSBlockL` cree automatiquement si absent
  - Sync des IPs blocklist vers le groupe XGS apres chaque telechargement CrowdSec
  - Prefix host: `CS_x.x.x.x` pour identifier les IPs CrowdSec
- Nouvelle interface `XGSClient` pour decouplage Sophos client

---

## [3.53.102] - 2026-01-13

### Added
- **Neural-Sync UI Complete**: Interface utilisateur finalisee pour CrowdSec Blocklist
  - Boutons clairement labelises: "Sync Blocklists" (mauve), "Refresh" (gris)
  - Carte verte "Country Enrichment Required" avec bouton "Start Country Enrichment"
  - Filtre pays avec drapeaux + noms complets (50+ pays mappes)
  - Auto-enrichment en background avec progression et bouton Stop

### Changed
- Country Name Mapping: Dictionnaire COUNTRY_NAMES avec 50+ pays

---

## [3.53.101] - 2026-01-13

### Added
- **abuse.ch Auth-Key Support**: ThreatFox et URLhaus necessitent maintenant un Auth-Key
- Variable `ABUSECH_API_KEY` pour authentification abuse.ch APIs

### Fixed
- API Tracking Callback Wiring: Connection aggregator → apiUsageService

---

## [3.53.100] - 2026-01-13

### Added
- **API Usage Tracking System**: Tracking quotas et compteurs par provider TI
- Nouveau systeme de gestion des cles API via Settings UI
- Tables ClickHouse: `api_provider_config`, `api_usage_daily`, `api_request_log`

---

## [3.52.103] - 2026-01-13

### Added
- **CrowdSec Blocklist Integration**: Synchronisation des blocklists premium vers XGS

---

## [3.52.102] - 2026-01-13

### Changed
- **Log Retention - Safe by Default**: Auto-cleanup desactive par defaut
- VGX ne supprime JAMAIS de donnees automatiquement sauf activation explicite

---

## [3.52.101] - 2026-01-13

### Added
- **Log Retention**: Configuration retention des logs avec cleanup automatique

---

## [3.52.100] - 2026-01-12

### Added
- **D2B v2 - Jail System Phase 1**: Systeme avance de gestion des bans
- Tiers progressifs: Tier 0 (4h) → Tier 1 (24h) → Tier 2 (7d) → Tier 3+ (Permanent)
- GeoZone Classification: Authorized / Hostile / Neutral

---

## [3.51.102] - 2026-01-12

### Added
- **Report Recipients**: Configuration des emails destinataires pour scheduled reports
- **Country Flags**: Affichage drapeau pays a cote des IPs dans Active Bans

---

## [3.51.101] - 2026-01-12

### Added
- **WAF Event Watcher**: Trigger instantane de sync ModSec sur detection WAF

---

## [3.51.100] - 2026-01-12

### Added
- **Detect2Ban Immunity**: Nouveau bouton "Unban 24h" pour faux positifs
- **Ban History Modal**: Section historique des bans dans IPThreatModal

### Fixed
- API Endpoint: `/bans/${ip}/history`
- ClickHouse Types: UInt32 → uint32, UInt8 → uint8
- Detect2Ban: EventCount int64 → uint64, Query FROM events → FROM vigilance_x.events

---

## [3.5.100] - 2026-01-12

### Added
- **Interactive Attack Map**: Nouvelle page de visualisation des attaques
- Carte mondiale avec flux animes
- Filtres par type: WAF, IPS/IDS, Malware, Threat
- Service d'enrichissement geo automatique

---

*Pour les versions anterieures, voir les notes de release sur GitHub.*
