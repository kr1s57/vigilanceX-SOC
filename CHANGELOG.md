# VIGILANCE X - Changelog

Toutes les modifications notables du projet sont documentees dans ce fichier.

Le format est base sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhere au [Semantic Versioning](https://semver.org/spec/v2.0.0.html) modifie (X.YY.Z).

---

## [3.57.103] - 2026-01-17

### Changed
- **CrowdSec Blocklist XGS Architecture**: Nouvelle architecture de nommage pour les listes CrowdSec
  - Limite XGS découverte: **1000 IPs maximum par IPList** (erreur code 522 si dépassé)
  - Nouveau nommage: `grp_CS_{BlocklistName}_XX` (ex: `grp_CS_BotnetActors_01`, `_02`, etc.)
  - Chaque blocklist CrowdSec obtient sa propre série d'IPLists
  - Sync séparé par blocklist (plus de liste globale)
  - Cleanup automatique des anciennes listes lors de réduction du nombre d'IPs

### Technical
- `backend/internal/adapter/external/sophos/client.go`:
  - `SyncBlocklistIPLists()`: Synchronise une blocklist vers IPLists numérotées
  - `sanitizeBlocklistName()`: Convertit labels en noms XGS valides
  - `cleanupOldIPLists()`: Supprime les IPLists obsolètes
  - `DeleteIPHost()`: Suppression d'objet IPHost
- `backend/internal/usecase/crowdsec/blocklist_service.go`:
  - `SyncToXGS()` réécrit pour sync chaque blocklist séparément

### Result
- 33 IPLists créées sur XGS:
  - `grp_CS_BotnetActors_01` à `_24` (23,471 IPs)
  - `grp_CS_InternetScanners_01` à `_09` (8,511 IPs)

---

## [3.57.102] - 2026-01-17

### Fixed
- **CrowdSec Blocklist XGS Sync**: Correction majeure du sync vers Sophos XGS pour les grandes listes d'IPs
  - Fix: Passage de GET à POST pour les payloads XML volumineux (limite URL dépassée)
  - Fix: Format IPList corrigé (`HostType: "IPList"` + `ListOfIPAddresses`)
  - Fix: Vérification d'erreurs sur `resp.IPHost[0].Status` au lieu de `resp.Status`
  - Note: Les objets IPList ne peuvent pas être membres d'un IPHostGroup dans Sophos XGS
  - Les objets CS_List_1 à CS_List_32 sont créés et disponibles pour les règles firewall

### Technical
- `backend/internal/adapter/external/sophos/client.go`:
  - `sendRequest()`: POST avec body form-encoded au lieu de GET avec query params
  - `CreateIPListObject()`: Utilise `HostType: "IPList"` et `ListOfIPAddresses`
  - `UpdateIPListObject()`: Même correction de format
  - `SyncGroupIPsWithList()`: Crée les objets IPList sans tenter de les ajouter à un groupe
- `frontend/nginx.conf`: Timeout API augmenté à 300s pour les opérations de sync longues

---

## [3.57.101] - 2026-01-16

### Added
- **WAF Monitored Servers**: Nouvelle fonctionnalité de suivi des serveurs WAF
- **Country Selector Component**: Sélecteur de pays amélioré pour le geoblocking

### Technical
- Nouveau handler `waf_servers.go` pour la gestion des serveurs WAF
- Repository ClickHouse `waf_servers_repo.go`
- Migration `014_waf_monitored_servers.sql`
- Composants frontend: `WAFServerModal.tsx`, `WAFServersCard.tsx`, `CountrySelector.tsx`

---

## [3.55.116] - 2026-01-16

### Added
- **Version Check Badge**: Dashboard affiche la version installée avec indicateur de mise à jour
  - Pastille verte si à jour, orange si mise à jour disponible
  - Compare la version installée avec la dernière version depuis VGXKey
- **Login Page Version**: Affichage de la version en footer sur les pages de login (VGX et VGXKey)

### Improved
- **License Badge Colors**: Couleur du badge licence selon les jours restants
  - Vert: >30 jours restants
  - Orange: ≤30 jours restants
  - Rouge: ≤15 jours restants ou expiré
- **VGXKey License Display**: Couleurs uniformisées pour les licences expirantes
  - "X days remaining" en rouge si ≤15 jours
  - "X days remaining" en orange si ≤30 jours

### Technical
- `VGXKey`: Nouveau champ `LatestVGXVersion` dans LicenseStatus
- `VGX Dashboard`: Import de `useLicense` + badge version dynamique
- `VGX Sidebar`: Logique de couleur basée sur `days_remaining`
- `VGX Login`: Footer avec version v3.55.116

---

## [3.55.115] - 2026-01-16

### Fixed
- **License Sync 402 Error**: Correction du bug où `/license/validate` était protégé par le middleware de licence
  - L'endpoint `/license/validate` déplacé vers les routes FREE (sans licence requise)
  - Permet maintenant de synchroniser la licence même quand elle n'est pas valide localement
- **VGXKey Auto-Activation**: Les nouvelles licences trial sont automatiquement activées lors du FreshDeploy
  - Création automatique d'un enregistrement d'activation dans la DB

### Technical
- `backend/cmd/api/main.go`: `/license/validate` moved to free routes group
- `vigilanceKey/backend/internal/service/license.go`: Auto-create activation in FreshDeploy

---

## [3.55.114] - 2026-01-16

### Fixed
- **Fresh Deploy License Key**: Correction critique du bug ou la clé de licence trial n'était pas transmise au client VGX
  - VGXKey: `LicenseStatus` inclut maintenant `license_key` dans la réponse JSON
  - VGXKey: `ToStatus()` retourne la clé de licence
  - VGX Client: `FreshDeployResponse.License` inclut maintenant `LicenseKey`
  - VGX Client: `FreshDeploy()` stocke la clé reçue de VGXKey
  - Le sync de licence fonctionne maintenant correctement après fresh deploy

### Technical
- `vigilanceKey/backend/internal/entity/license.go`: Ajout `LicenseKey` à `LicenseStatus` + `ToStatus()`
- `backend/internal/license/client.go`: Ajout `LicenseKey` à `FreshDeployResponse.License` + stockage dans `FreshDeploy()`

---

## [3.55.113] - 2026-01-16

### Fixed
- **License Persistence for Trial Status**: Correction critique du bug ou les licences trial (FDEPLOY, TRIAL) n'etaient pas correctement restaurees apres un restart du backend
  - `LoadFromStore()` ne supportait que le status "active", pas les status trial
  - Ajout du support pour les status: active, trial, fdeploy, asked (case-insensitive)
  - Les utilisateurs ne seront plus forces de re-demander une licence apres logout/login

### Technical
- `backend/internal/license/client.go`: `LoadFromStore()` utilise maintenant une map de statuts valides

---

## [3.55.112] - 2026-01-15

### Added
- **Clickable Logo**: Le logo VIGILANCE X dans la sidebar est maintenant cliquable et redirige vers le dashboard

### Fixed
- **License Persistence After Logout**: Correction du bug ou la licence etait re-demandee apres logout/login meme quand elle etait deja synchronisee
  - LicenseContext detecte maintenant les changements d'authentification
  - Reset de l'etat licence au logout, refresh automatique au login

### Improved
- **VPS Deployment**: Mise a jour de la documentation pour simplifier le deploiement
  - docker-compose utilise `${VGX_VERSION:-latest}` pour les images GHCR
  - README avec instructions detaillees pour .env
  - Ajout de la configuration reverse proxy recommandee

### Technical
- LicenseContext.tsx: Ajout de useAuth() hook pour detecter les changements d'auth
- client-dist/deploy/docker-compose.yml: Images GHCR avec version dynamique
- client-dist/README.md: Instructions de deploiement ameliorees

---

## [3.55.111] - 2026-01-15

### Fixed
- **Domain Migration**: Migration de domaine completee
- **Password Fix**: Correction du mot de passe par defaut

---

## [3.55.102] - 2026-01-15

### Added
- **Track IP Feature**: Nouvel outil de recherche forensique pour traquer une IP/hostname a travers tous les logs
  - 8 categories de recherche parallele: events, waf, modsec, firewall, vpn, atp, antivirus, heartbeat
  - Enrichissement GeoIP automatique
  - Summary avec severity breakdown et time range
  - API: `GET /api/v1/track-ip?query={ip}&period={1h|24h|7d|30d}`
  - Navigation: Sidebar > Network > Track IP

### Fixed
- **WAF Events in Track IP**: La section WAF Events utilise maintenant les vrais logs WAF Sophos
  - Nouvelle methode `SearchWAFSophos()` filtrant `log_type='WAF'` dans la table events
  - Renommage "XGS Events" en "Firewall Events" pour plus de clarte

### Technical
- Backend: entity/trackip.go, repository/trackip_repo.go, usecase/trackip/service.go, handlers/trackip.go
- Frontend: pages/TrackIP.tsx (810 lignes), types, api client

---

## [3.55.101] - 2026-01-14

### Fixed
- **Report Recipients Persistence**: Correction du bug ou les emails Report Recipients ne persistaient pas
  - Ajout du champ `report_recipients` dans `MergeAndUpdateSettings()` (notifications/service.go)
- **Unified Attack History**: Section Attack History unifiee dans IPThreatModal
  - Fusion des sections "Attack History" et "WAF Attack History"
- **Attack History API 500 Error**: Correction critique du filtrage par IP
  - Probleme: ClickHouse collision d'alias `There is no supertype for types String, IPv4`
  - Solution: Prefixes de table explicites (`e.` pour events, `m.` pour modsec_logs)

---

## [3.55.100] - 2026-01-14

### Added
- **D2B v2 Phase 2 - Decision Engine avec logique zones**
  - Engine D2B v2 avec nouvelles interfaces: `GeoIPClient`, `GeoZoneRepository`, `PendingBansRepository`
  - Logique de decision par zone geographique (Hostile/Authorized/Neutral)
  - Service Bans avec `BanIPWithTier()` et `UnbanIPWithConditional()`
  - Handler Pending Bans pour gestion file d'attente admin
  - Routes `/api/v1/pending-bans/*` ajoutees

---

## [3.54.100] - 2026-01-14

### Added
- **Vigimail Checker Module**: Nouveau module complet de verification emails et securite DNS
  - Migration ClickHouse `013_vigimail_checker.sql` (5 tables)
  - Clients externes: HIBP v3, LeakCheck.io, DNS checker natif
  - 14 endpoints HTTP sous `/api/v1/vigimail/*`
  - Page `VigimailChecker.tsx` avec UI complete
  - Worker background configurable (6h/12h/24h/48h/7d)
- **Settings Reorganisation**: Integrations reorganisees par categories
  - 5 categories: Sophos Firewall, CrowdSec, Threat Intelligence, Email & Notifications, Premium

---

## [3.53.106] - 2026-01-14

### Fixed
- **Detect2Ban Immunity Bug**: Correction du ban automatique après expiration de l'immunité 24h
  - Avant: IP re-bannie car events PENDANT l'immunité étaient comptés
  - Après: Seuls les events APRÈS l'expiration de l'immunité sont comptés
  - Nouvelle fonction `countEventsAfter()` pour recompter les events post-immunité

### Technical
- `handleMatch()` vérifie maintenant si `ImmuneUntil` a expiré récemment
- Si l'immunité a expiré dans la fenêtre du scenario, recompte uniquement les events après

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
