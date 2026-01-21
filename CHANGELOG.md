# VIGILANCE X - Changelog

Toutes les modifications notables du projet sont documentees dans ce fichier.

Le format est base sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhere au [Semantic Versioning](https://semver.org/spec/v2.0.0.html) modifie (X.YY.Z).

---

## [3.58.106] - 2026-01-21

### Changed
- **Version Bump**: Test release to validate Docker container update fix

---

## [3.58.105] - 2026-01-21

### Fixed
- **System Update Process**: New approach using separate Docker container
  - Previous fix (nohup/setsid) didn't work because Docker kills entire cgroup
  - Now launches `docker:cli` container that survives backend death
  - Update logs saved to `/opt/vigilanceX/update.log` for debugging

---

## [3.58.104] - 2026-01-21

### Changed
- **Version Bump**: Test release to validate update fix from v3.58.103

---

## [3.58.103] - 2026-01-21

### Fixed
- **System Update Process**: Fixed auto-restart after update via WebUI
  - Backend now uses `nohup setsid` to detach docker compose restart
  - Previously, the restart command was killed when the container died
  - Update logs saved to `/tmp/vgx-update.log` for debugging
- **Settings Admin Email**: Email now persists after page refresh
  - Added useEffect to load admin_email from savedConfigs on mount
- **Settings Default Tab**: Now opens on "System" tab instead of "General"

---

## [3.58.102] - 2026-01-20

### Fixed
- **Production Deployment**: Fixed GHCR images for VPS deployments
- **System Update**: Git pull + docker compose build workflow for local builds

---

## [3.58.101] - 2026-01-20

### Fixed
- **Web UI Firmware**: Upgrade mechanism for VPS deployments

---

## [3.58.100] - 2026-01-20

### Added
- **System Notifications**: Admin email configuration in Settings > System
- **Vigimail Leak Badges**: Visual indicators for email breach status

---

## [3.57.126] - 2026-01-20

### Added
- **Custom Logo**: New hexagonal logo design with teal/orange accents
  - SVG component at `/components/Logo.tsx`
  - Updated favicon with cache-busting version parameter
  - Applied to Login, Dashboard, and Sidebar

### Fixed
- **Logout 401 Error**: Moved `/auth/logout` to public routes
  - Now works even with expired/invalid tokens (common pattern)
- **Timestamp Offset**: Fixed 1-hour timezone offset in WAF logs
  - Vector now parses XGS timestamps with timezone offset (`+0100`)
  - Backend Dockerfile sets `TZ=UTC`
  - ClickHouse connection uses `session_timezone: UTC`
- **IPThreatModal Pending Badge**: Now correctly shows "Pending Approval" status
  - `GetBanByIP` checks both `ip_ban_status` and `pending_bans` tables
- **Vigimail 400 Error**: Fixed double `@@` bug when adding emails
  - Removed pre-fill that caused `@domain.domain` prefix
- **Vigimail Leak Count**: HIBP API now includes unverified breaches
  - Added `includeUnverified=true` parameter
- **401 on Dashboard Load**: Moved `modsec/test` and `detect2ban/status` to free routes
  - These status endpoints no longer require license

### Changed
- **WAF Explorer Pagination**: Now per-day instead of global
  - All days visible and expandable when viewing 7d/30d
  - Pagination controls (25/50/100 items) appear within each expanded day
  - First/Prev/Page/Next/Last navigation per day
  - Footer shows total events across all days

---

## [3.57.125] - 2026-01-20

### Changed
- **Version Bump**: Test release for firmware update validation

---

## [3.57.124] - 2026-01-20

### Fixed
- **429 Rate Limit Handling**: LicenseContext now preserves license state on temporary errors (429, 502, 503)
  - Previously, rate limit errors caused redirect to "License Required" page
  - Now keeps previous valid license state and logs warning silently
- **Rate Limiter Too Aggressive**: Increased global rate limit from 100 to 500 req/min
  - React SPAs make many parallel requests on page load
  - 100/min was causing auth failures and redirect loops
- **Version Comparison Logic**: Fixed semver comparison in Dashboard and backend
  - Dashboard badge now correctly shows green "Up to Date" when installed >= latest
  - Backend `/system/version` uses proper semver comparison instead of string equality
  - Previously showed "Update Available" even when installed version was newer

---

## [3.57.123] - 2026-01-20

### Added
- **In-App Updates**: Settings System tab now shows firmware/software update section
  - Displays installed version vs latest GitHub release
  - Visual comparison with update indicator

---

## [3.57.122] - 2026-01-20

### Fixed
- **License Activation Loop**: Fixed license.json corruption after hardware ID migration (VX2→VX3)
  - VX3 binding now includes firewall serial for stronger hardware binding
  - Corrupt license files are now properly detected and require re-activation

### Changed
- **README Parser Stats**: Updated to accurate numbers (104 fields, 74 rules, 23 MITRE techniques)

---

## [3.57.121] - 2026-01-20

### Fixed
- **Theme Contrast**: Fixed unreadable text in WAF Explorer for Dark+ and Anthracite themes
  - Attack type badges now use brighter colors for visibility
  - CSS attribute selectors to avoid Tailwind circular dependency

---

## [3.57.120] - 2026-01-20

### Fixed
- **Version Badge Detection**: Dashboard now fetches latest version from GitHub API
  - Shows green badge when up-to-date
  - Shows orange "Update: vX.Y.Z" when update available
  - Gray badge while checking

### Changed
- **README**: Renamed "Neural-Sync" to "CrowdSec BL" for clarity

---

## [3.57.119] - 2026-01-20

### Fixed
- **gitgo Skill**: Added complete file exclusions for public repos
  - Now properly excludes: docs/, BUGFIXSESSION/, FEATURESPROMPT/, .github/, .claude/, backups/

---

## [3.57.118] - 2026-01-20

### Fixed
- **Pending Bans Approve/Reject 404**: Fixed API returning 404 on approve/reject operations
  - Added `GetPendingBanByID` method to repository for UUID lookup
  - Updated handler to use ID instead of IP for pending ban retrieval
  - Interface `PendingBansStore` extended with new method

- **IP Modal Slow Loading**: Fixed auto-scan triggering even when score exists
  - Modals now display existing scores immediately
  - Full TI scan only runs when no stored score exists
  - User can manually refresh to get updated data

### Added
- **Sorting for Pending Approval List**: Sort by Date or TI Score
  - Toggle buttons in modal header
  - Ascending/descending support

- **Sorting for Active Bans Table**: Sortable columns
  - Status (permanent > active)
  - Ban Count (high to low)
  - Last Ban date

- **Pagination for Active Bans**: Navigation system for large lists
  - Items per page selector: 25 / 50 / 100
  - Page navigation: First, Previous, Page X of Y, Next, Last
  - Auto-reset to page 1 on filter changes

- **8h Time Filter**: Added to Active2Ban page
  - Filter options: All, 8h, 24h, 7d

- **WAF Explorer 8h Filter**: Replaced 14d with 8h
  - Period options now: 1h, 8h, 24h, 7d, 30d

- **Quick Navigation Buttons**: VPN, Track IP, Attack Analyzer in IP modals
  - Navigate to pages with IP pre-filled
  - Auto-search/filter on arrival

- **Auto-Search on Navigation**: Pages now auto-execute searches from URL params
  - TrackIP: `?ip=X.X.X.X` triggers search
  - VpnNetwork: `?src_ip=X.X.X.X` sets filter
  - AttacksAnalyzer: `?src_ip=X.X.X.X` opens modal with filter

---

## [3.57.115] - 2026-01-19

### Added
- **High Threat Auto-Ban Scenario**: New D2B scenario `high_threat_auto_ban.yaml`
  - Bans IPs with TI score >= 70 even with single security event
  - Triggers on WAF, IPS, ATP events
  - 24h aggregation window, 24h ban duration
  - Solves issue where high-threat IPs with low event count weren't banned

### Fixed
- **Duplicate Pending Bans**: Improved D2B engine duplicate handling
  - Added `UpdatePendingBanEventCount` method to repository
  - Engine now updates existing pending bans instead of creating duplicates
  - Updates event_count and last_event timestamp for ongoing attacks
  - Interface `PendingBansRepository` extended with new method

---

## [3.57.114] - 2026-01-19

### Fixed
- **Infrastructure IP Exclusion**: Exclude XGS/VigilanceX public IP (83.194.220.184) from all stats
  - Dashboard stats: Total events, blocked events, unique IPs, severity counts
  - Timeline chart: Event counts per time bucket
  - GeoHeatmap: Country distribution (all versions)
  - Stats by log type: Event type breakdown
  - Report stats: All report statistics and aggregations
  - Top attackers, targets, rules, countries in reports
  - WAF Explorer: GetLogs, GetGroupedByRequest, rule stats, attack type stats
  - ModSec logs: All queries exclude infrastructure IP to avoid false positives

- **Duplicate Pending Bans**: Fixed D2B engine creating duplicate pending entries
  - Added existence check in `createPendingApproval` before creating new entry
  - Cleaned up existing duplicates in database

### Added
- **Pending Approval UI**: New clickable stats card in Active2Ban page
  - 5-column stats grid with new "Pending Approval" card
  - Full modal with IP info, Approve Ban, Deny Ban, View Details buttons
  - Real-time pending count display

- **Permanent Whitelist Entry**: Added infrastructure IP to permanent whitelist
  - IP 83.194.220.184 whitelisted as "Infrastructure VigilanceX/XGS"

---

## [3.57.113] - 2026-01-18

### Added
- **MITRE ATT&CK Detection**: Automatic technique identification in Vector log parser
  - 23 MITRE techniques mapped: T1190, T1059, T1059.007, T1083, T1105, T1595, T1203, T1046, T1498, T1110, T1071, T1204, T1486, T1566, T1496, T1090
  - WAF attacks: SQL Injection (T1190), XSS (T1059.007), RCE (T1059), LFI (T1083), RFI (T1105)
  - IPS alerts: Port Scan (T1046), DoS (T1498), Brute Force (T1110), Exploits (T1203)
  - ATP threats: C2 Communication (T1071), Malware (T1204), Ransomware (T1486), Phishing (T1566), Cryptominer (T1496)
  - Scanner detection: Nmap, Masscan, Nuclei, SQLMap, Nikto, Burp, ZAP, Dirbuster, Gobuster, Wfuzz
  - Exploit detection: Log4Shell, XXE, SSRF, Deserialization, EternalBlue, Shellshock

- **Enhanced Log Categorization**: More granular sub_category field
  - SQL Injection: Union-based, Blind SQLi, Generic SQLi
  - XSS: Reflected, Stored, Generic XSS
  - RCE: Shell Command, PowerShell, Generic RCE
  - Network Scan: SYN Scan, Port Scan, Nmap Detected
  - DoS: SYN Flood, UDP Flood, Amplification
  - Malware: Trojan, Ransomware, Worm, Adware

### Changed
- **Event Entity**: Added `mitre_technique` field to Event struct and ClickHouse schema
- **Events Repository**: Updated GetEvents and GetEventByID to include MITRE technique
- **Frontend Types**: Added `mitre_technique` to Event interface

### Technical
- `docker/vector/vector.toml`: Added MITRE ATT&CK categorization in categorize_attacks transform
- `docker/clickhouse/init-db.sql`: Added mitre_technique column + index
- `backend/internal/entity/event.go`: Added MitreTechnique field
- `backend/internal/adapter/repository/clickhouse/events_repo.go`: Updated queries for mitre_technique
- `frontend/src/types/index.ts`: Added mitre_technique to Event interface

---

## [3.57.112] - 2026-01-18

### Fixed
- **CrowdSec CTI API Key Loading**: Critical fix - `loadIntegrationsConfig()` now called BEFORE `config.Load()`
  - API keys from integrations.json were not being loaded because config was parsed first
  - CrowdSec CTI now properly queries with saved API key (50/day quota active)

- **Attack Map XGS IP Filter**: Filter out lines FROM public IP 83.194.220.184
  - Added `src_ip != toIPv4('83.194.220.184')` to `GetGeoHeatmapFiltered()` and `GetGeoHeatmapFilteredRange()`
  - XGS firewall public IP no longer appears as attack source on map

- **Cyber Theme Admin Console**: Header not showing properly with futuristic theme
  - Added `.admin-console-modal` and `.admin-console-header` CSS classes
  - Added futuristic theme specific styling with solid backgrounds and neon accents

### Changed
- **CrowdSec BL XGS Groups**: Moved from inline section to modal popup
  - Groups only shown when clicking XGS Groups card (cleaner UI)
  - Added hover effects and "Click to view" indication

- **TI Cascade CrowdSec Weight**: Increased from 0.10 to 0.16 (60% increase)
  - CrowdSec now highest weighted provider in aggregation
  - Better reflects CrowdSec's superior data quality (behaviors, MITRE, subnet reputation)

### Technical
- `backend/cmd/api/main.go`: Reordered initialization - integrations loaded before config
- `backend/internal/adapter/repository/clickhouse/events_repo.go`: XGS IP filter in heatmap queries
- `backend/internal/adapter/external/threatintel/aggregator.go`: CrowdSec weight adjustment
- `frontend/src/components/TerminalConsole.tsx`: Added CSS class identifiers
- `frontend/src/index.css`: +45 lines for admin console futuristic styling
- `frontend/src/pages/CrowdSecBL.tsx`: XGS groups modal implementation

---

## [3.57.109] - 2026-01-18

### Added
- **Futuristic Theme (Cyberpunk/Neon)**: Nouveau theme UI moderne et immersif
  - **Palette neon**: Cyan (#06b6d4), Violet (#a855f7), Pink (#ec4899) comme accents
  - **Glassmorphism avance**: Effets verre depoli avec profondeur et glow
  - **Animations fluides**: Gradient animated borders, glow pulse, neon flicker
  - **Selection dans Settings**: Display > Theme > Cyber (icone Sparkles)
  - **Auto-applied styles**: Transformation automatique de tous les composants

- **CSS Utility Classes**: Nouvelles classes pour styling futuriste
  - `.neon-text-*`: Texte avec effet neon (cyan, purple, pink)
  - `.neon-border-*`: Bordures avec glow (cyan, purple, animated)
  - `.glass-futuristic`: Glassmorphism profond avec teinte cyan
  - `.cyber-card`: Cartes avec grid pattern cyberpunk
  - `.holographic`: Gradient anime holographique
  - `.btn-futuristic`, `.btn-neon-*`: Boutons avec effets neon

- **Tailwind Extensions**: Config Tailwind enrichie
  - Shadows: `neon-cyan`, `neon-purple`, `neon-pink`, `glass`, `glass-lg`
  - Animations: `glow-pulse`, `neon-flicker`, `gradient-x`, `border-flow`, `float`
  - Colors: Palette `neon.*` pour accents
  - Background: `cyber-grid` pattern

- **Claude Code Skills**: 6 nouveaux skills CSS/UI crees
  - `css-glassmorphism`: Effets glassmorphism et neumorphism
  - `css-animations`: Animations CSS et micro-interactions
  - `css-dark-theme`: Design dark mode pour SOC
  - `tailwind-patterns`: Patterns Tailwind avances
  - `framer-motion`: Animations React avec Framer Motion
  - `color-palette`: Theorie des couleurs pour dashboards

### Changed
- **SettingsContext**: Ajout du theme 'futuristic' aux options
  - Theme applique via classes CSS sur `<html>` (.dark + .futuristic)
  - Variables CSS personnalisees pour couleurs futuristes

### Technical
- `frontend/src/index.css`: +350 lignes de styles futuristes
  - Theme variables (.futuristic)
  - Neon glow effects
  - Advanced glassmorphism
  - Auto-applied styles pour cards, buttons, inputs, tables
  - Futuristic scrollbar, map styling
- `frontend/tailwind.config.js`: Extended colors, shadows, animations
- `frontend/src/contexts/SettingsContext.tsx`: theme: 'futuristic' option
- `frontend/src/pages/Settings.tsx`: Cyber theme dans ToggleGroup
- `.claude/skills/css-*/SKILL.md`: 6 nouveaux skills documentes

---

## [3.57.108] - 2026-01-18

### Added
- **IP Threat Modal Shortcuts**: Ajout icones loupe a cote des IPs dans toute l'app
  - Dashboard > Top Attackers: Loupe pour voir fiche TI de l'IP
  - Dashboard > Critical Alerts Modal: Loupe sur les IPs source
  - WAF Servers Modal: Loupe sur Top Attacker IPs et Recent Activity IPs
  - Permet d'ouvrir IPThreatModal pour consultation rapide de la fiche menace

- **CrowdSec BL Background Enrichment**: Worker backend pour enrichissement automatique
  - Enrichissement pays execute en arriere-plan (45 IPs/90s pour respecter ip-api.com)
  - Demarre automatiquement au boot si IPs existent sans country_code
  - Status visible dans `/api/v1/crowdsec/blocklist/status` (enrichment_running)
  - Plus besoin de rester sur la page CrowdSecBL pour enrichir

### Changed
- **Attack Map Improvements v3.57.108**: Map plus immersive avec flux colores par type
  - **Couleurs par type d'attaque**: Orange (WAF), Rouge (IPS), Violet (Malware), Vert (Threat)
  - Chaque pays colore selon son type d'attaque dominant
  - **Animations ameliorees**: Effet comet trail, particules plus brillantes
  - Impact flash multi-ring au point d'arrivee
  - Flux avec glow externe plus prononce

- **Top Attackers Dashboard**: Filtre IP externes uniquement + metriques ameliorees
  - Exclusion automatique des IP LAN (10.x, 172.16-31.x, 192.168.x, 127.x)
  - Focus sur les log types securite (WAF, IPS, ATP, Anti-Virus, Firewall, Threat)
  - Affichage "blocked" (rouge) et "detected" (orange) separes

### Fixed
- **Terminal Console Logs**: Docker CLI maintenant disponible dans le container backend
  - `docker-cli` ajoute dans backend/Dockerfile
  - `/var/run/docker.sock` monte en lecture seule
  - Logs services accessibles via Terminal Console > Logs

- **CrowdSec API Usage Counter**: PriorityCrowdSec maintenant actif dans CascadeConfig
  - Bug: CascadeConfig custom n'incluait pas PriorityCrowdSec (default false)
  - Fix: `PriorityCrowdSec: true` explicite dans main.go

### Technical
- `backend/Dockerfile`: +docker-cli, user vigilance dans groupe docker
- `docker/docker-compose.yml`: Mount /var/run/docker.sock:ro
- `backend/cmd/api/main.go`: PriorityCrowdSec=true dans CascadeConfig
- `backend/internal/usecase/crowdsec/blocklist_service.go`: enrichWorker background
- `backend/internal/adapter/repository/clickhouse/events_repo.go`: Top Attackers query LAN filter
- `frontend/src/pages/Dashboard.tsx`: IPThreatModal integration, TopAttackerRow avec loupe
- `frontend/src/components/dashboard/WAFServersCard.tsx`: IPThreatModal + loupes
- `frontend/src/pages/AttackMap.tsx`: Fetch per-type, couleurs dominantes
- `frontend/src/components/attackmap/AttackFlowLayer.tsx`: Trail comet, glow ameliore

---

## [3.57.107] - 2026-01-18

### Added
- **Admin Terminal Console**: Nouvelle interface CLI pour administration Docker
  - Mode Console: Commandes admin (status, restart, stop, start, health, db-stats, cache-clear, logs)
  - Mode Logs Viewer: Visualisation temps reel des logs services avec streaming SSE
  - Accessible via icone Monitor dans le header (admin uniquement)
  - Backend: `/api/v1/console/execute`, `/api/v1/console/logs`, `/api/v1/console/logs/stream`
  - Frontend: `TerminalConsole.tsx` modal avec tabs Console/Logs

### Fixed
- **ThreatIntel CrowdSec Priority**: CrowdSec est maintenant toujours interroge (PriorityCrowdSec=true)
  - Ajout option `PriorityCrowdSec` dans `CascadeConfig`
  - CrowdSec query immediatement apres Tier 1, independamment du seuil de cascade
  - Nouvelles fonctions: `queryCrowdSecPriority()`, `queryTier2WithFlags()`

- **Dashboard Layout Fixes**:
  - XGS Logins (authentification) deplace en position 2 pour visibilite
  - Events by Type hauteur augmentee (180px vs 100px)
  - Filtre auth ameliore: inclut login, logged, sign, sub_category

### Technical
- `backend/internal/adapter/controller/http/handlers/console.go`: Handler console admin
- `backend/internal/adapter/external/threatintel/aggregator.go`: CrowdSec priority mode
- `frontend/src/components/TerminalConsole.tsx`: Modal console admin
- `frontend/src/lib/api.ts`: consoleApi pour commandes terminal

---

## [3.57.106] - 2026-01-18

### Security
- **CORS Securise**: Remplacement du wildcard `https://*` par configuration env-based (`APP_FRONTEND_URL`)
- **Security Headers Middleware**: Ajout des headers OWASP (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, CSP, HSTS)
- **Console Logs Production**: Suppression des logs debug en production (websocket.ts, IPThreatModal.tsx)

### Performance
- **React Lazy Loading**: Toutes les pages chargees en lazy avec Suspense (~60% reduction bundle initial)
- Code splitting automatique par route (visible dans build output)

### Added
- **Glassmorphism UI Components**:
  - `GlassModal`: Modal moderne avec effet verre depoli et animations CSS
  - `GlassCard`: Carte avec effet glassmorphism
  - `GlassButton`: Bouton style verre
- **CSS Utilities**: Classes `.glass`, `.glass-card`, `.shimmer`, `.card-glow`, `.gradient-text`
- **Audit Notes Section**: Section CLAUDE.md pour tracker les points futurs

### Technical
- `backend/internal/adapter/controller/http/middleware/security.go`: Nouveau middleware
- `backend/internal/config/config.go`: Ajout `FrontendURL` pour CORS production
- `frontend/src/components/ui/GlassModal.tsx`: Composants glassmorphism
- `frontend/src/App.tsx`: React.lazy() pour toutes les pages
- `frontend/src/index.css`: Utilities glassmorphism

---

## [3.57.105] - 2026-01-17

### Changed
- **Dashboard Layout v2**: Améliorations significatives du layout
  - **Top Attackers**: Max-height 320px, affiche ~5 items avec scroll, indicateur "X total"
  - **Events by Type**: Version ultra-compacte (100px) avec indicateurs colorés inline
  - **XGS Logins**: Pagination complète (10 items/page, nav 1-2-3...) pour 200 entrées max
  - Format login: `[OK/FAIL] username | IP | date heure`

### Technical
- `LogTypeRowCompact`: Nouveau composant avec indicateur couleur + barre inline
- `XGSLoginCard`: Réécrit avec pagination (ChevronLeft/Right, numéros de page)
- Constantes: `ITEMS_PER_PAGE = 10`, `MAX_ENTRIES = 200`

---

## [3.57.104] - 2026-01-17

### Added
- **Dashboard XGS Login Activity**: Nouvelle carte affichant les connexions admin XGS
  - Affiche username, IP source, pays, timestamp
  - Marqueur vert pour succès, rouge + badge "FAILED" pour échecs
  - Scroll avec max 50 entrées visibles
  - Refresh automatique selon settings

### Changed
- **Dashboard Layout Improvements**:
  - Top Attackers: Liste réduite avec scroll (max-height 280px)
  - Events by Type: Section compacte avec scroll (max-height 140px)
  - Grid 2x2 au lieu de 3 colonnes pour accommoder XGS Logins

### Technical
- `frontend/src/components/dashboard/XGSLoginCard.tsx`: Nouveau composant
- `frontend/src/pages/Dashboard.tsx`: Import XGSLoginCard, layout 2x2, scroll sections

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
