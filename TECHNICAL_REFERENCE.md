# VIGILANCE X - Technical Reference

> **Version**: 3.55.113 | **Derniere mise a jour**: 2026-01-16

Ce fichier contient la reference technique complete du projet VIGILANCE X.
Pour les regles, conventions et workflows, voir `CLAUDE.md`.

---

## Table des Matieres

1. [Stack Technique](#stack-technique)
2. [Structure du Projet](#structure-du-projet)
3. [Fichiers Cles par Fonction](#fichiers-cles-par-fonction)
4. [API Reference Complete](#api-reference-complete)
5. [Database Schemas ClickHouse](#database-schemas-clickhouse)
6. [Entities Go](#entities-go)
7. [Types TypeScript](#types-typescript)
8. [Variables d'Environnement](#variables-denvironnement)
9. [Threat Intelligence Providers](#threat-intelligence-providers)
10. [Systeme de Licence VX3](#systeme-de-licence-vx3)
11. [Integrations Sophos XGS](#integrations-sophos-xgs)
12. [CrowdSec Neural-Sync](#crowdsec-neural-sync)
13. [Detect2Ban Engine](#detect2ban-engine)
14. [Log Retention](#log-retention)
15. [Vigimail Checker](#vigimail-checker)

---

## Stack Technique

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Backend | Go (Chi router, Clean Architecture) | 1.22 |
| Frontend | React + TypeScript + Tailwind + Shadcn UI | 18.2.0 |
| Database | ClickHouse (analytique temps reel) | 24.1 |
| Cache | Redis | 7-alpine |
| Ingestion | Vector.dev (Syslog) | 0.34.1 |
| Deploiement | Docker Compose | - |

---

## Structure du Projet

```
/opt/vigilanceX/
├── backend/                    # API Go + Detect2Ban Engine
│   ├── cmd/                    # Points d'entree
│   │   ├── api/               # Serveur API (main.go)
│   │   ├── detect2ban/        # Moteur de detection
│   │   └── reset-password/    # CLI reset mot de passe
│   ├── internal/              # Code applicatif (Clean Architecture)
│   │   ├── domain/            # Logique metier (scoring)
│   │   ├── entity/            # Modeles de donnees
│   │   ├── adapter/           # Adaptateurs externes
│   │   │   ├── repository/    # Acces base de donnees
│   │   │   ├── controller/    # Handlers HTTP et WebSocket
│   │   │   └── external/      # Clients externes (Sophos, ThreatIntel)
│   │   ├── usecase/           # Services metier
│   │   ├── config/            # Configuration
│   │   ├── license/           # Systeme de licence VX3
│   │   └── pkg/               # Utilitaires reutilisables
│   ├── scenarios/             # Scenarios YAML Detect2Ban
│   └── migrations/            # Migrations SQL
├── frontend/                   # React SPA
│   ├── src/
│   │   ├── pages/             # 15+ pages principales
│   │   ├── components/        # Composants UI reutilisables
│   │   ├── contexts/          # AuthContext, SettingsContext, LicenseContext
│   │   ├── stores/            # Zustand stores (bans, events)
│   │   ├── lib/               # API client, WebSocket, utils
│   │   ├── hooks/             # Custom React hooks
│   │   └── types/             # Definitions TypeScript
│   └── dist/                  # Build de production
├── docker/                     # Configuration Docker Compose
│   ├── docker-compose.yml
│   ├── clickhouse/            # Init SQL ClickHouse + migrations
│   ├── vector/                # Configuration Vector.dev
│   ├── nginx/                 # Reverse proxy production
│   └── ssh/                   # Cles SSH pour Sophos XGS
├── docs/                       # Documentation interne
│   ├── BUGFIX-KB.md           # Knowledge base bugs
│   └── architecture/
├── CLAUDE.md                  # Memoire Claude Code (regles, workflows)
├── TECHNICAL_REFERENCE.md     # CE FICHIER - Reference technique
├── CHANGELOG.md               # Historique des versions
└── README.md                  # Documentation principale
```

---

## Fichiers Cles par Fonction

### Backend - Points d'Entree

| Fichier | Lignes | Description |
|---------|--------|-------------|
| `backend/cmd/api/main.go` | ~800 | Initialisation API, routes, middleware, wiring |
| `backend/cmd/detect2ban/main.go` | ~200 | Daemon de detection |
| `backend/cmd/reset-password/main.go` | ~50 | CLI urgence |

### Backend - Services Metier (usecase/)

| Fichier | Description |
|---------|-------------|
| `usecase/auth/service.go` | Authentification JWT, bcrypt |
| `usecase/bans/service.go` | Gestion des bans progressifs + XGS sync |
| `usecase/threats/service.go` | Aggregation Threat Intel (11 providers) |
| `usecase/events/service.go` | Traitement des evenements |
| `usecase/geoblocking/service.go` | Regles geographiques |
| `usecase/modsec/service.go` | Sync ModSecurity SSH |
| `usecase/detect2ban/engine.go` | Moteur de detection automatique |
| `usecase/crowdsec/blocklist_service.go` | Sync blocklists CrowdSec |
| `usecase/retention/service.go` | Cleanup automatique logs |
| `usecase/notifications/service.go` | Emails SMTP |
| `usecase/apiusage/service.go` | Tracking quotas API |
| `usecase/trackip/service.go` | Recherche forensique IP |
| `usecase/vigimail/service.go` | Verification emails/DNS |
| `license/client.go` | Systeme licence VX3 |

### Backend - Repositories (adapter/repository/clickhouse/)

| Fichier | Description |
|---------|-------------|
| `events_repo.go` | Events Sophos XGS |
| `bans_repo.go` | Ban status et history |
| `threats_repo.go` | Scores Threat Intel |
| `whitelist_repo.go` | Soft whitelist |
| `geozone_repo.go` | GeoZone config + Pending bans |
| `crowdsec_blocklist_repo.go` | IPs blocklist CrowdSec |
| `retention_repo.go` | Settings retention |
| `api_usage_repo.go` | Quotas API providers |
| `trackip_repo.go` | Recherche cross-tables |
| `vigimail_repo.go` | Emails et leaks |
| `modsec_repo.go` | Logs ModSecurity |

### Backend - Adaptateurs Externes (adapter/external/)

| Dossier | Description |
|---------|-------------|
| `threatintel/` | 11 providers TI (AbuseIPDB, VT, etc.) |
| `sophos/` | Client API XML Sophos XGS |
| `crowdsec/` | Client CrowdSec + VigilanceKey proxy |
| `geoip/` | Lookup geolocalisation |
| `storage/` | SMB/S3 archivage |

### Frontend - Pages Principales

| Fichier | Lignes | Description |
|---------|--------|-------------|
| `pages/Dashboard.tsx` | ~400 | Vue d'ensemble securite |
| `pages/AttacksAnalyzer.tsx` | ~1100 | Analyse WAF/ModSec |
| `pages/Settings.tsx` | ~2200 | Configuration systeme |
| `pages/VpnNetwork.tsx` | ~900 | Monitoring VPN |
| `pages/Geoblocking.tsx` | ~570 | Regles geo |
| `pages/SoftWhitelist.tsx` | ~630 | Whitelist graduee |
| `pages/UserManagement.tsx` | ~600 | Gestion utilisateurs |
| `pages/AttackMap.tsx` | ~800 | Carte mondiale attaques |
| `pages/NeuralSync.tsx` | ~700 | CrowdSec Blocklist |
| `pages/TrackIP.tsx` | ~810 | Recherche forensique IP |
| `pages/VigimailChecker.tsx` | ~900 | Verification emails |
| `pages/WAFExplorer.tsx` | ~600 | Exploration logs WAF |
| `pages/Reports.tsx` | ~500 | Rapports PDF/XML |

### Frontend - Infrastructure

| Fichier | Description |
|---------|-------------|
| `lib/api.ts` | Client API Axios (~1500 lignes) |
| `lib/websocket.ts` | Manager WebSocket temps reel |
| `contexts/AuthContext.tsx` | Gestion authentification |
| `contexts/LicenseContext.tsx` | Gestion licence |
| `contexts/SettingsContext.tsx` | Settings globaux |
| `stores/bansStore.ts` | State management bans |
| `stores/attackMapStore.ts` | State carte attaques |
| `types/index.ts` | Definitions TypeScript |

---

## API Reference Complete

### Authentication

```
POST   /api/v1/auth/login              # Login (public)
POST   /api/v1/auth/logout             # Logout
GET    /api/v1/auth/me                 # User info
POST   /api/v1/auth/change-password    # Change password
```

### Events & Stats

```
GET    /api/v1/events                  # Liste events
GET    /api/v1/events/timeline         # Timeline
GET    /api/v1/events/geo-heatmap      # Heatmap geographique
GET    /api/v1/stats/overview          # Stats globales
GET    /api/v1/stats/top-attackers     # Top IPs
GET    /api/v1/stats/attack-categories # Categories d'attaques
```

### Threats

```
GET    /api/v1/threats/check/{ip}      # Check IP single provider
GET    /api/v1/threats/risk/{ip}       # Risk score combine
GET    /api/v1/threats/providers       # Status providers
POST   /api/v1/threats/batch           # Batch check multiple IPs
GET    /api/v1/threats/score/{ip}      # Score from cache
```

### Bans

```
GET    /api/v1/bans                    # Liste bans actifs
POST   /api/v1/bans                    # Creer ban manuel
DELETE /api/v1/bans/{ip}               # Supprimer ban
DELETE /api/v1/bans/{ip}?immunity_hours=24  # Unban avec immunite
GET    /api/v1/bans/{ip}/history       # Historique ban IP
POST   /api/v1/bans/sync               # Sync Sophos XGS
GET    /api/v1/bans/stats              # Statistiques bans
```

### Geoblocking

```
GET    /api/v1/geoblocking/rules       # Liste regles
POST   /api/v1/geoblocking/rules       # Creer regle
DELETE /api/v1/geoblocking/rules/{id}  # Supprimer regle
GET    /api/v1/geoblocking/check/{ip}  # Check IP blocked
GET    /api/v1/geoblocking/lookup/{ip} # Lookup geo
GET    /api/v1/geoblocking/stats       # Stats par pays
```

### Whitelist

```
GET    /api/v1/whitelist               # Liste whitelist
POST   /api/v1/whitelist               # Ajouter IP
DELETE /api/v1/whitelist/{ip}          # Supprimer IP
GET    /api/v1/whitelist/check/{ip}    # Check whitelist status
```

### GeoZone (D2B v2)

```
GET    /api/v1/geozone/config              # Get config
PUT    /api/v1/geozone/config              # Update config
GET    /api/v1/geozone/classify?country=XX # Classify country
GET    /api/v1/geozone/countries           # List all countries
POST   /api/v1/geozone/countries/authorized # Add authorized country
DELETE /api/v1/geozone/countries/authorized?country=XX # Remove
POST   /api/v1/geozone/countries/hostile   # Add hostile country
DELETE /api/v1/geozone/countries/hostile?country=XX # Remove
```

### Pending Bans

```
GET    /api/v1/pending-bans            # Liste bans en attente
GET    /api/v1/pending-bans/stats      # Statistiques
GET    /api/v1/pending-bans/ip/{ip}    # Par IP
POST   /api/v1/pending-bans/{id}/approve  # Approuver
POST   /api/v1/pending-bans/{id}/reject   # Rejeter
```

### CrowdSec Blocklist

```
GET    /api/v1/crowdsec/blocklist/config      # Configuration locale
PUT    /api/v1/crowdsec/blocklist/config      # Update config
GET    /api/v1/crowdsec/blocklist/lists       # Liste blocklists
GET    /api/v1/crowdsec/blocklist/status      # Status service
GET    /api/v1/crowdsec/blocklist/ips/list    # Liste paginee IPs
GET    /api/v1/crowdsec/blocklist/countries   # Liste pays uniques
POST   /api/v1/crowdsec/blocklist/enrich      # Enrichir GeoIP
POST   /api/v1/crowdsec/blocklist/sync        # Sync depuis VK
POST   /api/v1/crowdsec/blocklist/sync/{id}   # Sync blocklist specifique
```

### Log Retention

```
GET    /api/v1/retention/settings      # Get current settings
PUT    /api/v1/retention/settings      # Update retention periods
GET    /api/v1/retention/status        # Worker status + next cleanup
GET    /api/v1/retention/storage       # Disk usage per table
POST   /api/v1/retention/cleanup       # Manual cleanup trigger
```

### Storage (SMB)

```
GET    /api/v1/storage/config          # Get configuration
PUT    /api/v1/storage/config          # Update configuration
PUT    /api/v1/storage/smb             # Update SMB config
GET    /api/v1/storage/status          # Get connection status
POST   /api/v1/storage/test            # Test SMB connection
POST   /api/v1/storage/connect         # Connect to storage
POST   /api/v1/storage/disconnect      # Disconnect
POST   /api/v1/storage/enable          # Enable archiving
POST   /api/v1/storage/disable         # Disable archiving
```

### Notifications

```
GET    /api/v1/notifications/settings  # Get settings
PUT    /api/v1/notifications/settings  # Update settings
POST   /api/v1/notifications/test-email # Send test email
GET    /api/v1/notifications/status    # SMTP status
```

### API Usage / Integrations

```
GET    /api/v1/integrations/providers         # Liste providers avec quotas
GET    /api/v1/integrations/providers/{id}    # Status provider
PUT    /api/v1/integrations/providers/{id}    # Update config provider
```

### Track IP

```
GET    /api/v1/track-ip?query={ip}&period={1h|24h|7d|30d}  # Recherche forensique
```

### Vigimail

```
GET    /api/v1/vigimail/config         # Configuration
PUT    /api/v1/vigimail/config         # Update config
GET    /api/v1/vigimail/domains        # Liste domaines
POST   /api/v1/vigimail/domains        # Ajouter domaine
DELETE /api/v1/vigimail/domains/{id}   # Supprimer domaine
GET    /api/v1/vigimail/domains/{id}/emails  # Emails du domaine
POST   /api/v1/vigimail/domains/{id}/emails  # Ajouter email
DELETE /api/v1/vigimail/emails/{id}    # Supprimer email
POST   /api/v1/vigimail/check/email/{id}     # Check leaks email
POST   /api/v1/vigimail/check/domain/{id}    # Check DNS domaine
GET    /api/v1/vigimail/leaks          # Liste tous les leaks
GET    /api/v1/vigimail/stats          # Statistiques
```

### ModSecurity

```
GET    /api/v1/modsec/logs             # Liste logs WAF
GET    /api/v1/modsec/stats            # Stats ModSec
POST   /api/v1/modsec/sync             # Force sync SSH
GET    /api/v1/modsec/watcher          # Status watcher
```

### License

```
GET    /api/v1/license/status          # Status (public)
POST   /api/v1/license/activate        # Activation manuelle
POST   /api/v1/license/fresh-deploy    # Trial automatique (rate limit 5/h)
POST   /api/v1/license/ask-pro         # Demande upgrade Pro
POST   /api/v1/license/sync-firewall   # Sync firewall binding
GET    /api/v1/license/info            # Details (admin)
POST   /api/v1/license/validate        # Force validation (admin)
```

### Detect2Ban

```
GET    /api/v1/detect2ban/status       # Status engine
POST   /api/v1/detect2ban/start        # Start engine
POST   /api/v1/detect2ban/stop         # Stop engine
GET    /api/v1/detect2ban/scenarios    # Liste scenarios
```

### Users

```
GET    /api/v1/users                   # Liste users (admin)
POST   /api/v1/users                   # Creer user
PUT    /api/v1/users/{id}              # Update user
DELETE /api/v1/users/{id}              # Supprimer user
```

### Reports

```
GET    /api/v1/reports/generate        # Generate report
POST   /api/v1/reports/email           # Send report by email
```

### WebSocket

```
GET    /ws                             # Real-time updates
GET    /api/v1/ws?token=xxx            # With auth token
```

### Status

```
GET    /api/v1/status/syslog           # Status reception syslog
GET    /api/v1/health                  # Health check
```

---

## Database Schemas ClickHouse

### Tables Principales

```sql
-- Events Sophos XGS
CREATE TABLE vigilance_x.events (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    log_type LowCardinality(String),
    log_subtype LowCardinality(String),
    severity LowCardinality(String),
    action LowCardinality(String),
    category LowCardinality(String),
    rule_id String,
    message String,
    raw_log String,
    -- 27 champs additionnels XGS Parser
    country_code LowCardinality(String) DEFAULT '',
    latitude Float64 DEFAULT 0,
    longitude Float64 DEFAULT 0
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip)
PARTITION BY toYYYYMM(timestamp);

-- Ban Status
CREATE TABLE vigilance_x.ip_ban_status (
    ip IPv4,
    is_banned UInt8,
    ban_reason String,
    banned_at DateTime,
    banned_until Nullable(DateTime),
    banned_by String,
    source LowCardinality(String),
    threat_score Int32 DEFAULT 0,
    immune_until Nullable(DateTime),
    -- D2B v2 fields
    current_tier UInt8 DEFAULT 0,
    conditional_until Nullable(DateTime),
    geo_zone LowCardinality(String) DEFAULT '',
    threat_score_at_ban Int32 DEFAULT 0,
    xgs_group LowCardinality(String) DEFAULT 'grp_VGX-BannedIP',
    version UInt64 DEFAULT 1
) ENGINE = ReplacingMergeTree(version)
ORDER BY ip;

-- Ban History
CREATE TABLE vigilance_x.ban_history (
    id UUID DEFAULT generateUUIDv4(),
    ip IPv4,
    action LowCardinality(String),
    reason String,
    performed_by String,
    timestamp DateTime DEFAULT now(),
    details String DEFAULT '',
    tier UInt8 DEFAULT 0,
    geo_zone LowCardinality(String) DEFAULT '',
    threat_score Int32 DEFAULT 0,
    xgs_group LowCardinality(String) DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (ip, timestamp);

-- Threat Scores
CREATE TABLE vigilance_x.threat_scores (
    ip IPv4,
    aggregated_score Float64,
    threat_level LowCardinality(String),
    is_malicious UInt8,
    sources Array(String),
    categories Array(String),
    last_checked DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY ip;

-- Soft Whitelist
CREATE TABLE vigilance_x.whitelist (
    ip IPv4,
    level LowCardinality(String),
    reason String,
    added_by String,
    added_at DateTime DEFAULT now(),
    expires_at Nullable(DateTime),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY ip;

-- Geo Block Rules
CREATE TABLE vigilance_x.geo_block_rules (
    id UUID DEFAULT generateUUIDv4(),
    country_code LowCardinality(String),
    action LowCardinality(String),
    reason String,
    created_by String,
    created_at DateTime DEFAULT now(),
    enabled UInt8 DEFAULT 1
) ENGINE = MergeTree()
ORDER BY country_code;

-- ModSecurity Logs
CREATE TABLE vigilance_x.modsec_logs (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    src_ip IPv4,
    rule_id String,
    rule_msg String,
    severity LowCardinality(String),
    uri String,
    matched_data String,
    action LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip)
PARTITION BY toYYYYMM(timestamp);

-- GeoZone Config
CREATE TABLE vigilance_x.geozone_config (
    id UInt8 DEFAULT 1,
    enabled UInt8 DEFAULT 0,
    authorized_countries Array(String),
    hostile_countries Array(String),
    default_policy LowCardinality(String),
    waf_threshold_hzone UInt8 DEFAULT 1,
    waf_threshold_zone UInt8 DEFAULT 3,
    threat_score_threshold UInt8 DEFAULT 50,
    updated_at DateTime DEFAULT now(),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Pending Bans
CREATE TABLE vigilance_x.pending_bans (
    id UUID DEFAULT generateUUIDv4(),
    ip IPv4,
    country LowCardinality(String),
    geo_zone LowCardinality(String),
    threat_score Int32,
    threat_sources Array(String),
    event_count UInt32,
    first_event DateTime,
    last_event DateTime,
    trigger_rule String,
    reason String,
    status LowCardinality(String),
    created_at DateTime DEFAULT now(),
    reviewed_at Nullable(DateTime),
    reviewed_by String DEFAULT '',
    review_note String DEFAULT ''
) ENGINE = ReplacingMergeTree()
ORDER BY (ip, created_at);

-- CrowdSec Blocklist IPs
CREATE TABLE vigilance_x.crowdsec_blocklist_ips (
    ip String,
    blocklist_id String,
    blocklist_label String,
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),
    country_code LowCardinality(String) DEFAULT '',
    version UInt64 DEFAULT 1
) ENGINE = ReplacingMergeTree(version)
ORDER BY (blocklist_id, ip);

-- Retention Settings
CREATE TABLE vigilance_x.retention_settings (
    id UInt8 DEFAULT 1,
    retention_enabled UInt8 DEFAULT 0,
    events_days UInt32 DEFAULT 30,
    modsec_logs_days UInt32 DEFAULT 30,
    firewall_events_days UInt32 DEFAULT 30,
    vpn_events_days UInt32 DEFAULT 30,
    heartbeat_events_days UInt32 DEFAULT 30,
    atp_events_days UInt32 DEFAULT 90,
    antivirus_events_days UInt32 DEFAULT 90,
    ban_history_days UInt32 DEFAULT 365,
    audit_log_days UInt32 DEFAULT 365,
    cleanup_interval_hours UInt32 DEFAULT 24,
    last_cleanup DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- API Provider Config
CREATE TABLE vigilance_x.api_provider_config (
    provider_id String,
    provider_name String,
    api_key String DEFAULT '',
    enabled UInt8 DEFAULT 1,
    daily_quota Int32 DEFAULT -1,
    rate_limit_per_min Int32 DEFAULT -1,
    last_success Nullable(DateTime),
    last_error Nullable(DateTime),
    last_error_message String DEFAULT '',
    updated_at DateTime DEFAULT now(),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY provider_id;

-- API Usage Daily
CREATE TABLE vigilance_x.api_usage_daily (
    date Date,
    provider_id String,
    success_count UInt64 DEFAULT 0,
    error_count UInt64 DEFAULT 0,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY (date, provider_id);

-- Vigimail Domains
CREATE TABLE vigilance_x.vigimail_domains (
    id UUID DEFAULT generateUUIDv4(),
    domain String,
    dns_score Int32 DEFAULT 0,
    spf_valid UInt8 DEFAULT 0,
    dkim_valid UInt8 DEFAULT 0,
    dmarc_valid UInt8 DEFAULT 0,
    mx_valid UInt8 DEFAULT 0,
    dnssec_valid UInt8 DEFAULT 0,
    last_dns_check Nullable(DateTime),
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Vigimail Emails
CREATE TABLE vigilance_x.vigimail_emails (
    id UUID DEFAULT generateUUIDv4(),
    domain_id UUID,
    email String,
    leak_count UInt32 DEFAULT 0,
    last_check Nullable(DateTime),
    created_at DateTime DEFAULT now(),
    updated_at DateTime DEFAULT now(),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Vigimail Leaks
CREATE TABLE vigilance_x.vigimail_leaks (
    id UUID DEFAULT generateUUIDv4(),
    email_id UUID,
    breach_name String,
    breach_date Nullable(Date),
    data_classes Array(String),
    source LowCardinality(String),
    discovered_at DateTime DEFAULT now()
) ENGINE = MergeTree()
ORDER BY (email_id, discovered_at);

-- Users
CREATE TABLE vigilance_x.users (
    id UUID DEFAULT generateUUIDv4(),
    username String,
    email String,
    password_hash String,
    role LowCardinality(String),
    created_at DateTime DEFAULT now(),
    last_login Nullable(DateTime),
    is_active UInt8 DEFAULT 1,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY id;

-- Audit Log
CREATE TABLE vigilance_x.audit_log (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    user_id String,
    username String,
    action String,
    resource String,
    details String,
    ip_address String
) ENGINE = MergeTree()
ORDER BY timestamp
PARTITION BY toYYYYMM(timestamp);
```

---

## Entities Go

### BanStatus

```go
type BanStatus struct {
    IP               string     `json:"ip"`
    IsBanned         bool       `json:"is_banned"`
    BanReason        string     `json:"ban_reason"`
    BannedAt         time.Time  `json:"banned_at"`
    BannedUntil      *time.Time `json:"banned_until,omitempty"`
    BannedBy         string     `json:"banned_by"`
    Source           string     `json:"source"`
    ThreatScore      int        `json:"threat_score"`
    ImmuneUntil      *time.Time `json:"immune_until,omitempty"`
    // D2B v2 fields
    CurrentTier      uint8      `json:"current_tier"`
    ConditionalUntil *time.Time `json:"conditional_until,omitempty"`
    GeoZone          string     `json:"geo_zone"`
    ThreatScoreAtBan int        `json:"threat_score_at_ban"`
    XGSGroup         string     `json:"xgs_group"`
    // Enriched (not stored)
    Country          string     `json:"country,omitempty"`
}
```

### GeoZoneConfig

```go
type GeoZoneConfig struct {
    ID                   uint8    `json:"id"`
    Enabled              bool     `json:"enabled"`
    AuthorizedCountries  []string `json:"authorized_countries"`
    HostileCountries     []string `json:"hostile_countries"`
    DefaultPolicy        string   `json:"default_policy"`
    WAFThresholdHzone    int      `json:"waf_threshold_hzone"`
    WAFThresholdZone     int      `json:"waf_threshold_zone"`
    ThreatScoreThreshold int      `json:"threat_score_threshold"`
    UpdatedAt            time.Time `json:"updated_at"`
}
```

### PendingBan

```go
type PendingBan struct {
    ID            string     `json:"id"`
    IP            string     `json:"ip"`
    Country       string     `json:"country"`
    GeoZone       string     `json:"geo_zone"`
    ThreatScore   int        `json:"threat_score"`
    ThreatSources []string   `json:"threat_sources"`
    EventCount    uint32     `json:"event_count"`
    FirstEvent    time.Time  `json:"first_event"`
    LastEvent     time.Time  `json:"last_event"`
    TriggerRule   string     `json:"trigger_rule"`
    Reason        string     `json:"reason"`
    Status        string     `json:"status"`
    CreatedAt     time.Time  `json:"created_at"`
    ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
    ReviewedBy    string     `json:"reviewed_by"`
    ReviewNote    string     `json:"review_note"`
}
```

### ThreatScore

```go
type ThreatScore struct {
    IP              string    `json:"ip"`
    AggregatedScore float64   `json:"aggregated_score"`
    ThreatLevel     string    `json:"threat_level"`
    IsMalicious     bool      `json:"is_malicious"`
    Sources         []string  `json:"sources"`
    Categories      []string  `json:"categories"`
    LastChecked     time.Time `json:"last_checked"`
}
```

### Event

```go
type Event struct {
    ID          string    `json:"id"`
    Timestamp   time.Time `json:"timestamp"`
    SrcIP       string    `json:"src_ip"`
    DstIP       string    `json:"dst_ip"`
    SrcPort     uint16    `json:"src_port"`
    DstPort     uint16    `json:"dst_port"`
    LogType     string    `json:"log_type"`
    LogSubtype  string    `json:"log_subtype"`
    Severity    string    `json:"severity"`
    Action      string    `json:"action"`
    Category    string    `json:"category"`
    RuleID      string    `json:"rule_id"`
    Message     string    `json:"message"`
    CountryCode string    `json:"country_code"`
    Latitude    float64   `json:"latitude"`
    Longitude   float64   `json:"longitude"`
}
```

### WhitelistEntry

```go
type WhitelistEntry struct {
    IP        string     `json:"ip"`
    Level     string     `json:"level"`
    Reason    string     `json:"reason"`
    AddedBy   string     `json:"added_by"`
    AddedAt   time.Time  `json:"added_at"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
```

### NotificationSettings

```go
type NotificationSettings struct {
    SMTPEnabled         bool     `json:"smtp_enabled"`
    SMTPHost            string   `json:"smtp_host"`
    SMTPPort            int      `json:"smtp_port"`
    SMTPUser            string   `json:"smtp_user"`
    SMTPPassword        string   `json:"smtp_password"`
    SMTPFrom            string   `json:"smtp_from"`
    SMTPSecurity        string   `json:"smtp_security"`
    AlertsEnabled       bool     `json:"alerts_enabled"`
    AlertRecipients     []string `json:"alert_recipients"`
    AlertSeverity       string   `json:"alert_severity"`
    WAFDetectionAlert   bool     `json:"waf_detection_alert"`
    WAFBlockedAlert     bool     `json:"waf_blocked_alert"`
    NewBanAlert         bool     `json:"new_ban_alert"`
    CriticalEventAlert  bool     `json:"critical_event_alert"`
    ReportsEnabled      bool     `json:"reports_enabled"`
    ReportRecipients    []string `json:"report_recipients"`
    DailyReportEnabled  bool     `json:"daily_report_enabled"`
    DailyReportTime     string   `json:"daily_report_time"`
    WeeklyReportEnabled bool     `json:"weekly_report_enabled"`
    WeeklyReportDay     string   `json:"weekly_report_day"`
    MonthlyReportEnabled bool    `json:"monthly_report_enabled"`
}
```

---

## Types TypeScript

### BanStatus

```typescript
interface BanStatus {
  ip: string
  is_banned: boolean
  ban_reason: string
  banned_at: string
  banned_until?: string
  banned_by: string
  source: string
  threat_score: number
  immune_until?: string
  current_tier: number
  conditional_until?: string
  geo_zone: string
  threat_score_at_ban: number
  xgs_group: string
  country?: string
}
```

### GeoZoneConfig

```typescript
interface GeoZoneConfig {
  id: number
  enabled: boolean
  authorized_countries: string[]
  hostile_countries: string[]
  default_policy: 'authorized' | 'hostile' | 'neutral'
  waf_threshold_hzone: number
  waf_threshold_zone: number
  threat_score_threshold: number
  updated_at: string
}
```

### ThreatScore

```typescript
interface ThreatScore {
  ip: string
  aggregated_score: number
  threat_level: 'critical' | 'high' | 'medium' | 'low' | 'minimal'
  is_malicious: boolean
  sources: string[]
  categories: string[]
  last_checked: string
}
```

### TrackIPResponse

```typescript
interface TrackIPResponse {
  query: string
  query_type: 'ip' | 'hostname'
  resolved_ip?: string
  period: string
  geo_info?: {
    country: string
    country_code: string
    city: string
    region: string
    isp: string
    org: string
    as_number: string
    as_name: string
    latitude: number
    longitude: number
  }
  summary: {
    total_events: number
    severity_breakdown: Record<string, number>
    earliest_event?: string
    latest_event?: string
  }
  categories: {
    events?: { count: number; events: Event[] }
    waf?: { count: number; events: WAFEvent[] }
    modsec?: { count: number; events: ModSecLog[] }
    firewall?: { count: number; events: FirewallEvent[] }
    vpn?: { count: number; events: VPNEvent[] }
    atp?: { count: number; events: ATPEvent[] }
    antivirus?: { count: number; events: AntivirusEvent[] }
    heartbeat?: { count: number; events: HeartbeatEvent[] }
  }
}
```

---

## Variables d'Environnement

### Sophos XGS

```bash
SOPHOS_HOST=10.x.x.x           # IP du firewall
SOPHOS_PORT=4444               # Port API XML
SOPHOS_USER=admin              # Username API
SOPHOS_PASSWORD=xxx            # Password API
SOPHOS_SSH_HOST=10.x.x.x       # IP SSH (ModSec sync)
SOPHOS_SSH_PORT=22             # Port SSH
SOPHOS_SSH_USER=admin          # User SSH
SOPHOS_SSH_KEY_PATH=/ssh/id_rsa # Cle privee SSH
```

### Database

```bash
CLICKHOUSE_HOST=clickhouse     # Hostname ClickHouse
CLICKHOUSE_PORT=9000           # Port native
CLICKHOUSE_DATABASE=vigilance_x
CLICKHOUSE_USER=vigilance
CLICKHOUSE_PASSWORD=xxx
REDIS_HOST=redis               # Hostname Redis
REDIS_PORT=6379
```

### Authentication

```bash
JWT_SECRET=min-32-chars-secret # Secret JWT (min 32 chars)
JWT_EXPIRY=24h                 # Duree token
ADMIN_USERNAME=admin           # User initial
ADMIN_PASSWORD=VigilanceX2024! # Password initial
```

### License

```bash
LICENSE_ENABLED=true
LICENSE_SERVER_URL=https://vgxkey.vigilancex.lu
LICENSE_KEY=VX3-XXXX-XXXX-XXXX-XXXX
LICENSE_GRACE_PERIOD=168h      # 7 jours
LICENSE_INSECURE_SKIP_VERIFY=false  # Pour certificats self-signed
```

### Threat Intelligence

```bash
ABUSEIPDB_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
GREYNOISE_API_KEY=xxx
CROWDSEC_API_KEY=xxx
PULSEDIVE_API_KEY=xxx
CRIMINALIP_API_KEY=xxx
OTX_API_KEY=xxx
ABUSECH_API_KEY=xxx            # ThreatFox + URLhaus
```

### Notifications

```bash
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=alerts@domain.com
SMTP_PASSWORD=xxx
SMTP_FROM=alerts@domain.com
SMTP_SECURITY=starttls         # none/ssl/starttls
```

### Vigimail

```bash
HIBP_API_KEY=xxx               # Have I Been Pwned API
LEAKCHECK_API_KEY=xxx          # LeakCheck.io API
```

---

## Threat Intelligence Providers

### Tiers de Cascade

| Tier | Providers | Quota | Seuil Activation |
|------|-----------|-------|------------------|
| **Tier 1** (Free) | IPSum, OTX, ThreatFox, URLhaus, Shodan InternetDB | Illimite | Toujours |
| **Tier 2** | AbuseIPDB, GreyNoise, CrowdSec CTI | Modere | Score > 30 |
| **Tier 3** | VirusTotal, CriminalIP, Pulsedive | Limite | Score > 60 |

### Quotas par Provider

| Provider | Quota | Needs API Key |
|----------|-------|---------------|
| AbuseIPDB | 1000/day | Yes |
| VirusTotal | 500/day | Yes |
| GreyNoise | 500/day | Yes |
| CrowdSec CTI | 50/day | Yes |
| Pulsedive | 100/day | Yes |
| CriminalIP | 100/day | Yes |
| AlienVault OTX | Unlimited | Yes |
| IPsum | Unlimited | No |
| Shodan InternetDB | Unlimited | No |
| ThreatFox | Unlimited | Yes |
| URLhaus | Unlimited | Yes |

### Score Agrege

```go
// Calcul du score agrege (0-100)
AggregatedScore = weighted_average(provider_scores)

// Niveaux de menace
ThreatLevel:
  - critical: score >= 80
  - high:     score >= 60
  - medium:   score >= 40
  - low:      score >= 20
  - minimal:  score < 20
```

---

## Systeme de Licence VX3

### Binding Hardware

```
VX3 Hardware ID = SHA256("VX3:" + machine_id + ":" + firewall_serial)
```

- **machine_id**: UUID de la VM (/etc/machine-id)
- **firewall_serial**: Extrait des logs Sophos XGS

### Statuts Licence

| Status | Description | Duree |
|--------|-------------|-------|
| `FDEPLOY` | Fresh deploy, attente XGS | 15 jours |
| `TRIAL` | XGS connecte, trial valide | 15 jours |
| `ASKED` | Demande Pro soumise | Jusqu'a action admin |
| `ACTIVE` | Pro licence active | Config admin |
| `EXPIRED` | Licence expiree | - |
| `REVOKED` | Revoquee par admin | - |

### Grace Period

- Duree: 7 jours (168h)
- Active si serveur de licence injoignable
- Fonctionnalites completes maintenues

### Workflow Fresh Deploy

```
Installation -> Login -> Email + Generate Trial (15j) -> FDEPLOY
                                    |
                    [Sync auto 12h ou manuel]
                                    |
                    XGS detecte -> FWID envoye -> TRIAL valide
                                    |
                    "Ask Pro License" -> ASKED -> Admin approuve -> ACTIVE
```

---

## Integrations Sophos XGS

### Ports et Protocoles

| Service | Port | Protocole | Usage |
|---------|------|-----------|-------|
| Syslog | 514/UDP, 1514/TCP | Syslog | Reception logs |
| API XML | 4444 | HTTPS | Ban/Unban IPs |
| SSH | 22 | SSH | Sync ModSecurity rules |

### Groupes IP Sophos

| Groupe | Usage |
|--------|-------|
| `grp_VGX-BannedIP` | Bans temporaires (Tier 0-2) |
| `grp_VGX-BannedPerm` | Bans permanents (Tier 3+) |
| `grp_VGX-CrowdSBlockL` | IPs CrowdSec Blocklist |

### Format Host Name

```
Ban temporaire: VGX_1.2.3.4
Ban permanent:  VGX_1.2.3.4
CrowdSec:       CS_1.2.3.4
```

---

## CrowdSec Neural-Sync

### Architecture ProxyAPI

```
VigilanceKey Server (10.56.126.126:8080)
        │
        │ Download from CrowdSec API (every 2h)
        │ Store in /data/blocklists/{id}.txt
        ▼
┌───────────────────────────────────────┐
│ VGX Clients                           │
│ GET /api/v1/blocklist/lists           │
│ GET /api/v1/blocklist/{id}/download   │
│ Headers: X-License-Key, X-Hardware-ID │
└───────────────────────────────────────┘
        │
        │ Process locally
        ▼
  Sync to ClickHouse → Enrich GeoIP → Sync to XGS
```

### Endpoints VigilanceKey (ProxyAPI)

```
# For VGX Clients (License-Protected)
GET  /api/v1/blocklist/lists           # Liste blocklists
GET  /api/v1/blocklist/{id}/download   # Download IPs (text/plain)
GET  /api/v1/blocklist/status          # Status sync

# For Admin (JWT + Operator)
GET  /api/v1/admin/blocklist/config    # Configuration
PUT  /api/v1/admin/blocklist/config    # Update config
POST /api/v1/admin/blocklist/sync      # Force sync
```

---

## Detect2Ban Engine

### Scenarios YAML

```yaml
# backend/scenarios/waf_attacks.yaml
name: waf_attacks
description: Ban IPs with multiple WAF events
query: |
  SELECT src_ip, count() as event_count
  FROM vigilance_x.events
  WHERE timestamp > now() - INTERVAL 5 MINUTE
    AND log_type = 'WAF'
  GROUP BY src_ip
  HAVING event_count >= 5
threshold: 5
window: 5m
validate_threat: false
action: ban

# backend/scenarios/brute_force.yaml
name: brute_force
description: Ban IPs with authentication failures
query: |
  SELECT src_ip, count() as event_count
  FROM vigilance_x.events
  WHERE timestamp > now() - INTERVAL 10 MINUTE
    AND category = 'authentication'
    AND action = 'deny'
  GROUP BY src_ip
  HAVING event_count >= 10
threshold: 10
window: 10m
validate_threat: true
action: ban
```

### Flux de Decision D2B v2

```
WAF Event Detected
        │
        ▼
Classify IP GeoZone (country → zone)
        │
   ┌────┴────┬────────────┐
   ▼         ▼            ▼
HOSTILE   NEUTRAL    AUTHORIZED
   │         │            │
   ▼         ▼            ▼
1 event?  3+ events?  3+ events?
BAN NOW   BAN AUTO    TI CHECK
                          │
                    ┌─────┴─────┐
                    ▼           ▼
               Score ≥ 50   Score < 50
               BAN AUTO     PENDING APPROVAL
```

### Tiers de Ban (Recidivisme)

| Tier | Duree | Condition | Groupe XGS |
|------|-------|-----------|------------|
| 0 | 4 heures | Premier ban | grp_VGX-BannedIP |
| 1 | 24 heures | 1ere recidive | grp_VGX-BannedIP |
| 2 | 7 jours | 2eme recidive | grp_VGX-BannedIP |
| 3+ | Permanent | 3+ recidives | grp_VGX-BannedPerm |

---

## Log Retention

### Comportement par Defaut

> **VGX NE SUPPRIME JAMAIS DE DONNEES AUTOMATIQUEMENT PAR DEFAUT**

| Parametre | Valeur par defaut |
|-----------|-------------------|
| `retention_enabled` | **false** |
| Periodes de retention | Pre-configurees mais inactives |

### Periodes Suggerees

| Table | Retention |
|-------|-----------|
| `events` | 30 jours |
| `modsec_logs` | 30 jours |
| `firewall_events` | 30 jours |
| `vpn_events` | 30 jours |
| `heartbeat_events` | 30 jours |
| `atp_events` | 90 jours |
| `antivirus_events` | 90 jours |
| `ban_history` | 365 jours |
| `audit_log` | 365 jours |

---

## Vigimail Checker

### Fonctionnalites

- Gestion multi-domaines avec emails associes
- Detection de leaks via HIBP + LeakCheck
- Verification DNS: SPF, DKIM, DMARC, MX, DNSSEC
- Score global securite domaine (0-100)
- Worker background configurable (6h/12h/24h/48h/7d)

### Score DNS

```
Score = 20 * (SPF + DKIM + DMARC + MX + DNSSEC)
- SPF valid: +20
- DKIM valid: +20
- DMARC valid: +20
- MX valid: +20
- DNSSEC valid: +20
Total: 0-100
```

---

## Backups

### Paths

| Serveur | Path | Contenu |
|---------|------|---------|
| **vigilanceX** (10.25.72.28) | `/opt/vigilanceX/backups/` | ClickHouse, Redis, code |
| **vigilanceKey** (10.56.126.126) | `/opt/vigilanceKey/backups/` | PostgreSQL, code |

### Fichiers de Backup

**vigilanceX:**
- `clickhouse_YYYYMMDD_HHMMSS.tar.gz` - Donnees ClickHouse
- `redis_YYYYMMDD_HHMMSS.rdb` - Snapshot Redis
- `vigilanceX_code_YYYYMMDD_HHMMSS.tar.gz` - Code source

**vigilanceKey:**
- `postgres_YYYYMMDD_HHMMSS.sql.gz` - Dump PostgreSQL
- `vigilancekey_code_YYYYMMDD_HHMMSS.tar.gz` - Code source

### Scripts

```bash
# Backup vigilanceX (ClickHouse + Redis)
/opt/vigilanceX/scripts/backup.sh

# Backup to Forgejo (Git)
/opt/vigilanceX/scripts/backup-to-forgejo.sh --all
```

### Retention

Les backups sont conserves avec rotation automatique (7 derniers).

---

*Reference technique VIGILANCE X - Maintenir synchronise avec CLAUDE.md*
