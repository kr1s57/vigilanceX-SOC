# Architecture Backend - Go API

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

Le backend VIGILANCE X suit une **Clean Architecture** stricte avec séparation claire des responsabilités.

```
backend/
├── cmd/                    # Points d'entrée
│   ├── api/               # Serveur API principal
│   ├── detect2ban/        # Moteur D2B standalone
│   ├── reset-password/    # Utilitaire CLI
│   └── sophos-parser/     # Parser logs XGS
├── internal/              # Code privé
│   ├── adapter/           # Couche externe
│   ├── config/            # Configuration
│   ├── domain/            # Logique domaine
│   ├── entity/            # Modèles de données
│   ├── license/           # Système de licence
│   └── usecase/           # Services métier
├── scenarios/             # Scénarios D2B (YAML)
└── Dockerfile
```

---

## Clean Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frameworks & Drivers                  │
│  (Chi Router, ClickHouse, Redis, Sophos API, HTTP)          │
├─────────────────────────────────────────────────────────────┤
│                          Adapters                            │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │   Controllers    │  │   Repositories   │                 │
│  │   (HTTP/WS)      │  │   (ClickHouse)   │                 │
│  └──────────────────┘  └──────────────────┘                 │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │    External      │  │     Parser       │                 │
│  │    (TI, Sophos)  │  │    (Sophos XGS)  │                 │
│  └──────────────────┘  └──────────────────┘                 │
├─────────────────────────────────────────────────────────────┤
│                         Use Cases                            │
│  (auth, bans, events, threats, detect2ban, reports...)      │
├─────────────────────────────────────────────────────────────┤
│                          Entities                            │
│  (Event, Ban, User, Threat, GeoZone, WhitelistEntry...)     │
└─────────────────────────────────────────────────────────────┘
```

---

## Structure Détaillée

### `/cmd/api/main.go`

Point d'entrée principal (~1200 lignes). Responsabilités:
- Chargement configuration (Viper)
- Initialisation connexions (ClickHouse, Redis)
- Création repositories et services
- Configuration routes Chi
- Middleware (CORS, JWT, Rate Limiting)
- Graceful shutdown

### `/internal/entity/`

Modèles de données (12 fichiers):

| Fichier | Entités |
|---------|---------|
| `event.go` | Event, ModSecLog, EventFilters, EventStats |
| `ban.go` | BanStatus, BanHistory, WhitelistEntry, GeoZoneConfig, PendingBan |
| `user.go` | User, UserRole |
| `threat.go` | ThreatScore, ThreatProvider |
| `anomaly.go` | Anomaly, AnomalyType |
| `notification.go` | Notification, SMTPConfig |
| `retention.go` | RetentionSettings |
| `geoblocking.go` | GeoBlockRule |
| `trackip.go` | TrackIPResult |
| `vigimail.go` | Domain, Email, Leak |
| `waf_server.go` | WAFServer, CountryPolicy |
| `system_whitelist.go` | SystemWhitelistEntry |

### `/internal/usecase/`

Services métier (21 dossiers):

| Service | Fichiers | Responsabilité |
|---------|----------|----------------|
| `auth/` | service.go, service_test.go | Authentification JWT |
| `bans/` | service.go, service_test.go | Gestion des bans |
| `events/` | service.go | Requêtes événements |
| `threats/` | service.go | Enrichissement TI |
| `detect2ban/` | engine.go | Moteur de détection |
| `modsec/` | service.go | Sync logs ModSec |
| `reports/` | service.go, pdf_generator.go | Génération rapports |
| `notifications/` | service.go, triggers.go | Alertes email |
| `geoblocking/` | service.go | Blocage géographique |
| `blocklists/` | service.go | Gestion feeds |
| `crowdsec/` | blocklist_service.go | Neural-Sync |
| `vigimail/` | service.go | Détection fuites |
| `trackip/` | service.go | Recherche forensique |
| `retention/` | service.go | Nettoyage logs |
| `anomalies/` | service.go | Détection anomalies |
| `archiver/` | service.go | Archivage SMB |
| `apiusage/` | service.go | Tracking quotas TI |
| `geoenrich/` | service.go | Enrichissement GeoIP |
| `wafwatcher/` | service.go | Surveillance WAF |

### `/internal/adapter/`

Implémentations concrètes:

```
adapter/
├── controller/
│   ├── http/
│   │   ├── handlers/     # 25+ handlers API
│   │   └── middleware/   # JWT, License, Admin, Logger
│   └── ws/
│       └── hub.go        # WebSocket hub
├── repository/
│   └── clickhouse/       # 18 repositories
├── external/
│   ├── blocklist/        # Feed ingester
│   ├── crowdsec/         # CrowdSec client
│   ├── geoip/            # GeoIP2 client
│   ├── geolocation/      # Geolocation service
│   ├── smtp/             # SMTP client
│   ├── sophos/           # Sophos XGS client
│   ├── threatintel/      # TI aggregator
│   └── vigimail/         # HIBP/LeakCheck clients
└── parser/
    └── sophos/           # XGS log parser
```

---

## Handlers API

### Authentification

| Handler | Fichier | Routes |
|---------|---------|--------|
| `AuthHandler` | auth.go | POST /login, /logout, /change-password |
| `UsersHandler` | users.go | CRUD /users |
| `LicenseHandler` | license.go | /license/* |

### Événements & Menaces

| Handler | Fichier | Routes |
|---------|---------|--------|
| `EventsHandler` | events.go | GET /events, /stats, /timeline |
| `ThreatsHandler` | threats.go | GET /threats, /check/{ip}, /risk/{ip} |
| `ModSecHandler` | modsec.go | GET /modsec/logs, /stats, POST /sync |

### Bans & Whitelist

| Handler | Fichier | Routes |
|---------|---------|--------|
| `BansHandler` | bans.go | CRUD /bans, /whitelist |
| `Detect2BanHandler` | detect2ban.go | /detect2ban/status, /enable |
| `PendingBansHandler` | pending_bans.go | /pending-bans/approve |
| `GeoZoneHandler` | geozone.go | /geozone/config |

### Fonctionnalités Avancées

| Handler | Fichier | Routes |
|---------|---------|--------|
| `BlocklistsHandler` | blocklists.go | /blocklists/sync |
| `GeoblockingHandler` | geoblocking.go | /geoblocking/rules |
| `CrowdSecBlocklistHandler` | crowdsec_blocklist.go | /crowdsec/blocklist/* |
| `NeuralSyncHandler` | neural_sync.go | /neural-sync/* |
| `VigimailHandler` | vigimail.go | /vigimail/* |
| `TrackIPHandler` | trackip.go | GET /track-ip |
| `WAFServersHandler` | waf_servers.go | /waf-servers/* |

### Système

| Handler | Fichier | Routes |
|---------|---------|--------|
| `ReportsHandler` | reports.go | /reports/generate |
| `NotificationHandler` | notifications.go | /notifications/settings |
| `RetentionHandler` | retention.go | /retention/settings |
| `ConfigHandler` | config.go | /config/* |
| `ConsoleHandler` | console.go | /console/execute |
| `UpdateHandler` | update.go | /system/update |
| `ParserHandler` | parser.go | /parser/stats |

---

## Repositories ClickHouse

| Repository | Table | Responsabilité |
|------------|-------|----------------|
| `events_repo.go` | events | Événements sécurité |
| `modsec_repo.go` | modsec_logs | Logs ModSecurity |
| `bans_repo.go` | bans, ban_history | Bans et historique |
| `threats_repo.go` | ip_threat_scores | Scores TI |
| `users_repo.go` | users | Utilisateurs |
| `geozone_repo.go` | geozone_config | Config GeoZone |
| `geoblocking_repo.go` | geoblocking_rules | Règles géoblocage |
| `blocklist_repo.go` | blocklist_entries | Feeds blocklist |
| `crowdsec_blocklist_repo.go` | crowdsec_blocklist | CrowdSec IPs |
| `vigimail_repo.go` | vigimail_* | Domains/emails |
| `trackip_repo.go` | (multi-tables) | Recherche forensique |
| `waf_servers_repo.go` | waf_servers | Serveurs WAF |
| `retention_repo.go` | retention_settings | Config rétention |
| `api_usage_repo.go` | api_usage | Quotas TI |
| `stats_repo.go` | (agrégations) | Statistiques |
| `anomalies_repo.go` | anomalies | Anomalies |
| `system_whitelist_repo.go` | system_whitelist | Whitelist système |

---

## Middleware

| Middleware | Fichier | Fonction |
|------------|---------|----------|
| `JWTAuth` | jwt.go | Validation token JWT |
| `RequireLicense` | license.go | Vérification licence active |
| `RequireAdmin` | admin.go | Restriction rôle admin |
| `Logger` | logger.go | Logging structuré (slog) |
| `SecurityHeaders` | security.go | Headers OWASP |

---

## Services Externes

### Threat Intelligence Aggregator

```go
// Configuration cascade
CascadeConfig{
    EnableCascade:    true,
    Tier2Threshold:   30,  // Score min pour activer Tier 2
    Tier3Threshold:   60,  // Score min pour activer Tier 3
}
```

### Sophos XGS Client

```go
// API XML pour gestion groupes IP
sophosClient := sophos.NewClient(sophos.Config{
    Host:      "10.x.x.x",
    Port:      4444,
    Username:  "admin",
    Password:  "***",
    GroupName: "grp_VGX-BannedIP",
})
```

---

## Dépendances Clés

| Package | Version | Usage |
|---------|---------|-------|
| github.com/go-chi/chi/v5 | 5.0.12 | HTTP router |
| github.com/ClickHouse/clickhouse-go/v2 | 2.23.0 | ClickHouse driver |
| github.com/golang-jwt/jwt/v5 | 5.2.1 | JWT tokens |
| github.com/gorilla/websocket | 1.5.1 | WebSocket |
| github.com/spf13/viper | 1.18.2 | Configuration |
| github.com/go-chi/httprate | - | Rate limiting |
| github.com/go-chi/cors | - | CORS |
| github.com/go-pdf/fpdf | 0.9.0 | PDF generation |
| github.com/hirochachacha/go-smb2 | 1.1.0 | SMB archiving |

---

*Documentation générée par le workflow document-project*
