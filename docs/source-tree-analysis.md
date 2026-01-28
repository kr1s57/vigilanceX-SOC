# Analyse de l'Arborescence Source

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

Structure complète du projet VIGILANCE X avec annotations.

---

## Arborescence Racine

```
/opt/vigilanceX/
├── backend/                 # API Go (Clean Architecture)
├── frontend/                # React SPA
├── docker/                  # Docker Compose + configs
├── docs/                    # Documentation générée
├── scripts/                 # Scripts utilitaires
├── backups/                 # Sauvegardes (exclu git)
├── client-dist/             # Distribution client (wiki)
├── .claude/                 # Configuration Claude Code
├── .github/                 # GitHub Actions
├── _bmad/                   # BMAD framework
├── CLAUDE.md                # Mémoire Claude Code
├── TECHNICAL_REFERENCE.md   # Référence technique
├── CHANGELOG.md             # Historique versions
└── README.md                # Documentation principale
```

---

## Backend (`/backend/`)

### Structure

```
backend/
├── cmd/                         # Points d'entrée
│   ├── api/
│   │   └── main.go             # Serveur API principal (~1200 lignes)
│   ├── detect2ban/
│   │   └── main.go             # Moteur D2B standalone
│   ├── reset-password/
│   │   └── main.go             # Utilitaire CLI reset password
│   └── sophos-parser/
│       └── main.go             # Parser logs XGS CLI
│
├── internal/                    # Code privé (Clean Architecture)
│   ├── adapter/                 # Couche externe
│   │   ├── controller/
│   │   │   ├── http/
│   │   │   │   ├── handlers/   # 25+ handlers API
│   │   │   │   │   ├── auth.go
│   │   │   │   │   ├── bans.go
│   │   │   │   │   ├── config.go
│   │   │   │   │   ├── console.go
│   │   │   │   │   ├── crowdsec_blocklist.go
│   │   │   │   │   ├── detect2ban.go
│   │   │   │   │   ├── events.go
│   │   │   │   │   ├── geoblocking.go
│   │   │   │   │   ├── geozone.go
│   │   │   │   │   ├── license.go
│   │   │   │   │   ├── modsec.go
│   │   │   │   │   ├── neural_sync.go
│   │   │   │   │   ├── notifications.go
│   │   │   │   │   ├── parser.go
│   │   │   │   │   ├── pending_bans.go
│   │   │   │   │   ├── reports.go
│   │   │   │   │   ├── retention.go
│   │   │   │   │   ├── stubs.go
│   │   │   │   │   ├── threats.go
│   │   │   │   │   ├── trackip.go
│   │   │   │   │   ├── update.go
│   │   │   │   │   ├── users.go
│   │   │   │   │   ├── vigimail.go
│   │   │   │   │   └── waf_servers.go
│   │   │   │   └── middleware/
│   │   │   │       ├── admin.go
│   │   │   │       ├── jwt.go
│   │   │   │       ├── license.go
│   │   │   │       ├── logger.go
│   │   │   │       └── security.go
│   │   │   └── ws/
│   │   │       └── hub.go      # WebSocket hub
│   │   │
│   │   ├── repository/
│   │   │   └── clickhouse/     # 18 repositories
│   │   │       ├── connection.go
│   │   │       ├── events_repo.go
│   │   │       ├── modsec_repo.go
│   │   │       ├── bans_repo.go
│   │   │       ├── threats_repo.go
│   │   │       ├── users_repo.go
│   │   │       ├── geozone_repo.go
│   │   │       ├── geoblocking_repo.go
│   │   │       ├── blocklist_repo.go
│   │   │       ├── crowdsec_blocklist_repo.go
│   │   │       ├── vigimail_repo.go
│   │   │       ├── trackip_repo.go
│   │   │       ├── waf_servers_repo.go
│   │   │       ├── retention_repo.go
│   │   │       ├── api_usage_repo.go
│   │   │       ├── stats_repo.go
│   │   │       ├── anomalies_repo.go
│   │   │       └── system_whitelist_repo.go
│   │   │
│   │   ├── external/           # Clients externes
│   │   │   ├── blocklist/      # Feed ingester
│   │   │   ├── crowdsec/       # CrowdSec client
│   │   │   ├── geoip/          # GeoIP2 client
│   │   │   ├── geolocation/    # Geolocation service
│   │   │   ├── smtp/           # SMTP client
│   │   │   ├── sophos/         # Sophos XGS client (API XML)
│   │   │   ├── threatintel/    # TI aggregator (11 providers)
│   │   │   └── vigimail/       # HIBP/LeakCheck clients
│   │   │
│   │   └── parser/
│   │       └── sophos/         # XGS log parser
│   │
│   ├── config/
│   │   └── config.go           # Configuration Viper
│   │
│   ├── domain/
│   │   └── ...                 # Logique domaine
│   │
│   ├── entity/                 # Modèles de données (12 fichiers)
│   │   ├── event.go
│   │   ├── ban.go
│   │   ├── user.go
│   │   ├── threat.go
│   │   ├── anomaly.go
│   │   ├── notification.go
│   │   ├── retention.go
│   │   ├── geoblocking.go
│   │   ├── trackip.go
│   │   ├── vigimail.go
│   │   ├── waf_server.go
│   │   └── system_whitelist.go
│   │
│   ├── license/                # Système de licence VX3
│   │   └── ...
│   │
│   └── usecase/                # Services métier (21 dossiers)
│       ├── auth/
│       ├── bans/
│       ├── events/
│       ├── threats/
│       ├── detect2ban/
│       ├── modsec/
│       ├── reports/
│       ├── notifications/
│       ├── geoblocking/
│       ├── blocklists/
│       ├── crowdsec/
│       ├── vigimail/
│       ├── trackip/
│       ├── retention/
│       ├── anomalies/
│       ├── archiver/
│       ├── apiusage/
│       ├── geoenrich/
│       └── wafwatcher/
│
├── scenarios/                   # Scénarios Detect2Ban (YAML)
│   └── ...
│
├── Dockerfile                   # Build image
├── go.mod                       # Dépendances Go
└── go.sum
```

### Métriques Backend

| Métrique | Valeur |
|----------|--------|
| **Fichiers Go** | ~80 |
| **Lignes de code** | ~15,000 |
| **Handlers API** | 25+ |
| **Repositories** | 18 |
| **Use Cases** | 21 |
| **Entités** | 12 |

---

## Frontend (`/frontend/`)

### Structure

```
frontend/
├── src/
│   ├── App.tsx                  # Router principal
│   ├── main.tsx                 # Point d'entrée
│   ├── index.css                # Styles globaux (64KB)
│   ├── vite-env.d.ts
│   │
│   ├── pages/                   # 20 pages
│   │   ├── Dashboard.tsx        # 27KB
│   │   ├── WafExplorer.tsx      # 45KB
│   │   ├── AttacksAnalyzer.tsx  # 51KB
│   │   ├── AdvancedThreat.tsx   # 18KB
│   │   ├── ActiveBans.tsx       # 46KB
│   │   ├── SoftWhitelist.tsx    # 36KB
│   │   ├── Geoblocking.tsx      # 36KB
│   │   ├── AttackMap.tsx        # 25KB
│   │   ├── TrackIP.tsx          # 39KB
│   │   ├── NeuralSync.tsx       # 19KB
│   │   ├── CrowdSecBL.tsx       # 31KB
│   │   ├── VigimailChecker.tsx  # 44KB
│   │   ├── VpnNetwork.tsx       # 27KB
│   │   ├── RiskScoring.tsx      # 20KB
│   │   ├── Reports.tsx          # 25KB
│   │   ├── Settings.tsx         # 132KB (!)
│   │   ├── UserManagement.tsx   # 24KB
│   │   ├── Login.tsx            # 8KB
│   │   └── LicenseActivation.tsx# 19KB
│   │
│   ├── components/
│   │   ├── ui/                  # Composants Radix (Shadcn style)
│   │   │   ├── button.tsx
│   │   │   ├── card.tsx
│   │   │   ├── dialog.tsx
│   │   │   ├── dropdown-menu.tsx
│   │   │   ├── input.tsx
│   │   │   ├── select.tsx
│   │   │   ├── table.tsx
│   │   │   ├── tabs.tsx
│   │   │   ├── toast.tsx
│   │   │   └── ...
│   │   ├── layout/
│   │   │   └── Sidebar.tsx
│   │   ├── dashboard/
│   │   ├── charts/
│   │   ├── attackmap/
│   │   ├── settings/
│   │   ├── AdminRoute.tsx
│   │   ├── ProtectedRoute.tsx
│   │   ├── CountrySelector.tsx
│   │   ├── IPThreatModal.tsx
│   │   ├── Logo.tsx
│   │   ├── PendingApprovalDetailModal.tsx
│   │   ├── TerminalConsole.tsx
│   │   └── WAFServerModal.tsx
│   │
│   ├── contexts/                # React Context (3)
│   │   ├── AuthContext.tsx
│   │   ├── LicenseContext.tsx
│   │   └── SettingsContext.tsx
│   │
│   ├── stores/                  # Zustand stores (4)
│   │   ├── index.ts
│   │   ├── bansStore.ts
│   │   ├── eventsStore.ts
│   │   ├── attackMapStore.ts
│   │   └── alertsStore.ts
│   │
│   ├── hooks/
│   │   └── ...
│   │
│   ├── lib/
│   │   ├── api.ts               # Client Axios
│   │   └── utils.ts
│   │
│   └── types/
│       └── ...
│
├── public/
│   └── ...                      # Assets statiques
│
├── dist/                        # Build production
│
├── Dockerfile
├── Dockerfile.release
├── nginx.conf
├── package.json
├── package-lock.json
├── vite.config.ts
├── tailwind.config.js
├── tsconfig.json
├── tsconfig.node.json
├── postcss.config.js
└── eslint.config.js
```

### Métriques Frontend

| Métrique | Valeur |
|----------|--------|
| **Pages** | 20 |
| **Composants** | ~40 |
| **Taille pages** | 8KB - 132KB |
| **Plus gros fichier** | Settings.tsx (132KB) |
| **Stores Zustand** | 4 |
| **Contexts** | 3 |

---

## Docker (`/docker/`)

### Structure

```
docker/
├── docker-compose.yml           # Compose principal
├── docker-compose.prod.yml      # Compose production
├── docker-compose.yml.public    # Compose public (sanitized)
├── .env                         # Variables (gitignored)
├── .env.example                 # Template variables
├── .gitignore
│
├── clickhouse/
│   └── init-db.sql              # Schéma ClickHouse
│
├── vector/
│   └── vector.toml              # Config Vector (Syslog parser)
│
├── nginx/
│   ├── nginx.conf               # Config Nginx
│   └── ssl/                     # Certificats SSL
│
├── ssh/
│   └── id_rsa_xgs               # Clé SSH Sophos (gitignored)
│
└── data/                        # Données persistantes (gitignored)
```

---

## Configuration Claude (`.claude/`)

```
.claude/
├── settings.json                # Paramètres Claude Code
└── skills/                      # 36 skills personnalisés
    ├── gitgo/
    ├── version-bump/
    ├── backend-build/
    ├── frontend-build/
    ├── docker-deploy/
    ├── bugfix/
    ├── feature/
    ├── code-review/
    ├── waf-security/
    ├── threat-hunting/
    ├── forensics/
    └── ...
```

---

## Fichiers Critiques

### Configuration

| Fichier | Description |
|---------|-------------|
| `/docker/.env` | Variables d'environnement |
| `/backend/go.mod` | Dépendances Go |
| `/frontend/package.json` | Dépendances Node |
| `/docker/clickhouse/init-db.sql` | Schéma base de données |
| `/docker/vector/vector.toml` | Config ingestion Syslog |

### Points d'Entrée

| Fichier | Description |
|---------|-------------|
| `/backend/cmd/api/main.go` | Serveur API (~1200 lignes) |
| `/frontend/src/main.tsx` | Entrée React |
| `/frontend/src/App.tsx` | Router principal |

### Versioning

| Fichier | Variable |
|---------|----------|
| `/frontend/src/pages/Dashboard.tsx` | INSTALLED_VERSION |
| `/frontend/src/pages/Settings.tsx` | Footer version |
| `/frontend/src/pages/Login.tsx` | Footer version |
| `/frontend/src/pages/LicenseActivation.tsx` | Footer version |
| `/backend/.../handlers/update.go` | InstalledVersion |
| `/CLAUDE.md` | Header version |

---

## Exclusions Git

### Fichiers Ignorés

```gitignore
# Dependencies
node_modules/
vendor/

# Build
dist/
*.exe

# Environment
.env
.env.local
.env.production

# Secrets
*.pem
*.key
id_rsa*
credentials.json

# Data
data/
backups/

# IDE
.idea/
.vscode/
```

### Fichiers Publics Exclus

```
CLAUDE.md
TECHNICAL_REFERENCE.md
CHANGELOG.md
docs/
BUGFIXSESSION/
FEATURESPROMPT/
.github/
.claude/
backups/
```

---

*Documentation générée par le workflow document-project*
