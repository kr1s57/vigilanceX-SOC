# VIGILANCE X - Vue d'Ensemble du Projet

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Description

VIGILANCE X est une plateforme SOC (Security Operations Center) temps réel développée pour les entreprises utilisant des firewalls Sophos XGS. Elle collecte, analyse et répond automatiquement aux menaces de sécurité.

---

## Architecture Globale

```
┌─────────────────────────────────────────────────────────────────────┐
│                        VIGILANCE X Platform                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐       │
│  │   Sophos XGS  │────▶│    Vector     │────▶│   ClickHouse  │       │
│  │   Firewall    │     │   (Syslog)    │     │   (Analytics) │       │
│  └───────────────┘     └───────────────┘     └───────────────┘       │
│         │                                            │                │
│         │ XML API                                    │ SQL            │
│         ▼                                            ▼                │
│  ┌───────────────┐     ┌───────────────┐     ┌───────────────┐       │
│  │   Backend     │────▶│     Redis     │     │   Frontend    │       │
│  │   (Go API)    │     │    (Cache)    │     │   (React)     │       │
│  └───────────────┘     └───────────────┘     └───────────────┘       │
│         │                                            ▲                │
│         │ TI Enrichment                              │ WebSocket      │
│         ▼                                            │                │
│  ┌───────────────────────────────────────────────────┘               │
│  │  Threat Intelligence (11 providers)                               │
│  │  - Tier 1: OTX, ThreatFox, URLhaus, IPsum                        │
│  │  - Tier 2: AbuseIPDB, GreyNoise, CrowdSec                        │
│  │  - Tier 3: VirusTotal, CriminalIP, Pulsedive                     │
│  └───────────────────────────────────────────────────────────────────┘
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Parties du Projet

### Backend (`/opt/vigilanceX/backend/`)

| Attribut | Valeur |
|----------|--------|
| **Type** | API REST + Moteur de détection |
| **Langage** | Go 1.22 |
| **Architecture** | Clean Architecture |
| **Framework** | Chi Router v5 |
| **Binaires** | `api`, `detect2ban`, `reset-password`, `sophos-parser` |

**Responsabilités:**
- API REST pour le frontend (100+ endpoints)
- Moteur Detect2Ban (détection automatique, bans progressifs)
- Intégration Sophos XGS (API XML + SSH)
- Enrichissement Threat Intelligence (cascade 3 tiers)
- Synchronisation ModSecurity (logs WAF)
- WebSocket temps réel

### Frontend (`/opt/vigilanceX/frontend/`)

| Attribut | Valeur |
|----------|--------|
| **Type** | SPA (Single Page Application) |
| **Framework** | React 19 |
| **Build** | Vite 6 |
| **Styling** | Tailwind CSS 4 + Radix UI |
| **State** | Zustand + React Context |

**Pages principales (20):**
- Dashboard, WAF Explorer, Attacks Analyzer
- Advanced Threat, Active Bans, Soft Whitelist
- Geoblocking, Attack Map, Track IP
- Neural-Sync, Vigimail Checker, Reports
- Settings, User Management, Login

### Infrastructure (`/opt/vigilanceX/docker/`)

| Service | Image | Ports | Rôle |
|---------|-------|-------|------|
| **ClickHouse** | clickhouse-server:25.12 | 8123, 9000 | Base analytique |
| **Redis** | redis:7.4-alpine | 6379 | Cache & sessions |
| **Vector** | timberio/vector:0.52.0 | 514/UDP, 1514/TCP | Ingestion Syslog |
| **Backend** | Custom Go build | 8080 | API REST |
| **Frontend** | Custom React build | 3000 | Interface web |
| **Nginx** | nginx:alpine | 80, 443 | Reverse proxy (prod) |

---

## Flux de Données

### 1. Ingestion des Logs

```
Sophos XGS ──Syslog UDP/TCP──▶ Vector ──Parser──▶ ClickHouse
                                                      │
                                                      ▼
                                              Table: events
```

### 2. Détection & Réponse

```
events ──Query──▶ Detect2Ban ──TI Check──▶ Decision
                       │                      │
                       ▼                      ▼
               Threat Intel API          Ban/Pending
                       │                      │
                       └──────────────────────┼──▶ Sophos XGS
                                              │     (API XML)
                                              ▼
                                        Table: bans
```

### 3. Affichage Temps Réel

```
ClickHouse ──Query──▶ Backend API ──WebSocket──▶ Frontend
                           │                         │
                           └────────REST─────────────┘
```

---

## Intégrations Externes

### Sophos XGS Firewall

| Type | Protocole | Usage |
|------|-----------|-------|
| **Syslog** | UDP/TCP | Réception des logs |
| **API XML** | HTTPS | Gestion des groupes IP (ban/unban) |
| **SSH** | Port 22 | Sync logs ModSecurity |

### Threat Intelligence (11 providers)

| Tier | Providers | Activation |
|------|-----------|------------|
| **1** (Free) | OTX, ThreatFox, URLhaus, IPsum | Toujours |
| **2** (Limited) | AbuseIPDB, GreyNoise, CrowdSec | Score > 30 |
| **3** (Premium) | VirusTotal, CriminalIP, Pulsedive | Score > 60 |

### Licence (VigilanceKey)

| Endpoint | Usage |
|----------|-------|
| `/api/license/activate` | Activation licence |
| `/api/license/heartbeat` | Validation périodique |
| `/api/crowdsec/blocklist` | Neural-Sync (CrowdSec proxy) |

---

## Sécurité

### Modèle de Sécurité

| Couche | Protection |
|--------|------------|
| **Réseau** | Déploiement interne uniquement |
| **Accès** | VPN obligatoire |
| **Auth** | JWT + RBAC (admin/audit) |
| **API** | Rate limiting, CORS sécurisé |
| **Headers** | OWASP security headers |

### Rôles RBAC

| Rôle | Permissions |
|------|-------------|
| **admin** | Toutes les actions (CRUD users, bans, config) |
| **audit** | Lecture seule (dashboard, logs, events) |

---

## Versioning

**Format**: `X.YY.Z`

| Digit | Nom | Description |
|-------|-----|-------------|
| **X** | MAJOR | Sur demande explicite |
| **YY** | FEATURE | Nouvelle feature (+1) |
| **Z** | BUGFIX | Corrections (commence à 100) |

**Fichiers à mettre à jour:**
- `frontend/src/pages/Dashboard.tsx` - INSTALLED_VERSION
- `frontend/src/pages/Settings.tsx` - Footer version
- `frontend/src/pages/Login.tsx` - Footer version
- `frontend/src/pages/LicenseActivation.tsx` - Footer version
- `backend/internal/adapter/controller/http/handlers/update.go` - InstalledVersion
- `CLAUDE.md` - Header version

---

## Commandes de Développement

```bash
# Backend
cd backend
go build ./cmd/api          # Build API
go build ./cmd/detect2ban   # Build D2B
go test ./...               # Tests

# Frontend
cd frontend
npm run dev                 # Dev server
npm run build               # Production build
npm run lint                # ESLint

# Docker
cd docker
docker compose up -d        # Start stack
docker compose logs -f api  # View logs
docker compose restart api  # Restart service
```

---

*Documentation générée par le workflow document-project*
