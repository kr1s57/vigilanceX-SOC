# Architecture d'Intégration Multi-Part

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

VIGILANCE X est un projet **multi-part** composé de 2 applications distinctes qui communiquent via API REST et WebSocket.

```
┌─────────────────────────────────────────────────────────────────┐
│                     VIGILANCE X Platform                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌─────────────────┐         ┌─────────────────┐                │
│   │    Frontend     │◀───────▶│    Backend      │                │
│   │    (React)      │  REST   │    (Go API)     │                │
│   │    Port 3000    │  WS     │    Port 8080    │                │
│   └─────────────────┘         └─────────────────┘                │
│           │                           │                           │
│           │                           │                           │
│           ▼                           ▼                           │
│   ┌─────────────────┐         ┌─────────────────┐                │
│   │    Nginx        │         │   ClickHouse    │                │
│   │  (Reverse Proxy)│         │   + Redis       │                │
│   │    Port 80/443  │         │                 │                │
│   └─────────────────┘         └─────────────────┘                │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Parties du Projet

### Part 1: Backend (Go API)

| Attribut | Valeur |
|----------|--------|
| **Chemin** | `/opt/vigilanceX/backend/` |
| **Type** | API REST + Moteur de détection |
| **Port** | 8080 |
| **Dépendances** | ClickHouse, Redis, Sophos XGS |

**Services exposés:**
- REST API (`/api/v1/*`)
- WebSocket (`/ws`)
- Health check (`/health`)

### Part 2: Frontend (React SPA)

| Attribut | Valeur |
|----------|--------|
| **Chemin** | `/opt/vigilanceX/frontend/` |
| **Type** | Single Page Application |
| **Port** | 3000 (dev: 5173) |
| **Dépendances** | Backend API |

**Consommation:**
- API REST via Axios
- WebSocket pour temps réel

---

## Communication Inter-Parts

### Frontend → Backend

```
┌──────────────┐      HTTP/HTTPS        ┌──────────────┐
│   Frontend   │ ────────────────────▶ │   Backend    │
│              │ POST /api/v1/auth/login│              │
│              │ GET /api/v1/events     │              │
│              │ POST /api/v1/bans      │              │
└──────────────┘                        └──────────────┘
```

**Configuration Vite (dev):**
```typescript
// vite.config.ts
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:8080',
      changeOrigin: true,
    },
    '/ws': {
      target: 'ws://localhost:8080',
      ws: true,
    },
  },
}
```

### WebSocket (temps réel)

```
┌──────────────┐      WebSocket          ┌──────────────┐
│   Frontend   │ ◀────────────────────▶ │   Backend    │
│              │   /ws                   │   (Hub)      │
│              │   Events: ban, alert,   │              │
│              │   event, status         │              │
└──────────────┘                        └──────────────┘
```

**Messages WebSocket:**
```json
// Nouveau ban
{"type": "ban", "data": {"ip": "x.x.x.x", "reason": "..."}}

// Alerte critique
{"type": "alert", "data": {"severity": "critical", "message": "..."}}

// Nouvel événement
{"type": "event", "data": {...}}
```

---

## Dépendances Partagées

### ClickHouse

```
┌──────────────┐      TCP 9000/8123     ┌──────────────┐
│   Backend    │ ────────────────────▶ │  ClickHouse  │
│              │   SQL Queries          │              │
│              │   INSERT/SELECT        │              │
└──────────────┘                        └──────────────┘
        │
        │ (Frontend n'accède pas directement)
        ▼
```

### Redis

```
┌──────────────┐      TCP 6379          ┌──────────────┐
│   Backend    │ ────────────────────▶ │    Redis     │
│              │   Sessions             │              │
│              │   TI Cache             │              │
│              │   Rate Limiting        │              │
└──────────────┘                        └──────────────┘
```

---

## Intégrations Externes

### Sophos XGS Firewall

```
┌──────────────┐                        ┌──────────────┐
│   Backend    │ ─────API XML 4444────▶ │  Sophos XGS  │
│              │   Ban/Unban IP         │   Firewall   │
│              │ ◀────Syslog 514────── │              │
│              │   Security Events      │              │
│              │ ─────SSH 22──────────▶ │              │
│              │   ModSec Logs          │              │
└──────────────┘                        └──────────────┘
```

### Threat Intelligence (11 providers)

```
┌──────────────┐                        ┌──────────────┐
│   Backend    │ ─────HTTPS────────────▶│  TI APIs     │
│   (TI Agg)   │                        │              │
│              │   Tier 1: OTX, ThreatFox, URLhaus    │
│              │   Tier 2: AbuseIPDB, GreyNoise, CS   │
│              │   Tier 3: VT, CriminalIP, Pulsedive  │
└──────────────┘                        └──────────────┘
```

### VigilanceKey (Licence Server)

```
┌──────────────┐                        ┌──────────────┐
│   Backend    │ ─────HTTPS────────────▶│VigilanceKey  │
│              │   Activation           │              │
│              │   Heartbeat            │              │
│              │   Neural-Sync          │              │
└──────────────┘                        └──────────────┘
```

---

## Docker Compose

### Services

```yaml
services:
  # Database
  clickhouse:
    image: clickhouse/clickhouse-server:25.12
    ports: [8123, 9000]
    depends_on: []

  redis:
    image: redis:7.4-alpine
    ports: [6379]
    depends_on: []

  # Ingestion
  vector:
    image: timberio/vector:0.52.0
    ports: [514/udp, 1514/tcp]
    depends_on: [clickhouse]

  # Application
  backend:
    build: ../backend
    ports: [8080]
    depends_on: [clickhouse, redis]

  frontend:
    build: ../frontend
    ports: [3000]
    depends_on: [backend]

  # Reverse Proxy (production)
  nginx:
    image: nginx:alpine
    ports: [80, 443]
    profiles: [production]
    depends_on: [backend, frontend]
```

### Réseau

```yaml
networks:
  vigilance_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### Volumes

```yaml
volumes:
  clickhouse_data:    # Données ClickHouse
  clickhouse_logs:    # Logs ClickHouse
  redis_data:         # Persistance Redis
  vector_data:        # Buffer Vector
  backend_data:       # Données backend (licence)
  backend_config:     # Config backend (integrations.json)
```

---

## Flux de Données

### 1. Ingestion des Événements

```
Sophos XGS ──UDP/TCP──▶ Vector ──Parser──▶ ClickHouse
                                               │
                                               ▼
                                         Table: events
```

### 2. Détection Automatique

```
events ──Query──▶ Detect2Ban ──TI Check──▶ Decision
                       │                      │
                       ▼                      ▼
               TI Aggregator             Ban/Pending
                       │                      │
                       │                      ▼
                       │              Sophos XGS (API XML)
                       ▼
               ip_threat_scores
```

### 3. Interface Utilisateur

```
User ──Browser──▶ Frontend ──REST──▶ Backend ──SQL──▶ ClickHouse
                     │          │        │
                     │          │        └──────▶ Redis (cache)
                     │          │
                     └───WS─────┘ (temps réel)
```

---

## Points de Contrat

### API REST

| Endpoint | Method | Consumer | Producer |
|----------|--------|----------|----------|
| `/api/v1/*` | ALL | Frontend | Backend |
| `/health` | GET | Docker, Monitoring | Backend |
| `/ws` | WS | Frontend | Backend |

### Variables d'Environnement Partagées

| Variable | Usage |
|----------|-------|
| `CLICKHOUSE_HOST` | Backend, Vector |
| `CLICKHOUSE_PASSWORD` | Backend, Vector |
| `REDIS_HOST` | Backend |
| `REDIS_PASSWORD` | Backend |
| `SOPHOS_HOST` | Backend |

### Fichiers de Configuration

| Fichier | Localisation | Usage |
|---------|--------------|-------|
| `.env` | `/docker/.env` | Variables d'environnement |
| `integrations.json` | `/app/config/` | API keys persistées |
| `license.json` | `/app/data/` | Licence persistée |
| `vector.toml` | `/docker/vector/` | Config ingestion |
| `init-db.sql` | `/docker/clickhouse/` | Schéma DB |

---

## Développement

### Démarrage Local

```bash
# Terminal 1: Backend
cd backend
go run ./cmd/api

# Terminal 2: Frontend
cd frontend
npm run dev

# Terminal 3: Docker (DB + Redis + Vector)
cd docker
docker compose up clickhouse redis vector
```

### Tests d'Intégration

```bash
# Backend
cd backend && go test ./...

# Frontend
cd frontend && npm run lint && npm run build
```

---

*Documentation générée par le workflow document-project*
