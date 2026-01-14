# VIGILANCE X - Technical Documentation

**Version:** 3.54.102 | **Last Updated:** 2026-01-14

Complete technical reference for VIGILANCE X development and operations.

---

## Table of Contents

### Architecture
- [System Overview](#system-overview)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Clean Architecture](#clean-architecture)
- [Data Flow](#data-flow)

### Backend
- [API Server](#api-server)
- [Authentication & Authorization](#authentication--authorization)
- [Detect2Ban Engine](#detect2ban-engine)
- [Threat Intelligence Aggregator](#threat-intelligence-aggregator)
- [Services Overview](#services-overview)
- [External Adapters](#external-adapters)

### Frontend
- [React Application](#react-application)
- [State Management](#state-management)
- [WebSocket Integration](#websocket-integration)
- [Pages Reference](#pages-reference)

### Database
- [ClickHouse Schema](#clickhouse-schema)
- [Migrations](#migrations)
- [Queries & Optimization](#queries--optimization)

### Integrations
- [Sophos XGS](#sophos-xgs-integration)
- [Threat Intelligence Providers](#threat-intelligence-providers)
- [CrowdSec Blocklist](#crowdsec-blocklist)
- [Email Notifications](#email-notifications)

### Features
- [Vigimail Checker](#vigimail-checker)
- [Neural-Sync](#neural-sync)
- [GeoZone Classification](#geozone-classification)
- [Log Retention](#log-retention)

### Operations
- [Deployment](#deployment)
- [Configuration Reference](#configuration-reference)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

### Development
- [Development Setup](#development-setup)
- [Code Conventions](#code-conventions)
- [Git Workflow](#git-workflow)
- [Versioning](#versioning)
- [Testing](#testing)

---

# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VIGILANCE X                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────┐   │
│   │  Sophos XGS  │────►│   Vector     │────►│      ClickHouse          │   │
│   │  (Syslog)    │     │   (Ingest)   │     │   (Time-series DB)       │   │
│   └──────────────┘     └──────────────┘     └────────────┬─────────────┘   │
│                                                          │                  │
│   ┌──────────────┐     ┌──────────────┐                 │                  │
│   │   Sophos     │◄────┤   Go API     │◄────────────────┘                  │
│   │  (XML API)   │     │   Server     │                                    │
│   └──────────────┘     └──────┬───────┘                                    │
│                               │                                             │
│   ┌──────────────┐           │           ┌──────────────────────────┐     │
│   │ ThreatIntel  │◄──────────┼──────────►│      React SPA           │     │
│   │  (11 APIs)   │           │           │   (Dashboard/Analysis)   │     │
│   └──────────────┘           │           └──────────────────────────┘     │
│                               │                                             │
│   ┌──────────────┐           │           ┌──────────────────────────┐     │
│   │    Redis     │◄──────────┘           │      Nginx               │     │
│   │   (Cache)    │                       │   (Reverse Proxy)        │     │
│   └──────────────┘                       └──────────────────────────┘     │
│                                                                              │
│   ┌────────────────────────────────────────────────────────────────────┐   │
│   │                      Detect2Ban Engine                              │   │
│   │   WAF Events → Detection Rules → TI Validation → XGS Ban           │   │
│   └────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Backend** | Go | 1.22 | API server, business logic |
| **Frontend** | React + TypeScript | 18.2.0 | SPA user interface |
| **Database** | ClickHouse | 24.1 | Time-series analytics |
| **Cache** | Redis | 7-alpine | Session cache, rate limiting |
| **Ingestion** | Vector.dev | 0.34.1 | Log pipeline |
| **Proxy** | Nginx | alpine | Reverse proxy, SSL termination |
| **Container** | Docker Compose | 2.20+ | Orchestration |

## Project Structure

```
/opt/vigilanceX/
├── backend/
│   ├── cmd/
│   │   ├── api/                    # Main API server
│   │   ├── detect2ban/             # Detection daemon
│   │   └── reset-password/         # Password reset CLI
│   ├── internal/
│   │   ├── domain/                 # Business rules
│   │   │   └── scoring/            # Threat scoring logic
│   │   ├── entity/                 # Data models
│   │   ├── adapter/
│   │   │   ├── repository/         # Data access
│   │   │   │   └── clickhouse/     # ClickHouse implementations
│   │   │   ├── controller/
│   │   │   │   └── http/
│   │   │   │       ├── handlers/   # HTTP handlers
│   │   │   │       └── middleware/ # Auth, CORS, etc.
│   │   │   └── external/           # External integrations
│   │   │       ├── sophos/         # XGS API client
│   │   │       ├── threatintel/    # TI providers
│   │   │       ├── crowdsec/       # CrowdSec clients
│   │   │       ├── geoip/          # GeoIP lookup
│   │   │       └── storage/        # SMB storage
│   │   ├── usecase/                # Application services
│   │   │   ├── auth/               # Authentication
│   │   │   ├── bans/               # Ban management
│   │   │   ├── events/             # Event processing
│   │   │   ├── threats/            # Threat aggregation
│   │   │   ├── modsec/             # ModSecurity sync
│   │   │   ├── vigimail/           # Email leak checker
│   │   │   └── ...
│   │   ├── config/                 # Configuration
│   │   ├── license/                # VX3 license client
│   │   └── pkg/                    # Utilities
│   ├── scenarios/                  # Detect2Ban YAML rules
│   └── migrations/                 # SQL migrations (legacy)
├── frontend/
│   ├── src/
│   │   ├── pages/                  # Page components
│   │   ├── components/             # Reusable UI
│   │   ├── contexts/               # React contexts
│   │   ├── stores/                 # Zustand stores
│   │   ├── lib/                    # API, WebSocket, utils
│   │   ├── hooks/                  # Custom hooks
│   │   └── types/                  # TypeScript definitions
│   └── dist/                       # Production build
├── docker/
│   ├── docker-compose.yml
│   ├── .env
│   ├── clickhouse/
│   │   ├── config/
│   │   └── migrations/             # Active migrations
│   ├── nginx/
│   ├── vector/
│   └── ssh/
├── docs/                           # Internal documentation
├── CLAUDE.md                       # AI memory file
├── CHANGELOG.md                    # Version history
└── README.md                       # This file
```

## Clean Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         Frameworks                              │
│  HTTP Handlers │ ClickHouse │ Redis │ External APIs             │
└───────────────────────────────┬────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────┐
│                      Interface Adapters                         │
│  Repositories │ Controllers │ Presenters │ Gateways             │
└───────────────────────────────┬────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────┐
│                      Application Layer                          │
│  Use Cases │ Services │ DTOs │ Interfaces                       │
└───────────────────────────────┬────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────┐
│                         Domain Layer                            │
│  Entities │ Value Objects │ Domain Services │ Business Rules    │
└────────────────────────────────────────────────────────────────┘
```

**Dependency Rule:** Dependencies point inward. Inner layers know nothing about outer layers.

## Data Flow

### Event Ingestion
```
Sophos XGS ──UDP/TCP 514──► Vector.dev ──HTTP──► ClickHouse
                                │
                                └──► Transform (parse fields, enrich)
```

### Threat Analysis
```
User Request ──► API Handler ──► ThreatService ──► Aggregator
                                                      │
                    ┌─────────────────────────────────┼─────────────────┐
                    ▼                                 ▼                 ▼
                Tier 1 (Free)              Tier 2 (Score>30)    Tier 3 (Score>60)
                - IPsum                    - AbuseIPDB          - VirusTotal
                - OTX                      - GreyNoise          - CriminalIP
                - ThreatFox                - CrowdSec CTI       - Pulsedive
                - URLhaus
                - Shodan InternetDB
```

### Ban Workflow
```
Detection ──► Verify (whitelist, immunity, existing) ──► TI Check ──► BAN
                                                                       │
                                                                       ▼
                                                              XGS Group Sync
```

---

# Backend

## API Server

**Entry Point:** `backend/cmd/api/main.go`

### Router Setup (Chi)
```go
r := chi.NewRouter()

// Middleware stack
r.Use(middleware.RequestID)
r.Use(middleware.RealIP)
r.Use(middleware.Logger)
r.Use(middleware.Recoverer)
r.Use(corsMiddleware)
r.Use(rateLimitMiddleware)

// Public routes
r.Post("/api/v1/auth/login", authHandler.Login)
r.Get("/api/v1/license/status", licenseHandler.Status)

// Protected routes
r.Group(func(r chi.Router) {
    r.Use(authMiddleware)
    r.Get("/api/v1/events", eventsHandler.List)
    r.Get("/api/v1/bans", bansHandler.List)
    // ...
})

// Admin routes
r.Group(func(r chi.Router) {
    r.Use(authMiddleware)
    r.Use(adminMiddleware)
    r.Get("/api/v1/users", usersHandler.List)
    // ...
})
```

### Key Handlers

| Handler | File | Endpoints |
|---------|------|-----------|
| Auth | `handlers/auth.go` | login, logout, me, change-password |
| Events | `handlers/events.go` | list, timeline, stats, geo-heatmap |
| Bans | `handlers/bans.go` | list, create, delete, sync, history |
| Threats | `handlers/threats.go` | check, risk, batch, providers |
| Geoblocking | `handlers/geoblocking.go` | rules, check, lookup |
| Vigimail | `handlers/vigimail.go` | domains, emails, leaks, dns-checks |
| Reports | `handlers/reports.go` | generate, schedule, send |

## Authentication & Authorization

### JWT Flow
```
Login ──► Validate Credentials ──► Generate JWT ──► Return Token
                                        │
                                        └──► Claims: user_id, role, exp
```

### Roles
| Role | Permissions |
|------|-------------|
| `admin` | Full access |
| `audit` | Read-only access |

### Token Validation
```go
type Claims struct {
    UserID string `json:"user_id"`
    Role   string `json:"role"`
    jwt.StandardClaims
}

// Middleware extracts and validates JWT
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := extractToken(r)
        claims, err := validateToken(token)
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        ctx := context.WithValue(r.Context(), "claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Detect2Ban Engine

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                      Detect2Ban Engine                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  Scenario   │    │  Detection  │    │   Ban Executor      │ │
│  │  Loader     │───►│  Loop       │───►│                     │ │
│  │  (YAML)     │    │  (30s tick) │    │ - Verify conditions │ │
│  └─────────────┘    └─────────────┘    │ - TI validation     │ │
│                                        │ - Execute ban       │ │
│                                        │ - Sync XGS          │ │
│                                        └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Scenario Format
```yaml
# scenarios/waf_attacks.yaml
name: waf_attacks
description: "Ban IPs with multiple WAF events"
enabled: true

detection:
  source: events
  filter:
    log_type: "Web Application Firewall"
  threshold: 5
  window: 5m
  group_by: src_ip

action:
  type: ban
  duration: 4h
  validate_threat: false
```

### Detection Flow
```go
func (e *Engine) processScenario(ctx context.Context, scenario *Scenario) error {
    // 1. Query events matching scenario
    events, err := e.repo.QueryEvents(ctx, scenario.Detection)

    // 2. Group by source IP
    grouped := groupByIP(events)

    // 3. Check threshold
    for ip, count := range grouped {
        if count >= scenario.Detection.Threshold {
            // 4. Verify not protected/whitelisted/immune
            if e.shouldBan(ctx, ip) {
                // 5. Optional TI validation
                if scenario.Action.ValidateThreat {
                    score := e.threatService.GetRisk(ctx, ip)
                    if score < threshold {
                        continue
                    }
                }
                // 6. Execute ban
                e.banService.BanIP(ctx, ip, scenario.Action.Duration)
            }
        }
    }
}
```

## Threat Intelligence Aggregator

### Provider Tiers
```go
var tiers = map[int][]Provider{
    1: {IPsum, OTX, ThreatFox, URLhaus, ShodanInternetDB},  // Free/Unlimited
    2: {AbuseIPDB, GreyNoise, CrowdSecCTI},                  // Moderate quota
    3: {VirusTotal, CriminalIP, Pulsedive},                  // Limited quota
}

func (a *Aggregator) GetRisk(ctx context.Context, ip string) (*ThreatScore, error) {
    score := &ThreatScore{IP: ip}

    // Always check Tier 1
    for _, p := range tiers[1] {
        result, _ := p.Check(ctx, ip)
        score.Merge(result)
    }

    // Check Tier 2 if score > 30
    if score.AggregatedScore > 30 {
        for _, p := range tiers[2] {
            result, _ := p.Check(ctx, ip)
            score.Merge(result)
        }
    }

    // Check Tier 3 if score > 60
    if score.AggregatedScore > 60 {
        for _, p := range tiers[3] {
            result, _ := p.Check(ctx, ip)
            score.Merge(result)
        }
    }

    return score, nil
}
```

### Score Calculation
```go
type ThreatScore struct {
    IP              string
    AggregatedScore float64    // 0-100
    ThreatLevel     string     // critical/high/medium/low/minimal
    IsMalicious     bool
    Sources         []string
    Categories      []string
}

// Threat levels
// Critical: 80-100
// High: 60-79
// Medium: 40-59
// Low: 20-39
// Minimal: 0-19
```

## Services Overview

| Service | File | Purpose |
|---------|------|---------|
| AuthService | `usecase/auth/service.go` | JWT, password hashing |
| BansService | `usecase/bans/service.go` | Ban lifecycle, XGS sync |
| EventsService | `usecase/events/service.go` | Event queries, stats |
| ThreatsService | `usecase/threats/service.go` | TI aggregation |
| GeoblockingService | `usecase/geoblocking/service.go` | Country rules |
| ModsecService | `usecase/modsec/service.go` | SSH rule sync |
| VigimailService | `usecase/vigimail/service.go` | Email monitoring |
| NotificationService | `usecase/notifications/service.go` | SMTP emails |
| RetentionService | `usecase/retention/service.go` | Log cleanup |
| CrowdSecBlocklistService | `usecase/crowdsec/blocklist_service.go` | Blocklist sync |

## External Adapters

### Sophos XGS Client
```go
// internal/adapter/external/sophos/client.go
type Client interface {
    // Host management
    CreateHost(name, ip string) error
    DeleteHost(name string) error
    GetHost(name string) (*Host, error)

    // Group management
    CreateIPHostGroup(name, description string) error
    AddHostToGroup(groupName, hostName string) error
    RemoveHostFromGroup(groupName, hostName string) error
    GetGroupHosts(groupName string) ([]string, error)

    // Ban operations
    BanIP(ip string) error
    UnbanIP(ip string) error
    SyncBannedIPs(ips []string) error
}
```

### GeoIP Client
```go
// internal/adapter/external/geoip/client.go
type Client interface {
    Lookup(ip string) (*GeoInfo, error)
}

type GeoInfo struct {
    IP          string
    Country     string
    CountryCode string
    City        string
    Region      string
    ISP         string
    Latitude    float64
    Longitude   float64
}
```

---

# Frontend

## React Application

### Entry Point
```tsx
// src/main.tsx
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <LicenseProvider>
          <SettingsProvider>
            <App />
          </SettingsProvider>
        </LicenseProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
)
```

### Routing
```tsx
// src/App.tsx
<Routes>
  <Route path="/login" element={<Login />} />
  <Route element={<ProtectedLayout />}>
    <Route path="/" element={<Dashboard />} />
    <Route path="/waf-explorer" element={<WafExplorer />} />
    <Route path="/attacks" element={<AttacksAnalyzer />} />
    <Route path="/attack-map" element={<AttackMap />} />
    <Route path="/advanced-threat" element={<AdvancedThreat />} />
    <Route path="/vpn-network" element={<VpnNetwork />} />
    <Route path="/geoblocking" element={<Geoblocking />} />
    <Route path="/soft-whitelist" element={<SoftWhitelist />} />
    <Route path="/vigimail" element={<VigimailChecker />} />
    <Route path="/neural-sync" element={<NeuralSync />} />
    <Route path="/reports" element={<Reports />} />
    <Route path="/settings" element={<Settings />} />
    <Route path="/user-management" element={<UserManagement />} />
  </Route>
</Routes>
```

## State Management

### Contexts
| Context | Purpose |
|---------|---------|
| AuthContext | User session, login/logout |
| LicenseContext | License status, features |
| SettingsContext | UI preferences |

### Zustand Stores
```typescript
// stores/bansStore.ts
interface BansState {
  bans: Ban[]
  loading: boolean
  error: string | null
  fetchBans: () => Promise<void>
  banIP: (ip: string, reason: string) => Promise<void>
  unbanIP: (ip: string, immunityHours?: number) => Promise<void>
}

export const useBansStore = create<BansState>((set, get) => ({
  bans: [],
  loading: false,
  error: null,
  fetchBans: async () => {
    set({ loading: true })
    const bans = await api.bans.list()
    set({ bans, loading: false })
  },
  // ...
}))
```

## WebSocket Integration

```typescript
// lib/websocket.ts
class WebSocketManager {
  private ws: WebSocket | null = null
  private listeners: Map<string, Set<Function>> = new Map()

  connect(token: string) {
    this.ws = new WebSocket(`wss://${host}/api/v1/ws?token=${token}`)

    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      this.emit(data.type, data.payload)
    }
  }

  subscribe(event: string, callback: Function) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set())
    }
    this.listeners.get(event)!.add(callback)
  }

  private emit(event: string, data: any) {
    this.listeners.get(event)?.forEach(cb => cb(data))
  }
}
```

### Event Types
| Event | Payload | Description |
|-------|---------|-------------|
| `new_event` | Event object | New security event |
| `new_ban` | Ban object | IP was banned |
| `ban_removed` | { ip: string } | IP was unbanned |
| `threat_detected` | Threat object | High-risk IP detected |

## Pages Reference

| Page | File | Lines | Key Components |
|------|------|-------|----------------|
| Dashboard | `Dashboard.tsx` | ~400 | StatsCards, Timeline, TopAttackers |
| WAF Explorer | `WafExplorer.tsx` | ~800 | TreeView, EventDetail, RuleInfo |
| Attacks Analyzer | `AttacksAnalyzer.tsx` | ~1060 | Charts, IPModal, FilterTabs |
| Attack Map | `AttackMap.tsx` | ~600 | WorldMap, AttackFlows, CountryModal |
| Advanced Threat | `AdvancedThreat.tsx` | ~700 | ThreatLookup, ProviderResults |
| VPN Network | `VpnNetwork.tsx` | ~900 | SessionList, DayAccordion |
| Geoblocking | `Geoblocking.tsx` | ~570 | RuleList, CountryPicker |
| Soft Whitelist | `SoftWhitelist.tsx` | ~630 | WhitelistTable, AddModal |
| Vigimail | `VigimailChecker.tsx` | ~900 | DomainList, EmailList, LeakModal |
| Neural-Sync | `NeuralSync.tsx` | ~800 | BlocklistTable, SyncStatus |
| Reports | `Reports.tsx` | ~500 | ReportGenerator, Schedule |
| Settings | `Settings.tsx` | ~2200 | IntegrationCards, ConfigModals |

---

# Database

## ClickHouse Schema

### Core Tables

```sql
-- Events (main log table)
CREATE TABLE vigilance_x.events (
    timestamp DateTime,
    log_type LowCardinality(String),
    log_subtype LowCardinality(String),
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    action LowCardinality(String),
    severity LowCardinality(String),
    rule_id UInt32,
    message String,
    raw_log String,
    -- ... 104 fields total
) ENGINE = MergeTree()
ORDER BY (timestamp, log_type, src_ip)
PARTITION BY toYYYYMM(timestamp);

-- Ban Status
CREATE TABLE vigilance_x.ip_ban_status (
    ip String,
    is_banned UInt8,
    banned_at Nullable(DateTime),
    banned_until Nullable(DateTime),
    ban_reason String,
    banned_by String,
    ban_type LowCardinality(String),
    immune_until Nullable(DateTime),
    current_tier UInt8,
    geo_zone LowCardinality(String),
    xgs_group LowCardinality(String),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY ip;

-- Threat Scores Cache
CREATE TABLE vigilance_x.threat_scores (
    ip String,
    aggregated_score Float32,
    threat_level LowCardinality(String),
    is_malicious UInt8,
    sources Array(String),
    categories Array(String),
    checked_at DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY ip
TTL checked_at + INTERVAL 24 HOUR;
```

### Vigimail Tables

```sql
-- Domains
CREATE TABLE vigilance_x.vigimail_domains (
    id UUID,
    domain String,
    created_at DateTime,
    deleted UInt8,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY domain;

-- Emails
CREATE TABLE vigilance_x.vigimail_emails (
    id UUID,
    email String,
    domain String,
    last_check DateTime,
    leak_count UInt32,
    status LowCardinality(String),
    created_at DateTime,
    deleted UInt8,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
ORDER BY (domain, email);

-- Leaks
CREATE TABLE vigilance_x.vigimail_leaks (
    id UUID,
    email String,
    source LowCardinality(String),
    breach_name String,
    breach_date Nullable(Date),
    data_classes Array(String),
    is_verified UInt8,
    is_sensitive UInt8,
    description String,
    first_seen DateTime,
    last_seen DateTime
) ENGINE = MergeTree()
ORDER BY (email, source, breach_name);

-- DNS Checks
CREATE TABLE vigilance_x.vigimail_domain_checks (
    id UUID,
    domain String,
    check_time DateTime,
    spf_exists UInt8,
    spf_record String,
    spf_valid UInt8,
    spf_issues Array(String),
    dkim_exists UInt8,
    dkim_selectors Array(String),
    dkim_valid UInt8,
    dkim_issues Array(String),
    dmarc_exists UInt8,
    dmarc_record String,
    dmarc_policy LowCardinality(String),
    dmarc_valid UInt8,
    dmarc_issues Array(String),
    mx_exists UInt8,
    mx_records Array(String),
    overall_score UInt8,
    overall_status LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (domain, check_time)
TTL check_time + INTERVAL 90 DAY;
```

## Migrations

**Location:** `docker/clickhouse/migrations/`

| Migration | Description |
|-----------|-------------|
| 001_initial.sql | Core tables |
| 002_modsec.sql | ModSecurity tables |
| 003_whitelist.sql | Soft whitelist |
| 004_geoblocking.sql | Geoblocking rules |
| 005_notifications.sql | SMTP settings |
| 006_detect2ban.sql | D2B scenarios |
| 007_d2b_v2_ban_system.sql | Tiers, GeoZone |
| 008_retention_settings.sql | Log retention |
| 009_vpn_tables.sql | VPN sessions |
| 010_api_usage.sql | API tracking |
| 011_crowdsec_blocklist.sql | Blocklist IPs |
| 012_crowdsec_proxy.sql | Proxy settings |
| 013_vigimail_checker.sql | Email monitoring |

### Applying Migrations
```bash
# Apply single migration
docker compose exec clickhouse clickhouse-client < migrations/013_vigimail_checker.sql

# Apply all new migrations
for f in migrations/*.sql; do
  docker compose exec clickhouse clickhouse-client < "$f"
done
```

## Queries & Optimization

### Common Patterns

```sql
-- Soft-deleted records (use FINAL)
SELECT * FROM vigimail_emails FINAL WHERE deleted = 0;

-- Time-range queries (partition pruning)
SELECT * FROM events
WHERE timestamp >= now() - INTERVAL 7 DAY
  AND log_type = 'Web Application Firewall';

-- Aggregations with filtering
SELECT src_ip, count() as cnt
FROM events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY src_ip
ORDER BY cnt DESC
LIMIT 10;

-- Join with FINAL for consistency
SELECT e.email, l.breach_name
FROM vigimail_emails FINAL e
JOIN vigimail_leaks l ON e.email = l.email
WHERE e.deleted = 0;
```

### Performance Tips
- Always filter by timestamp first (partition pruning)
- Use `FINAL` only when needed (ReplacingMergeTree)
- Limit result sets for UI queries
- Use materialized views for frequent aggregations

---

# Integrations

## Sophos XGS Integration

### Syslog Configuration
```toml
# docker/vector/vector.toml
[sources.sophos_syslog]
type = "syslog"
address = "0.0.0.0:514"
mode = "udp"

[transforms.parse_sophos]
type = "remap"
inputs = ["sophos_syslog"]
source = '''
  # Parse Sophos log format
  .timestamp = parse_timestamp!(.timestamp, "%Y-%m-%d %H:%M:%S")
  .log_type = get_field(.message, "log_type")
  .src_ip = get_field(.message, "src_ip")
  # ... 104 fields
'''

[sinks.clickhouse]
type = "clickhouse"
inputs = ["parse_sophos"]
endpoint = "http://clickhouse:8123"
database = "vigilance_x"
table = "events"
```

### XML API Client
```go
// Ban IP via XML API
func (c *Client) BanIP(ip string) error {
    // 1. Create host object
    host := fmt.Sprintf("VGX_%s", strings.ReplaceAll(ip, ".", "_"))
    c.CreateHost(host, ip)

    // 2. Add to ban group
    c.AddHostToGroup("grp_VGX-BannedIP", host)

    return nil
}
```

### SSH ModSecurity Sync
```go
// Fetch rule IDs from XGS via SSH
func (c *SSHClient) GetWAFRuleDetails(ruleID int) (*RuleDetail, error) {
    cmd := fmt.Sprintf("cat /var/waf/rules/%d.conf", ruleID)
    output, err := c.Run(cmd)
    // Parse rule details...
}
```

## Threat Intelligence Providers

### Provider Configuration

```go
// Provider interface
type Provider interface {
    Name() string
    Check(ctx context.Context, ip string) (*Result, error)
    RateLimit() time.Duration
}

// AbuseIPDB implementation
type AbuseIPDBClient struct {
    apiKey string
    http   *http.Client
}

func (c *AbuseIPDBClient) Check(ctx context.Context, ip string) (*Result, error) {
    req, _ := http.NewRequestWithContext(ctx, "GET",
        fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ip), nil)
    req.Header.Set("Key", c.apiKey)
    // ...
}
```

### API Keys Configuration

| Provider | Env Variable | Quota |
|----------|--------------|-------|
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1000/day |
| VirusTotal | `VIRUSTOTAL_API_KEY` | 500/day |
| GreyNoise | `GREYNOISE_API_KEY` | 500/day |
| CrowdSec CTI | `CROWDSEC_API_KEY` | 50/day |
| Pulsedive | `PULSEDIVE_API_KEY` | 100/day |
| CriminalIP | `CRIMINALIP_API_KEY` | 100/day |
| AlienVault OTX | `OTX_API_KEY` | Unlimited |
| abuse.ch | `ABUSECH_API_KEY` | Unlimited |

## CrowdSec Blocklist

### Architecture (Neural-Sync ProxyAPI)
```
VigilanceKey ──► CrowdSec API ──► Download blocklists
     │
     └──► VGX Clients (license-authenticated)
              │
              └──► Local DB + XGS Group Sync
```

### VGX Client Flow
```go
// 1. Fetch available blocklists from VigilanceKey
lists, _ := vkClient.GetBlocklists(ctx)

// 2. Download selected blocklists
for _, list := range lists {
    ips, _ := vkClient.DownloadBlocklist(ctx, list.ID)

    // 3. Sync to local ClickHouse
    repo.SyncIPs(ctx, list.ID, ips)

    // 4. Enrich with GeoIP
    for _, ip := range newIPs {
        geo, _ := geoipClient.Lookup(ip)
        repo.UpdateIPCountry(ctx, ip, geo.CountryCode)
    }

    // 5. Sync to XGS group
    xgsClient.SyncGroupIPs(ctx, "grp_VGX-CrowdSBlockL", "CS", ips)
}
```

## Email Notifications

### SMTP Configuration
```go
type SMTPConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    From     string
    UseTLS   bool
    UseSTARTTLS bool
}

// Office 365 example
config := SMTPConfig{
    Host:        "smtp.office365.com",
    Port:        587,
    Username:    "alerts@company.com",
    Password:    "app_password",
    From:        "alerts@company.com",
    UseSTARTTLS: true,
}
```

### Email Types
| Type | Trigger | Template |
|------|---------|----------|
| WAF Alert | WAF blocking event | `waf_alert.html` |
| Ban Notification | New IP banned | `ban_notification.html` |
| Daily Report | Scheduled (daily) | `daily_report.html` |
| Weekly Summary | Scheduled (weekly) | `weekly_summary.html` |

---

# Features

## Vigimail Checker

### Service Architecture
```go
type VigimailService struct {
    repo        VigimailRepository
    hibpClient  *HIBPClient
    leakCheck   *LeakCheckClient
    dnsChecker  *DNSChecker
    worker      *checkWorker
}

// Background worker runs every N hours
func (w *checkWorker) run() {
    ticker := time.NewTicker(w.interval)
    for {
        select {
        case <-ticker.C:
            // 1. Cleanup orphan data
            w.service.CleanupOrphanData(ctx)

            // 2. Check all emails for leaks
            for _, email := range emails {
                w.service.CheckEmail(ctx, email)
            }

            // 3. Check all domains DNS
            for _, domain := range domains {
                w.service.CheckDomain(ctx, domain)
            }
        }
    }
}
```

### API Endpoints
```
GET    /api/v1/vigimail/config
PUT    /api/v1/vigimail/config
GET    /api/v1/vigimail/status
GET    /api/v1/vigimail/domains
POST   /api/v1/vigimail/domains
DELETE /api/v1/vigimail/domains/{domain}
GET    /api/v1/vigimail/domains/{domain}/dns
POST   /api/v1/vigimail/domains/{domain}/check
GET    /api/v1/vigimail/emails
POST   /api/v1/vigimail/emails
DELETE /api/v1/vigimail/emails/{email}
GET    /api/v1/vigimail/emails/{email}/leaks
POST   /api/v1/vigimail/emails/{email}/check
POST   /api/v1/vigimail/check-all
```

### DNS Checks
```go
type DNSChecker struct {
    commonDKIMSelectors []string // default, google, selector1, selector2, etc.
}

func (c *DNSChecker) CheckDomain(ctx context.Context, domain string) (*DomainDNSCheck, error) {
    check := &DomainDNSCheck{Domain: domain}

    // SPF
    spf, _ := net.LookupTXT(domain)
    check.SPFExists = containsSPF(spf)
    check.SPFValid = validateSPF(spf)

    // DMARC
    dmarc, _ := net.LookupTXT("_dmarc." + domain)
    check.DMARCExists = containsDMARC(dmarc)
    check.DMARCPolicy = extractPolicy(dmarc)

    // DKIM (check common selectors)
    for _, sel := range c.commonDKIMSelectors {
        dkim, err := net.LookupTXT(sel + "._domainkey." + domain)
        if err == nil && len(dkim) > 0 {
            check.DKIMExists = true
            check.DKIMSelectors = append(check.DKIMSelectors, sel)
        }
    }

    // MX
    mx, _ := net.LookupMX(domain)
    check.MXExists = len(mx) > 0

    // Calculate overall score
    check.OverallScore = calculateScore(check)

    return check, nil
}
```

## Neural-Sync

### VigilanceKey ProxyAPI
```
VGX Client ──► VigilanceKey ──► CrowdSec API
                  │
                  └──► /data/blocklists/{id}.txt
                       /data/blocklists/{id}.meta.json
```

### VGX Client Configuration
```go
type BlocklistConfig struct {
    Enabled       bool
    UseProxy      bool     // Use VigilanceKey as proxy
    ProxyServerURL string  // VigilanceKey URL
    EnabledLists  []string // Subscribed blocklist IDs
    SyncInterval  int      // Minutes
}
```

### XGS Group Sync
```go
const (
    XGSGroupName        = "grp_VGX-CrowdSBlockL"
    XGSGroupDescription = "CrowdSec Blocklist IPs - Managed by VIGILANCE X Neural-Sync"
    XGSHostPrefix       = "CS"  // CS_1.2.3.4
)

func (s *BlocklistService) syncToXGS(ctx context.Context, ips []string) error {
    // Ensure group exists
    s.xgsClient.EnsureGroupExists(XGSGroupName, XGSGroupDescription)

    // Sync IPs (add new, remove stale)
    return s.xgsClient.SyncGroupIPs(XGSGroupName, XGSHostPrefix, ips)
}
```

## GeoZone Classification

### Zone Types
| Zone | Behavior |
|------|----------|
| Authorized | Higher WAF threshold, TI validation required |
| Hostile | Lowest threshold, immediate ban |
| Neutral | Standard threshold, auto-ban |

### Configuration
```go
type GeoZoneConfig struct {
    Enabled              bool
    AuthorizedCountries  []string  // ["FR", "BE", "LU", "DE", "CH"]
    HostileCountries     []string  // ["RU", "CN", "KP"]
    DefaultPolicy        string    // authorized/hostile/neutral
    WAFThresholdHzone    int       // Events before ban (hostile)
    WAFThresholdZone     int       // Events before ban (auth/neutral)
    ThreatScoreThreshold int       // TI score for auto-ban
}
```

### Classification
```go
func (c *GeoZoneConfig) ClassifyCountry(country string) string {
    if contains(c.AuthorizedCountries, country) {
        return "authorized"
    }
    if contains(c.HostileCountries, country) {
        return "hostile"
    }
    return c.DefaultPolicy
}
```

## Log Retention

### Configuration
```go
type RetentionSettings struct {
    Enabled         bool
    CleanupInterval int  // hours
    Periods         map[string]int  // table -> days
}

// Default periods
var defaultPeriods = map[string]int{
    "events":           30,
    "modsec_logs":      30,
    "firewall_events":  30,
    "vpn_events":       30,
    "heartbeat_events": 30,
    "atp_events":       90,
    "antivirus_events": 90,
    "ban_history":      365,
    "audit_log":        365,
}
```

### Cleanup Worker
```go
func (s *RetentionService) cleanup(ctx context.Context) error {
    for table, days := range s.config.Periods {
        query := fmt.Sprintf(`
            ALTER TABLE vigilance_x.%s DELETE
            WHERE timestamp < now() - INTERVAL %d DAY
        `, table, days)
        s.db.Exec(ctx, query)
    }
    return nil
}
```

---

# Operations

## Deployment

### Docker Compose
```yaml
services:
  api:
    build: ../backend
    ports:
      - "8080:8080"
    environment:
      - CLICKHOUSE_HOST=clickhouse
      - REDIS_HOST=redis
    depends_on:
      - clickhouse
      - redis

  frontend:
    build: ../frontend
    ports:
      - "3000:80"

  clickhouse:
    image: clickhouse/clickhouse-server:24.1
    volumes:
      - clickhouse_data:/var/lib/clickhouse

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  vector:
    image: timberio/vector:0.34.1-alpine
    ports:
      - "514:514/udp"
      - "1514:1514"
    volumes:
      - ./vector/vector.toml:/etc/vector/vector.toml

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
```

### Production Deployment
```bash
# Build and push images
docker build -t ghcr.io/kr1s57/vigilancex-api:latest -f backend/Dockerfile backend/
docker build -t ghcr.io/kr1s57/vigilancex-frontend:latest -f frontend/Dockerfile frontend/
docker push ghcr.io/kr1s57/vigilancex-api:latest
docker push ghcr.io/kr1s57/vigilancex-frontend:latest

# Deploy on server
docker compose pull
docker compose up -d --force-recreate
```

## Configuration Reference

### Environment Variables

```bash
# === Database ===
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=9000
CLICKHOUSE_DATABASE=vigilance_x
CLICKHOUSE_USER=vigilance
CLICKHOUSE_PASSWORD=

# === Redis ===
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=

# === Authentication ===
JWT_SECRET=                    # Min 32 chars
JWT_EXPIRY=24h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!

# === Sophos XGS ===
SOPHOS_HOST=
SOPHOS_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASSWORD=
SOPHOS_SSH_HOST=               # For ModSec sync
SOPHOS_SSH_USER=
SOPHOS_SSH_KEY_PATH=

# === License ===
LICENSE_ENABLED=true
LICENSE_SERVER_URL=https://vigilancekey.example.com
LICENSE_KEY=
LICENSE_GRACE_PERIOD=168h
LICENSE_INSECURE_SKIP_VERIFY=false

# === Threat Intelligence ===
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
GREYNOISE_API_KEY=
CROWDSEC_API_KEY=
PULSEDIVE_API_KEY=
CRIMINALIP_API_KEY=
OTX_API_KEY=
ABUSECH_API_KEY=

# === Notifications ===
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_USE_TLS=true
```

## Monitoring

### Health Endpoints
```
GET /health          # API health
GET /api/v1/status   # Detailed status
```

### Metrics
```go
// Custom metrics exposed
vigilancex_events_total{type="waf"}
vigilancex_bans_active
vigilancex_threat_checks_total{provider="abuseipdb"}
vigilancex_api_requests_total{endpoint="/api/v1/events"}
```

### Logs
```bash
# Structured JSON logs
docker compose logs -f api | jq '.'

# Filter by level
docker compose logs api | grep '"level":"error"'
```

## Troubleshooting

### Common Issues

**API not starting:**
```bash
docker compose logs api
# Check for: DB connection, license validation, config errors
```

**No events received:**
```bash
# Check Vector
docker compose logs vector
# Verify: syslog source, ClickHouse sink, network connectivity
```

**License validation failing:**
```bash
# Check connectivity
curl -k https://vigilancekey.example.com/health

# Enable insecure mode for self-signed certs
LICENSE_INSECURE_SKIP_VERIFY=true
```

**High memory usage (ClickHouse):**
```bash
# Check table sizes
docker compose exec clickhouse clickhouse-client -q "
  SELECT table, formatReadableSize(sum(bytes))
  FROM system.parts
  GROUP BY table
  ORDER BY sum(bytes) DESC
"

# Run optimization
docker compose exec clickhouse clickhouse-client -q "OPTIMIZE TABLE vigilance_x.events FINAL"
```

---

# Development

## Development Setup

```bash
# Clone repository
git clone git@github.com:kr1s57/vigilanceX.git
cd vigilanceX

# Backend
cd backend
go mod download
go run ./cmd/api

# Frontend
cd frontend
npm install
npm run dev

# Docker (full stack)
cd docker
cp .env.example .env
docker compose up -d
```

## Code Conventions

### Go
```go
// File naming: snake_case.go
// Packages: lowercase
// Interfaces: PascalCase (BansRepository)
// Structs: PascalCase (BanStatus)
// Variables: camelCase
// Constants: PascalCase or ALL_CAPS

// Error handling
func (s *Service) DoSomething(ctx context.Context) error {
    result, err := s.repo.Query(ctx)
    if err != nil {
        return fmt.Errorf("query failed: %w", err)
    }
    return nil
}
```

### TypeScript/React
```typescript
// Components: PascalCase
// Hooks: useXxx
// Files: PascalCase.tsx for components, camelCase.ts for utilities
// Types: PascalCase

// Component structure
export function MyComponent({ prop }: Props) {
  const [state, setState] = useState<Type>(initial);

  useEffect(() => {
    // ...
  }, [dep]);

  return <div>...</div>;
}
```

## Git Workflow

### Commit Messages
```
feat(vX.YY.Z): Description of feature
fix(vX.YY.Z): Description of bug fix
refactor(vX.YY.Z): Code refactoring
docs(vX.YY.Z): Documentation update
chore(vX.YY.Z): Maintenance task
```

### Branch Strategy
```
main ──────────────────────────────────►
       │                    │
       └── feature/xxx ─────┘
       │                    │
       └── fix/xxx ─────────┘
```

### Release Process
```bash
# 1. Update version in Settings.tsx
# 2. Update CLAUDE.md header
# 3. Commit changes
git add .
git commit -m "feat(v3.54.102): Description"

# 4. Push to remotes
git push origin main
git push forgejo main

# 5. Create tag
git tag v3.54.102
git push origin v3.54.102

# 6. Create GitHub release
gh release create v3.54.102 --title "VIGILANCE X v3.54.102" --notes "..."
```

## Versioning

### Format: X.YY.Z
| Digit | Name | Description |
|-------|------|-------------|
| X | MAJOR | Major version bump (manual) |
| YY | FEATURE | Feature increment (50→51→52) |
| Z | BUGFIX | Bug fixes (starts at 100) |

### Examples
- `3.54.100` → New feature release
- `3.54.101` → Bug fix
- `3.55.100` → Next feature release
- `4.0.100` → Major version bump

## Testing

### Backend
```bash
cd backend
go test ./...
go test -v ./internal/usecase/...
go test -cover ./...
```

### Frontend
```bash
cd frontend
npm run lint
npm run build  # Type check via build
```

### Integration
```bash
# Start test environment
docker compose -f docker-compose.test.yml up -d

# Run API tests
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'
```

---

# Support

## Contact

**Email:** contact@vigilancex.io

## Resources

- [CLAUDE.md](./CLAUDE.md) - AI memory file with detailed context
- [CHANGELOG.md](./CHANGELOG.md) - Version history
- [docs/](./docs/) - Additional documentation

---

**VIGILANCE X** - Real-Time Security Operations Center Platform

*Built with Go, React, and ClickHouse for high-performance security operations.*
