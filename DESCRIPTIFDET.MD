# VIGILANCE X - Documentation Technique Detaillee

> **Version:** 1.0.0
> **Date:** Janvier 2026
> **Plateforme:** Security Operations Center (SOC) pour Sophos XGS

---

## Table des Matieres

1. [Vue d'Ensemble](#1-vue-densemble)
2. [Architecture Globale](#2-architecture-globale)
3. [Stack Technologique](#3-stack-technologique)
4. [Backend (Go)](#4-backend-go)
5. [Frontend (React/TypeScript)](#5-frontend-reacttypescript)
6. [Base de Donnees (ClickHouse)](#6-base-de-donnees-clickhouse)
7. [Pipeline de Logs (Vector)](#7-pipeline-de-logs-vector)
8. [APIs Externes](#8-apis-externes)
9. [Infrastructure Docker](#9-infrastructure-docker)
10. [Securite](#10-securite)
11. [Endpoints API](#11-endpoints-api)
12. [WebSocket](#12-websocket)
13. [Detect2Ban Engine](#13-detect2ban-engine)

---

## 1. Vue d'Ensemble

**VIGILANCE X** est une plateforme SIEM (Security Information and Event Management) conçue pour surveiller, analyser et repondre aux menaces de securite en temps reel. Elle s'integre avec les pare-feux Sophos XGS pour:

- **Collecter** les logs de securite (WAF, IPS, VPN, Firewall, ATP, Anti-Virus)
- **Analyser** les patterns d'attaque via ModSecurity CRS
- **Enrichir** les donnees avec du renseignement sur les menaces (Threat Intelligence)
- **Bloquer** automatiquement les IPs malveillantes (progressive banning)
- **Visualiser** les metriques de securite en temps reel

### Fonctionnalites Principales

| Fonctionnalite | Description |
|----------------|-------------|
| **Multi-Source Threat Intel** | Integration AbuseIPDB, VirusTotal, AlienVault OTX |
| **ModSec Log Correlation** | Correlation des regles ModSecurity avec les evenements WAF |
| **Progressive Banning** | Systeme de ban progressif (1h -> 4h -> 24h -> permanent) |
| **Real-time Dashboard** | Tableau de bord en temps reel via WebSocket |
| **Report Generation** | Generation de rapports PDF/XML |
| **Geolocation** | Enrichissement geographique des IPs |
| **Sophos XGS Sync** | Synchronisation bidirectionnelle des bans |

---

## 2. Architecture Globale

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VIGILANCE X Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│   │  Sophos XGS  │────>│    Vector    │────>│  ClickHouse  │                │
│   │  (Firewall)  │     │  (Pipeline)  │     │  (Database)  │                │
│   └──────────────┘     └──────────────┘     └──────────────┘                │
│         │                                          │                         │
│         │ SSH (ModSec logs)                        │                         │
│         │ API (Bans sync)                          │                         │
│         ▼                                          ▼                         │
│   ┌──────────────────────────────────────────────────────────────┐          │
│   │                     Backend Go API                            │          │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │          │
│   │  │   Handlers  │  │   Services  │  │   Adapters  │           │          │
│   │  │  (HTTP/WS)  │  │  (UseCase)  │  │  (External) │           │          │
│   │  └─────────────┘  └─────────────┘  └─────────────┘           │          │
│   └──────────────────────────────────────────────────────────────┘          │
│         │                    │                                               │
│         │                    ├─────> AbuseIPDB API                          │
│         │                    ├─────> VirusTotal API                         │
│         │                    └─────> AlienVault OTX API                     │
│         ▼                                                                    │
│   ┌──────────────────────────────────────────────────────────────┐          │
│   │                    Frontend React SPA                         │          │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │          │
│   │  │Dashboard │ │WAF Expl. │ │ Threats  │ │  Bans    │        │          │
│   │  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │          │
│   └──────────────────────────────────────────────────────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Flux de Donnees

1. **Sophos XGS** envoie les logs syslog vers **Vector** (UDP:514, TCP:1514)
2. **Vector** parse, categorise et insere les evenements dans **ClickHouse**
3. **Backend Go** interroge ClickHouse et enrichit avec Threat Intelligence
4. **Frontend React** affiche les donnees et recoit les mises a jour via WebSocket
5. **Detect2Ban** analyse les patterns et declenche des bans automatiques

---

## 3. Stack Technologique

### Backend

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Langage | Go | 1.22 |
| Router HTTP | Chi | 5.0.12 |
| WebSocket | Gorilla WebSocket | 1.5.1 |
| Database Client | clickhouse-go | 2.23.0 |
| Configuration | Viper | 1.18.2 |
| PDF Generation | go-pdf/fpdf | 0.9.0 |
| UUID | google/uuid | 1.6.0 |

### Frontend

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Framework | React | 18.2.0 |
| Langage | TypeScript | 5.3 |
| Build Tool | Vite | 5.1.4 |
| Routing | React Router | 6.22.1 |
| State Management | Zustand | 4.5.1 |
| HTTP Client | Axios | 1.6.7 |
| Charts | Recharts | 2.12.2 |
| Icons | Lucide React | 0.330.0 |
| Styling | Tailwind CSS | 3.4.1 |
| UI Components | Radix UI | Latest |

### Infrastructure

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Database | ClickHouse | 24.1 |
| Cache | Redis | 7 (Alpine) |
| Log Pipeline | Vector | 0.34.1 |
| Reverse Proxy | Nginx | Alpine |
| Containerisation | Docker Compose | 3.8 |

---

## 4. Backend (Go)

### 4.1 Architecture Clean Architecture

Le backend suit une architecture en couches avec separation claire des responsabilites:

```
backend/
├── cmd/
│   ├── api/main.go              # Point d'entree API
│   └── detect2ban/main.go       # Daemon de detection
├── internal/
│   ├── config/                  # Configuration (Viper)
│   ├── entity/                  # Modeles de domaine
│   ├── usecase/                 # Logique metier (Services)
│   └── adapter/
│       ├── controller/          # HTTP Handlers + WebSocket
│       ├── repository/          # Acces donnees (ClickHouse)
│       └── external/            # APIs externes
└── scenarios/                   # Regles Detect2Ban (YAML)
```

### 4.2 Entites (Domain Models)

#### Event (Evenement de Securite)
```go
type Event struct {
    EventID     uuid.UUID  // Identifiant unique
    Timestamp   time.Time  // Horodatage

    // Classification
    LogType     string     // WAF, IPS, ATP, Anti-Virus, Firewall, VPN
    Category    string     // SQL Injection, Brute Force, etc.
    SubCategory string
    Severity    string     // critical, high, medium, low, info

    // Reseau
    SrcIP       string     // IP source
    DstIP       string     // IP destination
    SrcPort     uint16
    DstPort     uint16
    Protocol    string     // TCP, UDP, ICMP

    // Action
    Action      string     // allow, drop, reject, quarantine
    RuleID      string
    RuleName    string

    // Contexte
    Hostname    string
    URL         string
    UserAgent   string

    // Geolocalisation
    GeoCountry  string
    GeoCity     string
    GeoASN      uint32

    // Enrichissement ModSec
    ModSecRuleIDs  []string  // IDs des regles ModSec declenchees
    ModSecMessages []string  // Messages des regles
}
```

#### ThreatScore (Score de Menace)
```go
type ThreatScore struct {
    IP              string
    AggregatedScore int       // Score agrege (0-100)
    ThreatLevel     string    // critical, high, medium, low, minimal

    // Scores par source
    AbuseIPDBScore    int     // Score AbuseIPDB (0-100)
    AbuseIPDBReports  int     // Nombre de signalements
    VirusTotalScore   int     // Score VirusTotal (0-100)
    VirusTotalPositives int   // Detections positives
    OTXScore          int     // Score AlienVault OTX

    // Metadata
    IsTor           bool      // Noeud de sortie Tor
    MalwareFamilies []string  // Familles de malware associees
    Categories      []string  // Categories de menace

    LastChecked     time.Time // Derniere verification
}
```

#### BanStatus (Statut de Ban)
```go
type BanStatus struct {
    IP          string
    Status      string    // active, expired, permanent
    BanCount    int       // Nombre de bans (recidive)
    FirstBan    time.Time
    LastBan     time.Time
    ExpiresAt   *time.Time // nil si permanent
    Reason      string
    Source      string    // manual, detect2ban, threat_intel
    SyncedXGS   bool      // Synchronise avec Sophos
}
```

#### ModSecLog (Log ModSecurity)
```go
type ModSecLog struct {
    ID            string
    Timestamp     time.Time
    UniqueID      string    // Groupe tous les logs d'une requete
    SrcIP         string
    Hostname      string
    URI           string
    RuleID        string    // Ex: "920320", "949110"
    RuleFile      string    // Fichier CRS
    RuleMsg       string    // Message descriptif
    RuleSeverity  string    // NOTICE, WARNING, CRITICAL
    AttackType    string    // sqli, xss, lfi, rfi, rce
    ParanoiaLevel uint8     // 1-4
    TotalScore    uint16    // Score d'anomalie accumule
    IsBlocking    bool      // A cause le blocage
}
```

### 4.3 Services (Use Cases)

#### Events Service
```go
// Gestion des evenements de securite
type EventsService interface {
    ListEvents(ctx, filters, limit, offset) ([]Event, uint64, error)
    GetEvent(ctx, eventID) (*Event, error)
    GetTimeline(ctx, period, interval) ([]TimelinePoint, error)
    GetOverview(ctx, period) (*OverviewResponse, error)
    GetTopAttackers(ctx, period, limit) ([]TopAttacker, error)
    GetTopTargets(ctx, period, limit) ([]TopTarget, error)
    GetGeoHeatmap(ctx, period) ([]GeoData, error)
    GetSyslogStatus(ctx) (*SyslogStatus, error)
    GetCriticalAlerts(ctx, limit) ([]CriticalAlert, error)
}
```

#### Threats Service
```go
// Gestion du renseignement sur les menaces
type ThreatsService interface {
    CheckIP(ctx, ip) (*ThreatScore, error)           // Verification temps reel
    GetStoredScore(ctx, ip) (*ThreatScore, error)    // Score en cache
    GetTopThreats(ctx, limit) ([]ThreatScore, error)
    GetThreatsByLevel(ctx, level, limit) ([]ThreatScore, error)
    ShouldBan(ctx, ip) (bool, string, error)         // Decision de ban
    ClearCache() error
}
```

#### Bans Service
```go
// Gestion des bans IP
type BansService interface {
    List(ctx) ([]BanStatus, error)
    Get(ctx, ip) (*BanStatus, error)
    Create(ctx, ip, reason, permanent) (*BanStatus, error)
    Delete(ctx, ip) error
    Extend(ctx, ip, days) (*BanStatus, error)
    MakePermanent(ctx, ip) (*BanStatus, error)
    GetHistory(ctx, ip) ([]BanHistory, error)
    SyncWithSophos(ctx) error
}
```

#### ModSec Service
```go
// Synchronisation des logs ModSecurity
type ModSecService interface {
    Start(ctx)                    // Demarre le sync background
    Stop()
    SyncNow(ctx) error           // Sync immediat
    GetStats() *SyncStats
    RefreshGeolocation(ctx) (int, error)  // Rafraichit les geolocalisations
}
```

### 4.4 Adaptateurs Externes

#### Threat Intelligence Aggregator

Le systeme agrege les donnees de 3 providers avec ponderation configurable:

```go
type AggregatorConfig struct {
    AbuseIPDBKey  string
    VirusTotalKey string
    OTXKey        string
    CacheTTL      time.Duration  // Default: 24h
}

// Ponderations par defaut
const (
    AbuseIPDBWeight  = 0.40  // 40%
    VirusTotalWeight = 0.35  // 35%
    OTXWeight        = 0.25  // 25%
)
```

##### AbuseIPDB
- **API:** `https://api.abuseipdb.com/api/v2/check`
- **Donnees:** Confidence Score (0-100), Reports, Country, ISP, Tor status
- **Rate Limit:** 1000 req/jour (gratuit)

##### VirusTotal
- **API:** `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- **Donnees:** Malicious/Suspicious counts, Reputation, Tags
- **Scoring:** Ratio malicious/total + reputation penalty
- **Rate Limit:** 4 req/min (gratuit)

##### AlienVault OTX
- **API:** `https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}`
- **Donnees:** Pulses count, Malware families, Adversaries
- **Scoring:** Pulses * 5 + ThreatScore * 0.3 + Malware * 5

#### Sophos XGS Client

Integration avec le pare-feu via deux methodes:

**1. API XML (Port 4444)**
```xml
<!-- Ajout d'IP au blocklist -->
<Request>
  <Login>
    <Username>admin</Username>
    <Password>***</Password>
  </Login>
  <Set operation="add">
    <IPHost>
      <Name>bannedIP_192.168.1.100</Name>
      <IPFamily>IPv4</IPFamily>
      <HostType>IP</HostType>
      <IPAddress>192.168.1.100</IPAddress>
      <HostGroupList>
        <HostGroup>VIGILANCE_X_BLOCKLIST</HostGroup>
      </HostGroupList>
    </IPHost>
  </Set>
</Request>
```

**2. SSH (Port 22)**
- Connexion via cle SSH pour recuperer les logs ModSecurity
- Navigation menu: Device Management (5) -> Advanced Shell (3)
- Commande: `tail -10000 /log/reverseproxy.log | grep 'security2:error'`

#### Geolocation Service

- **API:** `http://ip-api.com/json/{ip}`
- **Cache:** Memoire + ClickHouse
- **Donnees:** Country, City, Region, Lat/Long, ISP, ASN, Proxy/Tor flags
- **Refresh:** Mensuel (1er du mois a 3h)

---

## 5. Frontend (React/TypeScript)

### 5.1 Structure du Projet

```
frontend/src/
├── App.tsx                 # Router principal
├── main.tsx               # Point d'entree
├── index.css              # Styles globaux (Tailwind)
├── types/
│   └── index.ts           # Interfaces TypeScript
├── lib/
│   ├── api.ts             # Client Axios
│   ├── websocket.ts       # Manager WebSocket
│   └── utils.ts           # Utilitaires
├── hooks/
│   └── useWebSocket.ts    # Hooks WebSocket
├── stores/
│   ├── eventsStore.ts     # Store Zustand
│   └── bansStore.ts
├── components/
│   ├── layout/            # Header, Sidebar, Layout
│   ├── dashboard/         # StatCard
│   ├── charts/            # TimelineChart, SeverityChart
│   └── IPThreatModal.tsx  # Modal de menace IP
└── pages/
    ├── Dashboard.tsx      # Tableau de bord
    ├── WafExplorer.tsx    # Exploration ModSec
    ├── AttacksAnalyzer.tsx # Analyse des attaques
    ├── AdvancedThreat.tsx # Threat Intelligence
    ├── VpnNetwork.tsx     # VPN & Reseau
    ├── ActiveBans.tsx     # Gestion des bans
    └── Reports.tsx        # Generation de rapports
```

### 5.2 Routes

| Route | Composant | Description |
|-------|-----------|-------------|
| `/` | Dashboard | Vue d'ensemble avec KPIs et timeline |
| `/waf` | WafExplorer | Exploration des regles ModSecurity |
| `/attacks` | AttacksAnalyzer | Analyse des patterns d'attaque |
| `/threats` | AdvancedThreat | Dashboard Threat Intelligence |
| `/vpn` | VpnNetwork | Sessions VPN et evenements reseau |
| `/bans` | ActiveBans | Gestion des IPs bannies |
| `/reports` | Reports | Generation de rapports PDF/XML |

### 5.3 Pages Detaillees

#### Dashboard (`Dashboard.tsx`)

**Fonctionnalites:**
- 4 cartes KPI: Total Events, Blocked, Critical Alerts, Unique IPs
- Graphique timeline (evenements/heure ou /jour)
- Camembert de severite
- Top 5 attaquants avec drapeaux pays
- Distribution par type de log
- Modal alertes critiques (cliquable)

**APIs appelees:**
```typescript
statsApi.overview(period)       // Stats globales
eventsApi.timeline(period)      // Donnees timeline
alertsApi.critical(20)          // Alertes critiques
```

**Rafraichissement:** Automatique toutes les 30 secondes

---

#### WAF Explorer (`WafExplorer.tsx`)

**Fonctionnalites:**
- Vue groupee par jour avec collapse/expand
- Vue liste plate
- Filtres: recherche, hostname, type d'attaque
- Details expandables par requete (unique_id)
- Affichage de toutes les regles declenchees
- Score d'anomalie et statut (Blocked/Detected)
- Bouton Sync avec ModSec backend

**APIs appelees:**
```typescript
modsecApi.getGroupedLogs(filters)  // Logs groupes par requete
modsecApi.getHostnames()           // Liste des hosts
modsecApi.getStats()               // Statut du sync
modsecApi.syncNow()                // Declenchement sync
```

**Colonnes affichees:**
| Colonne | Description |
|---------|-------------|
| Time | Horodatage de la detection |
| Source IP | IP attaquante + geoloc |
| Target | Hostname + URI |
| Rules | Nombre de regles + IDs |
| Score | Score d'anomalie cumule |
| Status | Blocked (rouge) / Detected (orange) |

---

#### Attacks Analyzer (`AttacksAnalyzer.tsx`)

**Fonctionnalites:**
- 4 cartes KPI: Total Triggers, Categories, Top Attack, Unique IPs
- Camembert distribution des types d'attaque
- Barres horizontales des regles les plus declenchees
- Liste detaillee des regles avec expansion
- Top attaquants avec modal de recherche
- Integration modal IP Threat

**APIs appelees:**
```typescript
modsecApi.getRuleStats(period)       // Stats par regle
modsecApi.getAttackTypeStats(period) // Stats par type
statsApi.topAttackers(period, 100)   // Top attaquants
bansApi.list()                       // Liste des bans
```

**Types d'attaque detectes:**
- SQL Injection (sqli)
- Cross-Site Scripting (xss)
- Local File Inclusion (lfi)
- Remote File Inclusion (rfi)
- Remote Code Execution (rce)
- Protocol Violations
- Scanner Detection

---

#### Advanced Threat (`AdvancedThreat.tsx`)

**Fonctionnalites:**
- 5 cartes KPI: Tracked, Critical, High, Tor Nodes, Checks 24h
- Indicateurs de statut des providers (AbuseIPDB, VT, OTX)
- Taux de hit cache
- Filtres par niveau de menace
- Formulaire de recherche IP
- Tableau des menaces avec scores detailles

**APIs appelees:**
```typescript
threatsApi.stats()         // Statistiques globales
threatsApi.providers()     // Statut des providers
threatsApi.list(50)        // Liste des menaces
threatsApi.check(ip)       // Verification temps reel
```

**Colonnes du tableau:**
| Colonne | Description |
|---------|-------------|
| IP | Adresse IP |
| Country | Drapeau + code pays |
| Score | Score agrege (0-100) avec couleur |
| Level | Badge niveau de menace |
| AbuseIPDB | Score AbuseIPDB |
| VirusTotal | Score VirusTotal |
| Tor | Indicateur noeud Tor |
| Last Check | Derniere verification |

---

#### VPN & Network (`VpnNetwork.tsx`)

**Fonctionnalites:**
- 5 cartes stats: VPN Sessions, Users, FW Events, IPS, Blocked
- Camembert distribution par type
- Barres trafic par pays
- Section VPN expandable avec recherche
- Section Network expandable (Firewall + IPS)
- Distribution des protocoles

**APIs appelees:**
```typescript
statsApi.overview(period)
eventsApi.list({ log_type: 'VPN', ... })
eventsApi.list({ log_type: 'Firewall', ... })
eventsApi.list({ log_type: 'IPS', ... })
geoApi.heatmap(period)
```

---

#### Active Bans (`ActiveBans.tsx`)

**Fonctionnalites:**
- 4 cartes stats: Active, Permanent, New 24h, Recidivists
- Tableau des bans avec actions
- Formulaire d'ajout de ban
- Section Whitelist avec gestion
- Bouton Sync XGS
- Integration modal IP Threat (clic sur ligne)

**APIs appelees:**
```typescript
bansApi.list()          // Liste des bans actifs
bansApi.stats()         // Statistiques
bansApi.create(...)     // Creation de ban
bansApi.delete(ip)      // Suppression
bansApi.extend(ip, d)   // Extension
bansApi.sync()          // Sync avec Sophos
whitelistApi.list()     // Whitelist
whitelistApi.add/remove // Gestion whitelist
```

**Actions disponibles:**
- **Unban:** Supprime le ban
- **Extend:** Prolonge de X jours
- **Make Permanent:** Ban definitif

---

#### Reports (`Reports.tsx`)

**Fonctionnalites:**
- Cartes stats DB: Taille, Total Events, Plage dates
- Grille events par type
- Tableau stats des tables
- Rapports rapides: Daily, Weekly, Monthly
- Constructeur rapport personnalise
- Selecteur format PDF/XML

**APIs appelees:**
```typescript
reportsApi.getDBStats()         // Stats base de donnees
reportsApi.generate(config)     // Generation + download
```

**Modules de rapport:**
- WAF / ModSecurity
- VPN & Network
- Threat Intelligence
- Bans & Whitelist

---

### 5.4 Composants Reutilisables

#### Header (`Header.tsx`)
- Indicateur WebSocket (WSocket - vert/rouge)
- Indicateur Syslog (vert/rouge)
- Timestamp derniere mise a jour
- Cloche notifications avec dropdown
- Gestion lu/non-lu (localStorage)
- Navigation vers page de detection au clic

#### Sidebar (`Sidebar.tsx`)
- Logo VIGILANCE X
- Navigation avec icones
- Indication page active
- Lien parametres

#### StatCard (`StatCard.tsx`)
```typescript
Props: {
  title: string
  value: string | number
  subtitle?: string
  icon?: ReactNode
  variant?: 'default' | 'critical' | 'warning' | 'success'
}
```

#### IPThreatModal (`IPThreatModal.tsx`)
- Score agrege avec jauge visuelle
- Niveau de menace avec badge
- Scores individuels par provider
- Tags et informations reseau
- Liens vers sites externes
- Bouton refresh

#### Charts
- **TimelineChart:** AreaChart Recharts avec gradients
- **SeverityChart:** PieChart donut avec couleurs par severite

### 5.5 WebSocket

**Manager (`websocket.ts`):**
- Singleton avec reconnexion automatique
- Backoff exponentiel (3s -> 6s -> 12s...)
- Max 10 tentatives
- Systeme de souscription par type

**Hooks (`useWebSocket.ts`):**
```typescript
useWebSocket()              // Statut connexion
useWebSocketSubscription()  // Souscription generique
useRealtimeEvents()         // Evenements en temps reel
useRealtimeBans()           // Mises a jour bans
useRealtimeAlerts()         // Alertes critiques
```

### 5.6 Utilitaires (`utils.ts`)

**Formatage:**
- `formatNumber(n)` - "1.2K", "3.4M"
- `formatPercent(n)` - "45.2%"
- `formatDateTime(d)` - Date + heure complete
- `getCountryFlag(code)` - Emoji drapeau Unicode
- `getCountryName(code)` - Nom complet du pays

**Couleurs:**
- `getSeverityColor(severity)` - Couleur texte
- `getSeverityBgColor(severity)` - Couleur fond
- `getThreatLevelColor(level)` - Couleur niveau menace

---

## 6. Base de Donnees (ClickHouse)

### 6.1 Configuration

- **Database:** `vigilance_x`
- **Engine principal:** MergeTree (partitionne par jour)
- **TTL par defaut:** 90 jours pour les evenements
- **Compression:** ZSTD pour les raw logs

### 6.2 Tables Principales

#### events (Evenements de securite)
```sql
CREATE TABLE events (
    event_id UUID,
    timestamp DateTime CODEC(Delta, ZSTD),
    log_type LowCardinality(String),      -- WAF, IPS, VPN, Firewall...
    category LowCardinality(String),
    severity LowCardinality(String),      -- critical, high, medium, low
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    protocol LowCardinality(String),
    action LowCardinality(String),        -- allow, drop, reject
    rule_id String,
    hostname String,
    url String,
    user_agent String,
    geo_country String,
    geo_city String,
    message String,
    raw_log String CODEC(ZSTD(3)),
    modsec_rule_ids Array(String),
    modsec_messages Array(String),
    ingested_at DateTime DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (log_type, severity, src_ip, timestamp)
TTL timestamp + INTERVAL 90 DAY
```

**Index:**
- `idx_src_ip` - bloom_filter(src_ip)
- `idx_rule_id` - bloom_filter(rule_id)
- `idx_hostname` - bloom_filter(hostname)

#### modsec_logs (Logs ModSecurity)
```sql
CREATE TABLE modsec_logs (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime64(6),
    unique_id String,                     -- Groupe une requete
    src_ip IPv4,
    hostname String,
    uri String,
    rule_id String,
    rule_file String,
    rule_msg String,
    rule_severity LowCardinality(String),
    rule_data String,
    crs_version String,
    paranoia_level UInt8,
    attack_type LowCardinality(String),   -- sqli, xss, lfi, rfi, rce
    anomaly_score UInt16,
    total_score UInt16,
    is_blocking UInt8,
    tags Array(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, unique_id, rule_id)
TTL timestamp + INTERVAL 90 DAY
```

#### ip_threat_scores (Cache Threat Intel)
```sql
CREATE TABLE ip_threat_scores (
    ip IPv4,
    aggregated_score UInt8,
    threat_level LowCardinality(String),
    abuseipdb_score UInt8,
    abuseipdb_reports UInt32,
    virustotal_score UInt8,
    virustotal_positives UInt16,
    otx_score UInt8,
    is_tor UInt8,
    categories Array(String),
    malware_families Array(String),
    first_seen DateTime,
    last_seen DateTime,
    last_checked DateTime,
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip
TTL last_checked + INTERVAL 7 DAY
```

#### ip_ban_status (Statut des bans)
```sql
CREATE TABLE ip_ban_status (
    ip IPv4,
    status LowCardinality(String),        -- active, expired, permanent
    ban_count UInt16,
    first_ban DateTime,
    last_ban DateTime,
    expires_at Nullable(DateTime),
    reason String,
    source LowCardinality(String),
    trigger_rule String,
    synced_xgs UInt8,
    version UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY ip
```

#### ban_history (Audit trail)
```sql
CREATE TABLE ban_history (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    ip IPv4,
    action LowCardinality(String),        -- ban, unban, extend, permanent
    previous_status String,
    new_status String,
    duration_hours Nullable(UInt32),
    reason String,
    performed_by String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, ip)
TTL timestamp + INTERVAL 365 DAY
```

#### ip_geolocation (Cache geolocalisation)
```sql
CREATE TABLE ip_geolocation (
    ip IPv4,
    country_code LowCardinality(String),
    country_name String,
    city String,
    region String,
    latitude Float64,
    longitude Float64,
    asn UInt32,
    org String,
    isp String,
    is_proxy UInt8,
    is_hosting UInt8,
    is_tor UInt8,
    updated_at DateTime
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ip
```

### 6.3 Vues Materialisees

#### stats_hourly (Agregation horaire)
```sql
CREATE MATERIALIZED VIEW stats_hourly_mv TO stats_hourly AS
SELECT
    toStartOfHour(timestamp) as hour,
    log_type,
    severity,
    action,
    count() as event_count,
    uniqExact(src_ip) as unique_ips,
    uniqExact(rule_id) as unique_rules
FROM events
GROUP BY hour, log_type, severity, action
```

#### stats_ip_daily (Stats par IP/jour)
```sql
CREATE MATERIALIZED VIEW stats_ip_daily_mv TO stats_ip_daily AS
SELECT
    toDate(timestamp) as date,
    src_ip,
    count() as event_count,
    countIf(action IN ('drop', 'reject')) as blocked_count,
    countIf(severity IN ('critical', 'high')) as high_severity_count
FROM events
GROUP BY date, src_ip
```

### 6.4 Retention des Donnees

| Table | Retention |
|-------|-----------|
| events | 90 jours |
| modsec_logs | 90 jours |
| vpn_events | 90 jours |
| firewall_events | 30 jours |
| atp_events | 180 jours |
| antivirus_events | 180 jours |
| heartbeat_events | 30 jours |
| ban_history | 365 jours |
| audit_log | 365 jours |
| ip_threat_scores | 7 jours |

---

## 7. Pipeline de Logs (Vector)

### 7.1 Configuration

**Fichier:** `/docker/vector/vector.toml`

### 7.2 Sources (Entrees)

```toml
[sources.sophos_syslog_udp]
type = "socket"
address = "0.0.0.0:514"
mode = "udp"
max_length = 102400

[sources.sophos_syslog_tcp]
type = "socket"
address = "0.0.0.0:1514"
mode = "tcp"
max_length = 102400
```

### 7.3 Transformations

#### 1. Parsing Sophos (`parse_sophos`)
- Parse le format key=value de Sophos
- Supprime les headers syslog (PRI, timestamp, hostname)
- Detection du type de log:
  - WAF: "Web Application Firewall", "Reverse Proxy"
  - VPN: "SSL VPN", "IPSec VPN"
  - IPS: Detection avant substring generique
  - ATP: "Sandstorm"
  - etc.

#### 2. Categorisation (`categorize_attacks`)
Categorise les evenements par type d'attaque:

| LogType | Categories |
|---------|------------|
| WAF | SQL Injection, XSS, RCE, LFI, RFI, Scanner, Bot |
| IPS | Network Scan, Exploit, DoS, Brute Force |
| ATP | C2 Communication, Malware, Phishing |
| VPN | VPN Attack, Auth Failure, Connection |
| Firewall | Blocked, Allowed |

#### 3. Preparation (`prepare_events`)
- Formatage timestamp
- Mapping vers schema ClickHouse
- Selection des champs pertinents

### 7.4 Sinks (Sorties)

```toml
[sinks.clickhouse_events]
type = "clickhouse"
endpoint = "http://clickhouse:8123"
database = "vigilance_x"
table = "events"
compression = "gzip"
batch.max_events = 5000
batch.timeout_secs = 5
```

---

## 8. APIs Externes

### 8.1 AbuseIPDB

**URL:** `https://api.abuseipdb.com/api/v2`

**Endpoint:** `GET /check?ipAddress={ip}&maxAgeInDays=90`

**Headers:**
```
Key: {ABUSEIPDB_API_KEY}
Accept: application/json
```

**Reponse:**
```json
{
  "data": {
    "ipAddress": "192.168.1.100",
    "abuseConfidenceScore": 85,
    "totalReports": 42,
    "numDistinctUsers": 15,
    "countryCode": "RU",
    "isp": "Example ISP",
    "isTor": false,
    "isWhitelisted": false
  }
}
```

**Scoring:** Utilise directement `abuseConfidenceScore` (0-100)

### 8.2 VirusTotal

**URL:** `https://www.virustotal.com/api/v3`

**Endpoint:** `GET /ip_addresses/{ip}`

**Headers:**
```
x-apikey: {VIRUSTOTAL_API_KEY}
```

**Reponse:**
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 5,
        "suspicious": 2,
        "harmless": 80,
        "undetected": 3
      },
      "reputation": -15,
      "asn": 12345,
      "as_owner": "Example AS",
      "country": "US"
    }
  }
}
```

**Scoring:**
```
score = (malicious + suspicious) / total * 100
if reputation < 0: score += min(abs(reputation), 50)
```

### 8.3 AlienVault OTX

**URL:** `https://otx.alienvault.com/api/v1`

**Endpoints:**
- `GET /indicators/IPv4/{ip}/general`
- `GET /indicators/IPv4/{ip}/reputation`

**Headers:**
```
X-OTX-API-KEY: {ALIENVAULT_API_KEY}
```

**Reponse (general):**
```json
{
  "pulse_info": {
    "count": 15,
    "pulses": [...]
  },
  "asn": "AS12345 Example",
  "country_name": "United States"
}
```

**Scoring:**
```
score = min(pulse_count * 5, 50)
      + min(threat_score * 0.3, 30)
      + min(malware_count * 5, 20)
```

### 8.4 ip-api.com (Geolocalisation)

**URL:** `http://ip-api.com/json/{ip}`

**Reponse:**
```json
{
  "country": "United States",
  "countryCode": "US",
  "city": "New York",
  "region": "NY",
  "lat": 40.7128,
  "lon": -74.0060,
  "isp": "Example ISP",
  "org": "Example Org",
  "as": "AS12345 Example",
  "proxy": false,
  "hosting": true
}
```

---

## 9. Infrastructure Docker

### 9.1 Services

| Service | Image | Ports | Role |
|---------|-------|-------|------|
| **clickhouse** | clickhouse-server:24.1 | 8123, 9000 | Base de donnees analytique |
| **redis** | redis:7-alpine | 6379 | Cache et sessions |
| **vector** | timberio/vector:0.34.1 | 514/UDP, 1514/TCP | Pipeline de logs |
| **backend** | golang:1.22 (build) | 8080 | API REST + WebSocket |
| **detect2ban** | golang:1.22 (build) | - | Daemon de detection |
| **frontend** | node:20-alpine | 3000 | Interface React |
| **nginx** | nginx:alpine | 80, 443 | Reverse proxy (prod) |

### 9.2 Reseau

```yaml
networks:
  vigilance_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### 9.3 Volumes

```yaml
volumes:
  clickhouse_data:   # Donnees ClickHouse
  clickhouse_logs:   # Logs ClickHouse
  redis_data:        # Donnees Redis
  vector_data:       # Buffer Vector
```

### 9.4 Variables d'Environnement

**Requises:**
```bash
CLICKHOUSE_PASSWORD=xxx
REDIS_PASSWORD=xxx
JWT_SECRET=xxx
SOPHOS_HOST=192.168.1.1
SOPHOS_USER=admin
SOPHOS_PASSWORD=xxx
```

**APIs Threat Intel:**
```bash
ABUSEIPDB_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
ALIENVAULT_API_KEY=xxx
```

**Optionnelles:**
```bash
APP_ENV=production
SOPHOS_PORT=4444
SOPHOS_SSH_PORT=22
SOPHOS_SSH_SYNC_INTERVAL=5m
SOPHOS_BAN_GROUP=grp_SOC-BannedIP
```

### 9.5 Health Checks

```yaml
clickhouse:
  healthcheck:
    test: clickhouse-client --query "SELECT 1"
    interval: 10s
    timeout: 5s

redis:
  healthcheck:
    test: redis-cli -a $PASSWORD ping
    interval: 10s
    timeout: 3s

backend:
  healthcheck:
    test: wget http://localhost:8080/health
    interval: 30s
    timeout: 10s
```

---

## 10. Securite

### 10.1 TLS/SSL (Production)

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
add_header Strict-Transport-Security "max-age=63072000" always;
```

### 10.2 Rate Limiting

```nginx
# API generale
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

# Login strict
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
```

### 10.3 Headers de Securite

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### 10.4 Authentification

- **JWT Tokens:** Expiration 24h
- **Roles:** admin, analyst, viewer
- **ClickHouse:** Utilisateur dedie avec mot de passe SHA256
- **Redis:** Mot de passe requis
- **SSH Sophos:** Authentification par cle

---

## 11. Endpoints API

### 11.1 Events

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/events` | Liste paginee avec filtres |
| GET | `/api/v1/events/{id}` | Detail d'un evenement |
| GET | `/api/v1/events/timeline` | Donnees timeline |
| GET | `/api/v1/events/hostnames` | Hostnames uniques |

**Parametres de filtre:**
- `log_type` - Type de log (WAF, IPS, VPN...)
- `severity` - Severite (critical, high, medium, low)
- `src_ip` - IP source
- `hostname` - Hostname cible
- `start_time` / `end_time` - Plage temporelle
- `limit` / `offset` - Pagination

### 11.2 Stats

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/stats/overview` | Vue d'ensemble |
| GET | `/api/v1/stats/top-attackers` | Top IPs attaquantes |
| GET | `/api/v1/stats/top-targets` | Top cibles |
| GET | `/api/v1/geo/heatmap` | Distribution geographique |

### 11.3 Threats

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/threats/` | Liste des menaces |
| GET | `/api/v1/threats/stats` | Statistiques |
| GET | `/api/v1/threats/providers` | Statut providers |
| GET | `/api/v1/threats/check/{ip}` | Verification temps reel |
| GET | `/api/v1/threats/score/{ip}` | Score en cache |
| GET | `/api/v1/threats/should-ban/{ip}` | Decision de ban |
| POST | `/api/v1/threats/cache/clear` | Vider le cache |

### 11.4 Bans

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/bans/` | Liste des bans actifs |
| GET | `/api/v1/bans/stats` | Statistiques |
| GET | `/api/v1/bans/{ip}` | Detail d'un ban |
| GET | `/api/v1/bans/{ip}/history` | Historique |
| POST | `/api/v1/bans/` | Creer un ban |
| DELETE | `/api/v1/bans/{ip}` | Supprimer un ban |
| POST | `/api/v1/bans/{ip}/extend` | Prolonger |
| POST | `/api/v1/bans/{ip}/permanent` | Rendre permanent |
| POST | `/api/v1/bans/sync` | Sync avec Sophos |

### 11.5 Whitelist

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/whitelist/` | Liste |
| POST | `/api/v1/whitelist/` | Ajouter |
| DELETE | `/api/v1/whitelist/{ip}` | Supprimer |

### 11.6 ModSec

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/modsec/logs` | Logs pagines |
| GET | `/api/v1/modsec/logs/grouped` | Groupes par requete |
| GET | `/api/v1/modsec/hostnames` | Hostnames |
| GET | `/api/v1/modsec/rules/stats` | Stats par regle |
| GET | `/api/v1/modsec/attacks/stats` | Stats par type |
| GET | `/api/v1/modsec/stats` | Statut sync |
| POST | `/api/v1/modsec/sync` | Sync immediat |
| GET | `/api/v1/modsec/test` | Test connexion SSH |

### 11.7 Reports

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/reports/stats` | Stats base de donnees |
| GET | `/api/v1/reports/preview` | Apercu rapport |
| GET/POST | `/api/v1/reports/generate` | Generation PDF/XML |

### 11.8 Status & Alerts

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/status/syslog` | Statut syslog |
| GET | `/api/v1/alerts/critical` | Alertes critiques |

---

## 12. WebSocket

### 12.1 Connexion

**Endpoint:** `ws://localhost:8080/ws` ou `wss://domain/ws`

### 12.2 Types de Messages

```typescript
type WSMessageType =
  | 'new_event'      // Nouvel evenement
  | 'ban_update'     // Mise a jour ban
  | 'threat_alert'   // Alerte menace
  | 'anomaly'        // Anomalie detectee
  | 'stats_update'   // Mise a jour stats
```

### 12.3 Format des Messages

```json
{
  "type": "new_event",
  "payload": {
    "event_id": "uuid",
    "timestamp": "2026-01-07T10:30:00Z",
    "log_type": "WAF",
    "severity": "high",
    "src_ip": "192.168.1.100",
    "message": "SQL Injection detected"
  },
  "timestamp": "2026-01-07T10:30:00Z",
  "topic": "events"
}
```

### 12.4 Topics

- `events` - Evenements de securite
- `bans` - Operations de ban
- `alerts` - Alertes critiques
- `stats` - Mises a jour statistiques

---

## 13. Detect2Ban Engine

### 13.1 Scenarios

Les scenarios de detection sont definis en YAML:

#### Brute Force Detection
```yaml
name: brute_force
description: Detect brute force attacks
enabled: true
priority: 5
window: 10m
conditions:
  - field: log_type
    operator: in
    value: [VPN, WAF, Firewall]
  - field: category
    operator: in
    value: [Auth Failure, Brute Force, Login Failure]
  - field: count
    operator: ">="
    value: 10
group_by: [src_ip]
scoring:
  base: 30
  per_event: 3
  max_additional: 50
actions:
  - type: check_whitelist
  - type: ban
    progressive: true
    sync_xgs: true
cooldown: 30m
```

#### WAF Attacks Detection
```yaml
name: waf_attacks
description: Detect WAF attacks
enabled: true
priority: 10
window: 5m
conditions:
  - field: log_type
    operator: "="
    value: WAF
  - field: action
    operator: "="
    value: drop
  - field: count
    operator: ">="
    value: 5
group_by: [src_ip]
scoring:
  base: 20
  per_event: 2
  max_additional: 40
  severity_multipliers:
    critical: 3
    high: 2
    medium: 1.5
    low: 1
actions:
  - type: check_threat_intel
    min_score: 50
  - type: check_whitelist
  - type: ban
    progressive: true
    sync_xgs: true
cooldown: 60m
```

### 13.2 Systeme de Ban Progressif

| Ban Count | Duree |
|-----------|-------|
| 1 | 1 heure |
| 2 | 4 heures |
| 3 | 24 heures |
| 4+ | Permanent |

### 13.3 Integration Sophos

- Creation automatique du groupe `VIGILANCE_X_BLOCKLIST`
- Nommage des objets: `bannedIP_{ip}`
- Synchronisation bidirectionnelle
- Import des bans existants du Sophos

---

## Annexes

### A. Codes de Severite

| Code | Couleur | Description |
|------|---------|-------------|
| critical | Rouge | Menace immediate, action requise |
| high | Orange | Risque eleve, attention requise |
| medium | Jaune | Risque modere, surveillance |
| low | Bleu | Risque faible, informatif |
| info | Gris | Information generale |

### B. Types d'Attaque ModSec

| Code | Description | Regles CRS |
|------|-------------|------------|
| sqli | SQL Injection | 942xxx |
| xss | Cross-Site Scripting | 941xxx |
| lfi | Local File Inclusion | 930xxx |
| rfi | Remote File Inclusion | 931xxx |
| rce | Remote Code Execution | 932xxx |
| protocol | Protocol Violations | 920xxx |

### C. Mappings Pays (ISO 3166)

Les drapeaux sont affiches via emojis Unicode:
- `US` -> `🇺🇸`
- `FR` -> `🇫🇷`
- `DE` -> `🇩🇪`
- etc.

---

**Document genere automatiquement - VIGILANCE X v1.0.0**
