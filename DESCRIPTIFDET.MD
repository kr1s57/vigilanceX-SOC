# VIGILANCE X - Documentation Technique Detaillee

> **Version:** 2.5.0
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
14. [CyberInt - Intelligence & Response](#14-cyberint---intelligence--response)
    - [14.1 OSINT Multi-Provider](#141-osint-multi-provider-threat-intelligence)
    - [14.2 ActiveResponse - Systeme de Bannissement](#142-activeresponse---systeme-de-bannissement)
15. [Blocklist Feed Ingester (v1.6)](#15-blocklist-feed-ingester-v16)
16. [Soft Whitelist (v2.0)](#16-soft-whitelist-v20)
17. [Geoblocking (v2.0)](#17-geoblocking-v20)
18. [Freshness Score (v2.0)](#18-freshness-score-v20)
19. [Risk Scoring UI (v2.3)](#19-risk-scoring-ui-v23)
20. [System Protected IPs (v2.5)](#20-system-protected-ips-v25)
21. [Personnalisation Interface (v2.5)](#21-personnalisation-interface-v25)

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
| **Multi-Source Threat Intel** | Integration 7 providers (AbuseIPDB, VirusTotal, AlienVault OTX, GreyNoise, IPSum, CriminalIP, Pulsedive) |
| **Blocklist Feed Ingester** | Synchronisation de 11 blocklists publiques (~800k IPs) |
| **ModSec Log Correlation** | Correlation des regles ModSecurity avec les evenements WAF |
| **Progressive Banning** | Systeme de ban progressif (1h -> 4h -> 24h -> permanent) |
| **Real-time Dashboard** | Tableau de bord en temps reel via WebSocket |
| **Report Generation** | Generation de rapports PDF/XML |
| **Geolocation** | Enrichissement geographique des IPs |
| **Sophos XGS Sync** | Synchronisation bidirectionnelle des bans |
| **Soft Whitelist (v2.0)** | Whitelist graduee (hard/soft/monitor) avec TTL et modificateurs |
| **Geoblocking (v2.0)** | Blocage par pays/ASN avec detection VPN/Proxy/Tor |
| **Freshness Score (v2.0)** | Scoring temporel avec decroissance exponentielle |
| **Risk Scoring UI (v2.3)** | Interface de visualisation des scores de risque |
| **System Protected IPs (v2.5)** | Protection des IPs critiques (DNS, CDN, Monitoring) |
| **Personnalisation (v2.5)** | Style d'icones, filtrage IPs systeme dans logs |

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
| `/settings` | Settings | Parametres utilisateur et configuration |

### 5.3 Pages Detaillees

#### Dashboard (`Dashboard.tsx`)

**Fonctionnalites:**
- 4 cartes KPI: Total Events, Blocked, Critical Alerts, Unique IPs
- Graphique timeline (evenements/heure ou /jour)
- Camembert de severite
- Top 5 attaquants avec drapeaux pays (enrichissement geoloc automatique)
- Distribution par type de log
- Modal alertes critiques (cliquable)

**Enrichissement Geolocalisation:**
Le backend enrichit automatiquement les Top Attackers avec les donnees de geolocalisation via ip-api.com pour les IPs qui n'ont pas de pays dans les logs. Les IPs privees (RFC1918) ne sont pas enrichies.

**APIs appelees:**
```typescript
statsApi.overview(period)       // Stats globales + top attackers enrichis
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
- **Barres horizontales** distribution des types d'attaque (meilleure lisibilite)
- Barres horizontales des regles les plus declenchees
- Liste detaillee des regles avec expansion
- Top attaquants avec modal de recherche
- Integration modal IP Threat
- **Modal IPs par categorie d'attaque** (clic sur ligne Attack Categories Summary)

**Interactions:**
- Clic sur une ligne de "Attack Categories Summary" → ouvre un modal avec la liste des IPs uniques ayant declenche ce type d'attaque
- Clic sur une IP dans le modal → ouvre le modal IP Threat avec analyse complete

**APIs appelees:**
```typescript
modsecApi.getRuleStats(period)       // Stats par regle
modsecApi.getAttackTypeStats(period) // Stats par type
modsecApi.getGroupedLogs({attack_type}) // IPs par type d'attaque
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
- **Barres horizontales** distribution par type (meilleure lisibilite que camembert)
- Barres horizontales trafic par pays
- Section VPN expandable avec recherche
- Section Network expandable (Firewall + IPS)
- Distribution des protocoles
- **Network Security Overview cliquable** avec modals de details

**Interactions - Network Security Overview:**
Les 3 blocs de la section Network Security Overview sont cliquables quand ils contiennent des donnees:
- **VPN Security** → Modal avec tous les evenements VPN (user, IP, status, message)
- **Firewall Protection** → Modal avec les evenements Firewall
- **Intrusion Prevention** → Modal avec les alertes IPS

Chaque modal affiche un tableau complet avec:
- Horodatage, Type, Source IP, Destination, Categorie, Regle, Action
- Barre de recherche pour filtrer
- Indicateur visuel (icone oeil) quand des donnees sont disponibles

**APIs appelees:**
```typescript
statsApi.overview(period)
eventsApi.list({ log_type: 'VPN', limit: 100 })
eventsApi.list({ log_type: 'Firewall', limit: 100 })
eventsApi.list({ log_type: 'IPS', limit: 50 })
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

#### Settings (`Settings.tsx`)

**Fonctionnalites:**
Page de configuration complete pour personnaliser l'experience utilisateur.

**Sections de parametres:**

| Section | Options | Description |
|---------|---------|-------------|
| **Display** | Theme (Dark/Light/System), Language, Time format (24h/12h), Number format (FR/EN), Default period | Preferences d'affichage |
| **Dashboard & Refresh** | Refresh interval (15s/30s/60s/Manual), Top Attackers count (5/10/20), Animations | Parametres du dashboard |
| **Notifications** | Enable notifications, Alert sound, Alert threshold (Critical only / Critical+High) | Alertes et sons |
| **Security** | Session timeout, Mask sensitive IPs | Securite et confidentialite |
| **Integrations** | Sophos XGS (Syslog, SSH, API), AbuseIPDB, VirusTotal, AlienVault OTX | Lecture seule - Statut connexion |

**Integrations Sophos XGS (3 methodes):**

| Methode | Endpoint | Description |
|---------|----------|-------------|
| **Syslog** | `GET /api/v1/status/syslog` | Reception des logs firewall (UDP 514/TCP 1514) - Affiche events/min |
| **SSH** | `GET /api/v1/modsec/test` | Session shell pour sync ModSecurity - Affiche derniere sync |
| **API** | `GET /api/v1/bans/xgs-status` | API XML pour gestion des bans - Affiche host + nb bans dans groupe |

**Persistance:** Les parametres sont sauvegardes dans localStorage (`vigilancex-settings`)

**Context React:**
```typescript
// SettingsContext.tsx
interface AppSettings {
  theme: 'dark' | 'light' | 'system'
  language: 'fr' | 'en'
  dateFormat: '24h' | '12h'
  numberFormat: 'fr' | 'en'
  defaultPeriod: '1h' | '24h' | '7d' | '30d'
  refreshInterval: 15 | 30 | 60 | 0
  topAttackersCount: 5 | 10 | 20
  animationsEnabled: boolean
  notificationsEnabled: boolean
  soundEnabled: boolean
  alertThreshold: 'critical' | 'critical+high'
  sessionTimeout: 15 | 30 | 60 | 0
  maskSensitiveIPs: boolean
}

// Hooks disponibles:
useSettings()     // Acces aux settings + updateSettings() + resetSettings()
useFormatters()   // formatNumber(), formatDateTime(), formatTime(), maskIP()
```

**Integration Dashboard:**
- `settings.defaultPeriod` → Periode par defaut des graphiques
- `settings.refreshInterval` → Intervalle de rafraichissement auto
- `settings.topAttackersCount` → Nombre de Top Attackers affiches

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

## 14. CyberInt - Intelligence & Response

La section **CyberInt** represente le coeur du systeme de defense active de VIGILANCE X. Elle comprend deux composants majeurs et interdependants:

1. **OSINT Multi-Provider** - Systeme de renseignement sur les menaces (Threat Intelligence)
2. **ActiveResponse** - Systeme de reponse automatisee avec bannissement progressif

Ces deux systemes travaillent en synergie pour:
- Collecter et agreger les informations de reputation sur les IPs
- Prendre des decisions de blocage basees sur des seuils configurables
- Appliquer des bans progressifs selon le niveau de recidive
- Synchroniser les blocages avec le pare-feu Sophos XGS en temps reel

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CYBERINT ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    OSINT - THREAT INTELLIGENCE                         │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │ │
│  │  │  AbuseIPDB   │  │  VirusTotal  │  │ AlienVault   │                 │ │
│  │  │   (40%)      │  │    (35%)     │  │  OTX (25%)   │                 │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                 │ │
│  │         │                 │                 │                          │ │
│  │         └─────────────────┼─────────────────┘                          │ │
│  │                           ▼                                            │ │
│  │               ┌───────────────────────┐                                │ │
│  │               │  Threat Aggregator    │                                │ │
│  │               │  Score: 0-100         │                                │ │
│  │               │  Level: critical/high │                                │ │
│  │               └───────────┬───────────┘                                │ │
│  └───────────────────────────┼────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    ACTIVERESPONSE - BAN SYSTEM                         │ │
│  │                                                                        │ │
│  │  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────────┐  │ │
│  │  │ Detect2Ban  │────>│ Ban Service │────>│   Sophos XGS Sync       │  │ │
│  │  │  (Auto)     │     │ (Progressive│     │   (Bidirectional)       │  │ │
│  │  └─────────────┘     │  1h→4h→24h→ │     └─────────────────────────┘  │ │
│  │                      │  Permanent) │                                   │ │
│  │  ┌─────────────┐     └──────┬──────┘     ┌─────────────────────────┐  │ │
│  │  │ Manual Ban  │────────────┤            │   Whitelist Protection  │  │ │
│  │  │  (API/UI)   │            │            │   (Priority Override)   │  │ │
│  │  └─────────────┘            │            └─────────────────────────┘  │ │
│  │                             ▼                                          │ │
│  │               ┌───────────────────────┐                                │ │
│  │               │  ClickHouse Storage   │                                │ │
│  │               │  + Ban History Audit  │                                │ │
│  │               └───────────────────────┘                                │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 14.1 OSINT Multi-Provider (Threat Intelligence)

Le systeme OSINT de VIGILANCE X est un agregateur de renseignements sur les menaces qui combine les donnees de **trois providers majeurs** pour etablir un score de menace fiable et consensuel.

#### 14.1.1 Architecture du Systeme

**Fichiers Sources:**
```
backend/internal/adapter/external/threatintel/
├── aggregator.go      # Logique d'agregation
├── cache.go           # Cache en memoire (24h TTL)
├── abuseipdb.go       # Client AbuseIPDB
├── virustotal.go      # Client VirusTotal
└── otx.go             # Client AlienVault OTX
```

**Principe de Fonctionnement:**

1. Les trois providers sont interroges **en parallele** (goroutines)
2. Chaque provider retourne un score normalise (0-100)
3. Les scores sont **ponderes** selon la fiabilite du provider
4. Un **score agrege** final est calcule
5. Le resultat est mis en cache (24h) et stocke dans ClickHouse

#### 14.1.2 Providers et Ponderations

| Provider | Poids | Donnees Collectees | Taux API |
|----------|-------|-------------------|----------|
| **AbuseIPDB** | 40% | Confidence Score, Reports, Tor flag | 1000/jour |
| **VirusTotal** | 35% | Detections malveillantes, Reputation | 4/min |
| **AlienVault OTX** | 25% | Threat Pulses, Malware families | Illimite |

**Pourquoi ces ponderations ?**
- **AbuseIPDB (40%)** : Specialise dans les signalements d'abus, tres reactif
- **VirusTotal (35%)** : Consensus multi-antivirus, haute precision
- **OTX (25%)** : Contexte enrichi (malware, adversaires), mais plus de faux positifs

#### 14.1.3 AbuseIPDB - Client Detaille

**Endpoint:** `https://api.abuseipdb.com/api/v2/check`

**Donnees Recuperees:**

```json
{
  "ipAddress": "192.168.1.100",
  "abuseConfidenceScore": 85,     // Score principal (0-100)
  "totalReports": 42,             // Nombre de signalements
  "numDistinctUsers": 15,         // Utilisateurs distincts
  "countryCode": "RU",            // Geolocalisation
  "isp": "Example ISP",           // Fournisseur d'acces
  "domain": "example.com",
  "usageType": "Data Center/Web Hosting",
  "isTor": false,                 // Detection noeud Tor
  "isWhitelisted": false,
  "lastReportedAt": "2026-01-06T..."
}
```

**Scoring AbuseIPDB:**
- Utilise directement le `abuseConfidenceScore` (deja normalise 0-100)
- **Tagging special:** Si `isTor=true`, ajoute le tag `tor_exit_node`

**Parametres de Requete:**
- `maxAgeInDays=90` : Ne considere que les 90 derniers jours
- `verbose=true` : Retourne les details complets

#### 14.1.4 VirusTotal - Client Detaille

**Endpoint:** `https://www.virustotal.com/api/v3/ip_addresses/{ip}`

**Donnees Recuperees:**

```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 5,           // Detections malveillantes
        "suspicious": 2,          // Detections suspectes
        "harmless": 80,           // Detections benignes
        "undetected": 3           // Non detecte
      },
      "reputation": -15,          // Reputation VT (-100 a +100)
      "asn": 12345,
      "as_owner": "Example AS",
      "country": "US",
      "network": "192.168.0.0/16",
      "tags": ["botnet", "c2"]    // Tags communautaires
    }
  }
}
```

**Formule de Scoring VirusTotal:**

```
Ratio Malveillant = (malicious + suspicious) / total_engines
Score Base = Ratio * 100

Si reputation < 0:
    Penalite = min(abs(reputation), 50)
    Score Final = Score Base + Penalite

Score Final = min(Score Final, 100)
```

**Exemple:**
- 5 detections malveillantes sur 90 moteurs = 5.5% → Base = 6
- Reputation = -30 → Penalite = 30
- **Score Final = 36 (medium threat)**

#### 14.1.5 AlienVault OTX - Client Detaille

**Endpoints:**
1. `GET /indicators/IPv4/{ip}/general` - Infos generales
2. `GET /indicators/IPv4/{ip}/reputation` - Score de reputation

**Donnees Recuperees:**

```json
{
  "pulse_info": {
    "count": 15,                      // Nombre de "pulses" (flux de menaces)
    "pulses": [
      {
        "id": "...",
        "name": "Emotet C2 Infrastructure",
        "description": "...",
        "tags": ["emotet", "banking-trojan"],
        "adversary": "TA542",          // Groupe de menace
        "malware_families": ["Emotet", "TrickBot"],
        "attack_ids": ["T1566", "T1055"]  // MITRE ATT&CK
      }
    ]
  },
  "reputation": {
    "threat_score": 65
  }
}
```

**Formule de Scoring OTX:**

```
Score Pulses   = min(pulse_count * 5, 50)     // Max 50 points
Score Threat   = min(threat_score * 0.3, 30)  // Max 30 points
Score Malware  = min(malware_count * 5, 20)   // Max 20 points

Score Total    = Pulses + Threat + Malware    // Max 100 points
```

**Exemple:**
- 3 pulses = 15 points
- Threat score 50 = 15 points
- 2 familles malware = 10 points
- **Score Total = 40 (medium threat)**

#### 14.1.6 Algorithme d'Agregation

**Fichier:** `aggregator.go`

```go
func (a *Aggregator) calculateAggregatedScore(result *AggregatedResult) {
    totalWeight := 0.0
    weightedSum := 0.0

    // Itere sur les sources disponibles uniquement
    for _, source := range result.Sources {
        if source.Available {
            totalWeight += source.Weight
            weightedSum += float64(source.Score) * source.Weight
        }
    }

    // Normalise par le poids total disponible
    if totalWeight > 0 {
        result.AggregatedScore = int(weightedSum / totalWeight)
        result.Confidence = totalWeight
    }
}
```

**Gestion des Providers Indisponibles:**

| Providers Disponibles | Redistribution des Poids |
|----------------------|-------------------------|
| 3/3 (tous) | AbuseIPDB 40%, VT 35%, OTX 25% |
| 2/3 | Poids redistribues proportionnellement |
| 1/3 | 100% du provider disponible |
| 0/3 | Score = 0, Confidence = 0 |

**Score de Confiance:**
- `1.0` = Les 3 providers ont repondu
- `0.75` = 2 providers disponibles
- `0.35-0.40` = 1 seul provider

#### 14.1.7 Niveaux de Menace

| Score | Niveau | Action Recommandee |
|-------|--------|-------------------|
| 80-100 | `critical` | **Auto-ban immediat** |
| 60-79 | `high` | Surveillance renforcee, ban probable |
| 40-59 | `medium` | Monitoring accru |
| 20-39 | `low` | Notification simple |
| 0-19 | `none` | Pas de menace identifiee |

#### 14.1.8 Systeme de Cache

**Fichier:** `cache.go`

**Caracteristiques:**
- **TTL:** 24 heures (configurable)
- **Stockage:** En memoire (map[string]*cacheEntry)
- **Thread-safe:** RWMutex pour acces concurrent
- **Nettoyage:** Goroutine toutes les 5 minutes

**Structure du Cache:**

```go
type ThreatCache struct {
    data   map[string]*cacheEntry  // IP → resultat
    ttl    time.Duration           // 24h par defaut
    mu     sync.RWMutex            // Protection concurrent
    hits   int64                   // Compteur hits
    misses int64                   // Compteur misses
}

type cacheEntry struct {
    result    *AggregatedResult
    expiresAt time.Time
}
```

**Statistiques Disponibles:**

```go
type CacheStats struct {
    Size    int     // Entrees actuelles
    Hits    int64   // Hits cumules
    Misses  int64   // Misses cumules
    HitRate float64 // Taux de hit (%)
    TTL     string  // Duree TTL
}
```

#### 14.1.9 Flux de Decision

```
Requete: GET /api/v1/threats/check/{ip}
│
├─ 1. Verification Cache
│      ├─ HIT: Retourne resultat cache (flag cache_hit=true)
│      └─ MISS: Continue vers etape 2
│
├─ 2. Lancement Goroutines Paralleles (timeout 15s max)
│      ├─ AbuseIPDB.CheckIP()  [timeout 10s]
│      ├─ VirusTotal.CheckIP() [timeout 15s]
│      └─ OTX.CheckIP()        [timeout 10s]
│
├─ 3. Collecte Resultats (mutex-protected)
│
├─ 4. Calcul Score Agrege Pondere
│
├─ 5. Determination Niveau de Menace
│
├─ 6. Extraction Metadata
│      ├─ Pays, ASN, ISP
│      ├─ Flag Tor
│      ├─ Familles Malware
│      └─ Adversaires
│
├─ 7. Mise en Cache (TTL: 24h)
│
├─ 8. Sauvegarde Async ClickHouse
│
└─ 9. Retour Resultat Client
```

#### 14.1.10 Structure de Reponse Complete

```json
{
  "ip": "192.0.2.1",
  "aggregated_score": 65,
  "threat_level": "high",
  "confidence": 1.0,
  "cache_hit": false,
  "last_checked": "2026-01-07T10:30:00Z",

  "sources": [
    {
      "provider": "AbuseIPDB",
      "score": 70,
      "weight": 0.4,
      "weighted_score": 28.0,
      "available": true
    },
    {
      "provider": "VirusTotal",
      "score": 60,
      "weight": 0.35,
      "weighted_score": 21.0,
      "available": true
    },
    {
      "provider": "AlienVault OTX",
      "score": 65,
      "weight": 0.25,
      "weighted_score": 16.25,
      "available": true
    }
  ],

  "abuseipdb": {
    "abuse_confidence_score": 70,
    "total_reports": 45,
    "country_code": "CN",
    "isp": "Example ISP",
    "is_tor": false
  },

  "virustotal": {
    "malicious_count": 6,
    "suspicious_count": 3,
    "reputation": -25,
    "as_owner": "Example ASN"
  },

  "otx": {
    "pulse_count": 2,
    "threat_score": 65,
    "malware_families": ["Emotet", "TrickBot"],
    "adversaries": ["APT28"]
  },

  "country": "CN",
  "asn": "AS1234",
  "isp": "Example ISP",
  "is_tor": false,
  "tags": ["botnet", "trojan"],
  "malware_families": ["Emotet", "TrickBot"],
  "adversaries": ["APT28"]
}
```

#### 14.1.11 Endpoints API OSINT

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/threats/check/{ip}` | Verification temps reel |
| GET | `/api/v1/threats/score/{ip}` | Score en cache/historique |
| GET | `/api/v1/threats/should-ban/{ip}` | Decision de ban (bool) |
| GET | `/api/v1/threats/` | Liste top menaces |
| GET | `/api/v1/threats/level/{level}` | IPs par niveau |
| GET | `/api/v1/threats/stats` | Statistiques globales |
| GET | `/api/v1/threats/providers` | Statut des providers |
| POST | `/api/v1/threats/batch` | Verification batch (max 50) |
| POST | `/api/v1/threats/cache/clear` | Vider le cache |

---

### 14.2 ActiveResponse - Systeme de Bannissement

Le systeme **ActiveResponse** est le module de reponse automatisee de VIGILANCE X. Il constitue le point nevralgique de la defense active, gerant l'ensemble du cycle de vie des bans IP avec un systeme de **punition progressive**.

#### 14.2.1 Principes Fondamentaux

1. **Punition Progressive:** Chaque recidive augmente la severite
2. **Synchronisation Bidirectionnelle:** Coherence avec Sophos XGS
3. **Protection Whitelist:** Les IPs autorisees ne peuvent jamais etre bannies
4. **Audit Complet:** Chaque action est tracee pendant 365 jours
5. **Multi-Sources:** Bans manuels, automatiques, ou importes

#### 14.2.2 Architecture du Systeme

**Fichiers Sources:**
```
backend/internal/
├── entity/ban.go                              # Modeles de donnees
├── usecase/bans/service.go                    # Logique metier
├── adapter/repository/clickhouse/bans_repo.go # Persistance
├── adapter/external/sophos/client.go          # Integration XGS
└── usecase/detect2ban/engine.go               # Detection automatique
```

#### 14.2.3 Durees de Ban Progressives

Le systeme utilise un algorithme de **punition progressive** base sur le nombre de recidives:

```
┌─────────────────────────────────────────────────────────────┐
│              ESCALADE PROGRESSIVE DES BANS                   │
├─────────────┬─────────────┬─────────────────────────────────┤
│  Ban Count  │   Duree     │   Description                   │
├─────────────┼─────────────┼─────────────────────────────────┤
│      1      │   1 heure   │   Premier avertissement         │
│      2      │   4 heures  │   Deuxieme infraction           │
│      3      │  24 heures  │   Troisieme infraction          │
│     4+      │  PERMANENT  │   Recidiviste chronique         │
└─────────────┴─────────────┴─────────────────────────────────┘
```

**Constantes (entity/ban.go):**

```go
var ProgressiveBanDurations = []time.Duration{
    1 * time.Hour,   // Ban #1
    4 * time.Hour,   // Ban #2
    24 * time.Hour,  // Ban #3
    // Ban #4+ = Permanent (nil duration)
}

const RecidivismThreshold = 4  // Seuil de recidive
```

**Exemple de Progression:**

```
Jour 1:  IP 1.2.3.4 declenche WAF → Ban 1h (banCount=1)
         Ban expire apres 1h

Jour 3:  Meme IP viole a nouveau → Ban 4h (banCount=2)
         Ban expire apres 4h

Jour 5:  Meme IP recidive       → Ban 24h (banCount=3)
         Ban expire apres 24h

Jour 8:  Meme IP persiste       → BAN PERMANENT (banCount=4)
         Jamais d'expiration automatique
         Requiert intervention manuelle pour debannir
```

#### 14.2.4 Cycle de Vie Complet d'un Ban

**A. Creation d'un Ban (BanIP)**

```
Requete: POST /api/v1/bans
{
  "ip": "192.168.1.100",
  "reason": "Multiple WAF violations",
  "permanent": false  // Optionnel
}
│
├─ 1. VERIFICATION WHITELIST
│      └─ Si IP whitelistee → REJET avec erreur
│
├─ 2. RECHERCHE BAN EXISTANT
│      ├─ Non trouve → Premiere infraction (banCount = 1)
│      └─ Trouve → Recidiviste (banCount = existing + 1)
│
├─ 3. CALCUL DUREE
│      ├─ Si permanent demande → Status = PERMANENT
│      ├─ Si banCount >= 4     → Status = PERMANENT (auto)
│      ├─ Si duree specifiee   → Utilise la duree fournie
│      └─ Sinon                → Duree progressive selon banCount
│
├─ 4. PERSISTANCE (ClickHouse)
│      └─ UpsertBan() dans ip_ban_status
│
├─ 5. HISTORIQUE
│      └─ RecordBanHistory() dans ban_history
│
├─ 6. SYNC SOPHOS (Async)
│      └─ Goroutine: AddIPToBlocklist()
│
└─ 7. RETOUR BanStatus
```

**B. Extension d'un Ban (ExtendBan)**

```go
// POST /api/v1/bans/{ip}/extend
// Body: { "duration_days": 7, "reason": "Extended for investigation" }

Processus:
1. Recupere le ban existant
2. Calcule nouvelle expiration:
   - Si expiration future: nouvelle = expiration + jours
   - Sinon: nouvelle = maintenant + jours
3. Met a jour ExpiresAt
4. Sauvegarde + Historique
5. Retourne ban mis a jour
```

**C. Ban Permanent (MakePermanent)**

```go
// POST /api/v1/bans/{ip}/permanent

Processus:
1. Recupere le ban existant
2. Change Status → "permanent"
3. Met ExpiresAt → nil
4. Sauvegarde + Historique (action: "permanent")
5. L'IP reste bannie indefiniment
```

**D. Suppression de Ban (UnbanIP)**

```go
// DELETE /api/v1/bans/{ip}
// Body optionnel: { "reason": "False positive verified" }

Processus:
1. Recupere le ban existant
2. Change Status → "expired"
3. Sauvegarde (NE SUPPRIME PAS l'enregistrement)
4. Historique avec action "unban"
5. Sync Sophos: RemoveIPFromBlocklist() (async)
6. Le banCount est PRESERVE pour reference future
```

**E. Expiration Automatique**

```go
// Appele periodiquement par ProcessExpiredBans()

Processus:
1. Requete: expires_at < now() AND status = 'active'
2. Pour chaque ban expire:
   - Status → "expired"
   - Historique avec action "expire", source "system"
   - Sync Sophos: RemoveIPFromBlocklist()
3. Retourne nombre de bans traites
```

#### 14.2.5 Statuts de Ban

| Statut | Description | ExpiresAt | Transition |
|--------|-------------|-----------|------------|
| `active` | Ban temporaire en cours | Date future | → expired (auto) ou → permanent (manuel) |
| `permanent` | Ban definitif | `nil` | → expired (unban manuel uniquement) |
| `expired` | Ban termine | Date passee | → active (si nouvelle violation) |

#### 14.2.6 Sources de Ban

| Source | Origine | PerformedBy | Description |
|--------|---------|-------------|-------------|
| `manual` | API/Interface | Nom utilisateur | Ban manuel par operateur |
| `detect2ban` | Detect2Ban Engine | "detect2ban" | Detection automatique |
| `threat_intel` | Threat Intelligence | "system" | Score critique auto |
| `xgs_import` | Sync Sophos | "xgs_sync" | Import depuis XGS |
| `system` | Processus systeme | "system" | Expirations automatiques |

#### 14.2.7 Integration Sophos XGS

**Communication:** API XML sur port 4444 (HTTPS)

**Groupe de Blocage:**
- Nom: `VIGILANCE_X_BLOCKLIST`
- Cree automatiquement au demarrage
- Gere exclusivement par VIGILANCE X

**Ajout d'IP au Blocklist:**

```xml
<Request>
  <Login>
    <Username>admin</Username>
    <Password>****</Password>
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

**Synchronisation Bidirectionnelle:**

```
┌────────────────────────────────────────────────────────────┐
│                 SYNC BIDIRECTIONNELLE                       │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  PHASE 1: PUSH (VIGILANCE X → Sophos)                      │
│  ─────────────────────────────────────                      │
│  1. Requete: bans WHERE synced_xgs = false                 │
│  2. Pour chaque ban non synchronise:                       │
│     - AddIPToBlocklist(ip, reason)                         │
│     - UpdateSyncStatus(ip, true)                           │
│  3. Compteur: synced, failed, errors                       │
│                                                             │
│  PHASE 2: IMPORT (Sophos → VIGILANCE X)                    │
│  ─────────────────────────────────────                      │
│  1. GetBlocklistIPs() depuis Sophos                        │
│  2. Pour chaque IP du Sophos:                              │
│     - Si existe localement: marquer synced                 │
│     - Si n'existe pas ET pas whiteliste:                   │
│       - Creer ban (status=permanent, source=xgs_import)    │
│       - Enregistrer historique                             │
│  3. Compteur: imported                                     │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

**Sync Asynchrone (Ban Individuel):**

```go
func (s *Service) syncBanToXGS(ban *BanStatus) {
    // Goroutine avec timeout 30s
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Ajoute au blocklist Sophos
    if err := s.sophos.AddIPToBlocklist(ban.IP, ban.Reason); err != nil {
        log.Printf("[ERROR] Sync XGS failed: %v", err)
        return  // Non-bloquant, reessai au prochain sync global
    }

    // Marque comme synchronise
    s.repo.UpdateSyncStatus(ctx, ban.IP, true)
}
```

#### 14.2.8 Mecanisme de Whitelist

**Principe:** Les IPs whitelistees sont **protegees contre tout ban**, quelque soit la source.

**Structure Whitelist:**

```go
type WhitelistEntry struct {
    IP          string    // Adresse IPv4
    CIDRMask    uint8     // Support CIDR (ex: /24), defaut 32
    Reason      string    // Justification
    AddedBy     string    // Qui a ajoute
    CreatedAt   time.Time
    IsActive    bool      // Soft delete support
}
```

**Points de Verification:**

1. **Lors du Ban:** Avant tout ban, verification whitelist
2. **Lors du Sync XGS:** IPs whitelistees ignorees lors de l'import
3. **Detect2Ban:** Scenarios verifient whitelist avant action

**Ajout a la Whitelist:**

```go
func (s *Service) AddToWhitelist(ip, reason, addedBy string) error {
    // 1. Si IP actuellement bannie, debannir d'abord
    ban, err := s.repo.GetBanByIP(ctx, ip)
    if err == nil && (ban.Status == "active" || ban.Status == "permanent") {
        s.UnbanIP(ctx, &UnbanRequest{
            IP:          ip,
            Reason:      "Added to whitelist",
            PerformedBy: addedBy,
        })
    }

    // 2. Ajouter a la whitelist
    return s.repo.AddToWhitelist(ctx, &WhitelistEntry{
        IP:        ip,
        Reason:    reason,
        AddedBy:   addedBy,
        CreatedAt: time.Now(),
        IsActive:  true,
    })
}
```

#### 14.2.9 Historique et Audit Trail

**Table:** `ban_history` (retention 365 jours)

**Structure:**

```sql
CREATE TABLE ban_history (
    id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    ip IPv4,
    action LowCardinality(String),  -- ban, unban, extend, permanent, expire
    previous_status String,
    new_status String,
    duration_hours Nullable(UInt32),
    reason String,
    source String,                   -- manual, detect2ban, system, xgs_import
    performed_by String,
    synced_xgs UInt8,
    metadata String                  -- JSON supplementaire
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (ip, timestamp)
TTL timestamp + INTERVAL 365 DAY;
```

**Actions Tracees:**

| Action | Declencheur | Donnees Enregistrees |
|--------|-------------|---------------------|
| `ban` | Nouveau ban | IP, raison, duree, source, operateur |
| `unban` | Suppression manuelle | IP, raison, operateur |
| `extend` | Extension duree | IP, nouvelle duree, raison |
| `permanent` | Escalade permanent | IP, operateur |
| `expire` | Expiration auto | IP, source="system" |

**Exemple Timeline:**

```
2026-01-05 10:00  BAN       1h      detect2ban  "WAF: 15 attacks"
2026-01-05 11:00  EXPIRE    -       system      "Ban expired"
2026-01-06 14:30  BAN       4h      detect2ban  "WAF: 8 attacks (recidivist)"
2026-01-06 15:00  EXTEND    +24h    admin       "Extended for investigation"
2026-01-07 15:00  EXPIRE    -       system      "Ban expired"
2026-01-08 09:00  BAN       24h     manual      "Confirmed malicious"
2026-01-08 10:00  PERMANENT -       admin       "Escalated to permanent"
```

#### 14.2.10 Detection de Recidivistes

**Definition:** Une IP est **recidiviste** a partir de `banCount >= 4`

**Methode de Detection:**

```go
func (b *BanStatus) IsRecidivist() bool {
    return b.BanCount >= RecidivismThreshold  // 4
}
```

**Comportement Automatique:**
- Au 4eme ban, le systeme applique automatiquement un ban permanent
- Aucune intervention manuelle requise
- Le `banCount` n'est JAMAIS remis a zero (meme apres unban)

**Statistiques Recidivistes:**

```sql
-- Compte les IPs bannies 3+ fois
SELECT count() FROM ip_ban_status FINAL
WHERE ban_count >= 3
```

#### 14.2.11 Endpoints API ActiveResponse

**Gestion des Bans:**

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/bans/` | Liste tous les bans actifs/permanents |
| GET | `/api/v1/bans/stats` | Statistiques globales |
| GET | `/api/v1/bans/xgs-status` | Statut sync Sophos |
| POST | `/api/v1/bans/` | Creer un nouveau ban |
| POST | `/api/v1/bans/sync` | Synchroniser avec Sophos |
| GET | `/api/v1/bans/{ip}` | Detail d'un ban specifique |
| DELETE | `/api/v1/bans/{ip}` | Supprimer un ban (unban) |
| POST | `/api/v1/bans/{ip}/extend` | Prolonger un ban |
| POST | `/api/v1/bans/{ip}/permanent` | Rendre permanent |
| GET | `/api/v1/bans/{ip}/history` | Historique complet |

**Gestion de la Whitelist:**

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/whitelist/` | Liste la whitelist |
| POST | `/api/v1/whitelist/` | Ajouter une IP |
| DELETE | `/api/v1/whitelist/{ip}` | Retirer une IP |

#### 14.2.12 Statistiques de Ban

```go
type BanStats struct {
    TotalActiveBans    uint64  // status IN ('active', 'permanent')
    TotalPermanentBans uint64  // status = 'permanent'
    TotalExpiredBans   uint64  // status = 'expired'
    BansLast24h        uint64  // Nouveaux bans en 24h
    UnbansLast24h      uint64  // Unbans en 24h
    RecidivistIPs      uint64  // IPs bannies 3+ fois
    PendingSync        uint64  // En attente sync XGS
}
```

#### 14.2.13 Integration Detect2Ban

Le module Detect2Ban analyse les evenements en continu et declenche des bans automatiques selon des scenarios YAML.

**Scenarios Actifs:**

1. **brute_force.yaml**
   - Detecte 10+ echecs auth en 10 minutes
   - Verifie whitelist avant ban
   - Applique durees progressives

2. **waf_attacks.yaml**
   - Detecte 5+ drops WAF en 5 minutes
   - Verifie threat intel (score min 50)
   - Verifie whitelist
   - Applique durees progressives

**Flux Detect2Ban:**

```
Detection Evenement
│
├─ Evaluation Scenario (conditions YAML)
│
├─ Match trouve → handleMatch()
│      │
│      ├─ Verification ban existant (skip si deja banni)
│      │
│      ├─ Verification threat intel (optionnel)
│      │
│      ├─ Verification whitelist
│      │
│      └─ executeBan()
│            │
│            └─ BanIP() avec:
│                 - PerformedBy: "detect2ban"
│                 - Reason: "Auto-ban: {scenario} ({count} events)"
│                 - Durees progressives
│
└─ Cooldown (evite doubles detections)
```

#### 14.2.14 Diagramme Complet du Systeme

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        ACTIVERESPONSE FLOW                                │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│    Sources de Ban                      Decisions                          │
│    ──────────────                      ─────────                          │
│                                                                           │
│    ┌──────────────┐                                                       │
│    │  Manual API  │─────┐                                                 │
│    └──────────────┘     │                                                 │
│                         │                                                 │
│    ┌──────────────┐     │         ┌────────────────────┐                 │
│    │  Detect2Ban  │─────┼────────>│   WHITELIST CHECK  │                 │
│    │  (Auto)      │     │         │                    │                 │
│    └──────────────┘     │         │  Whitelisted? ─────┼──> REJET        │
│                         │         │       │            │                 │
│    ┌──────────────┐     │         │       ▼ Non       │                 │
│    │ Threat Intel │─────┤         │  ┌────────────┐   │                 │
│    │ (Score >=80) │     │         │  │ LOOKUP BAN │   │                 │
│    └──────────────┘     │         │  └─────┬──────┘   │                 │
│                         │         │        │          │                 │
│    ┌──────────────┐     │         │        ▼          │                 │
│    │  XGS Import  │─────┘         │  ┌────────────┐   │                 │
│    └──────────────┘               │  │CALC DUREE  │   │                 │
│                                   │  │Progressive │   │                 │
│                                   │  └─────┬──────┘   │                 │
│                                   └────────┼──────────┘                 │
│                                            │                             │
│                                            ▼                             │
│    ┌─────────────────────────────────────────────────────────────────┐  │
│    │                      PERSISTANCE                                 │  │
│    │                                                                  │  │
│    │   ip_ban_status          ban_history           ip_whitelist     │  │
│    │   ──────────────         ───────────           ────────────     │  │
│    │   - IP                   - Timestamp           - IP             │  │
│    │   - Status               - Action              - Reason         │  │
│    │   - BanCount             - Reason              - AddedBy        │  │
│    │   - ExpiresAt            - Source              - CreatedAt      │  │
│    │   - SyncedXGS            - PerformedBy         - IsActive       │  │
│    │                                                                  │  │
│    └────────────────────────────┬────────────────────────────────────┘  │
│                                 │                                        │
│                                 ▼                                        │
│    ┌─────────────────────────────────────────────────────────────────┐  │
│    │                 SOPHOS XGS SYNCHRONIZATION                       │  │
│    │                                                                  │  │
│    │   ┌────────────────┐              ┌────────────────┐            │  │
│    │   │ AddIPToBlock() │              │ RemoveIPFrom() │            │  │
│    │   │ (sur ban)      │              │ (sur unban)    │            │  │
│    │   └───────┬────────┘              └───────┬────────┘            │  │
│    │           │                               │                      │  │
│    │           └───────────────┬───────────────┘                      │  │
│    │                           │                                      │  │
│    │                           ▼                                      │  │
│    │              ┌────────────────────────┐                         │  │
│    │              │  SOPHOS XGS FIREWALL   │                         │  │
│    │              │  VIGILANCE_X_BLOCKLIST │                         │  │
│    │              └────────────────────────┘                         │  │
│    │                                                                  │  │
│    └─────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│    Processus Background                                                  │
│    ────────────────────                                                  │
│                                                                          │
│    ┌──────────────────┐      ┌──────────────────┐                       │
│    │ ProcessExpired() │      │ SyncToXGS()      │                       │
│    │ (Horaire)        │      │ (Manuel/Planifie)│                       │
│    └──────────────────┘      └──────────────────┘                       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 15. Blocklist Feed Ingester (v1.6)

Le module **Blocklist Feed Ingester** permet de synchroniser automatiquement les IPs malveillantes depuis des sources publiques de threat intelligence.

### 15.1 Feeds Disponibles

| Feed | Categorie | IPs Estimees | Frequence Sync |
|------|-----------|--------------|----------------|
| **Firehol Level 1** | mixed | ~350k | 6h |
| **Firehol Level 2** | mixed | ~240k | 6h |
| **Spamhaus DROP** | malware | ~100k | 24h |
| **Spamhaus EDROP** | malware | ~66k | 24h |
| **Blocklist.de** | attacker | ~24k | 1h |
| **CI Army** | attacker | ~15k | 24h |
| **Binary Defense** | attacker | ~4k | 1h |
| **Emerging Threats** | attacker | ~1.5k | 6h |
| **Feodo Tracker** | botnet (C2) | ~300 | 30min |
| **DShield** | scanner | Top 20 | 1h |

**Total approximatif : ~800,000 IPs uniques**

### 15.2 API Endpoints

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/blocklists/stats` | Statistiques (total IPs, feeds actifs) |
| GET | `/api/v1/blocklists/feeds` | Status de tous les feeds |
| POST | `/api/v1/blocklists/sync` | Declenchement synchronisation manuelle |
| GET | `/api/v1/blocklists/check/{ip}` | Verifier si IP dans blocklists |
| GET | `/api/v1/blocklists/high-risk` | IPs multi-sources (haute confiance) |

### 15.3 Threat Intelligence Providers (7 Sources)

En plus des 3 providers principaux (AbuseIPDB, VirusTotal, OTX), 4 providers supplementaires:

| Provider | Description | Donnees |
|----------|-------------|---------|
| **GreyNoise** | Reduction faux positifs | Detection scanners benings vs malveillants |
| **IPSum** | Agregation 30+ blocklists | Score de confiance multi-source |
| **CriminalIP** | Detection infrastructure malveillante | C2, VPN, Proxy, Datacenter |
| **Pulsedive** | Correlation IOC | Acteurs de menace, TTP MITRE |

---

## 16. Soft Whitelist (v2.0)

Le systeme **Soft Whitelist** remplace le whitelist binaire (oui/non) par un systeme gradue permettant un controle fin du comportement.

### 16.1 Types de Whitelist

| Type | Comportement | Score Modifier | Ban Possible |
|------|--------------|----------------|--------------|
| **hard** | Bypass total | 0% (ignore) | Non - jamais |
| **soft** | Score reduit | Configurable (10-90%) | Non - alerte uniquement |
| **monitor** | Logging uniquement | 100% (normal) | Oui - avec logging |

### 16.2 Structure de Donnees

```go
type SoftWhitelistEntry struct {
    IP            string    // Adresse IPv4 ou CIDR
    Type          string    // hard, soft, monitor
    ScoreModifier float64   // 0.0 a 1.0 (multiplicateur)
    TTL           *int64    // Secondes, nil = permanent
    ExpiresAt     *time.Time
    Reason        string
    Tags          []string  // Categorisation libre
    CreatedBy     string
    CreatedAt     time.Time
    IsActive      bool
}
```

### 16.3 Exemples d'Utilisation

| Scenario | Type | Score Modifier | TTL |
|----------|------|----------------|-----|
| Serveur de monitoring interne | hard | 0% | Permanent |
| Partenaire commercial | soft | 30% | 90 jours |
| Test penetration planifie | monitor | 100% | 7 jours |
| CDN legitime | soft | 20% | Permanent |

### 16.4 API Endpoints

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/whitelist` | Liste toutes les entrees |
| GET | `/api/v1/whitelist/{ip}` | Detail d'une entree |
| POST | `/api/v1/whitelist` | Ajouter (type, TTL, score_modifier, tags) |
| PUT | `/api/v1/whitelist/{ip}` | Modifier une entree |
| DELETE | `/api/v1/whitelist/{ip}` | Supprimer |
| GET | `/api/v1/whitelist/check/{ip}` | Verifier status d'une IP |

---

## 17. Geoblocking (v2.0)

Le module **Geoblocking** permet de bloquer ou surveiller le trafic par pays ou ASN avec enrichissement geographique automatique.

### 17.1 Types de Regles

| Type | Action | Description |
|------|--------|-------------|
| `country_block` | Blocage | Bloque toutes les IPs du pays |
| `country_watch` | Surveillance | Augmente le score des IPs du pays |
| `asn_block` | Blocage | Bloque toutes les IPs de l'ASN |
| `asn_watch` | Surveillance | Augmente le score des IPs de l'ASN |

### 17.2 Pays Haute-Risque Preconfigures

10 pays identifies comme sources frequentes d'attaques:

| Code | Pays | Raison |
|------|------|--------|
| RU | Russie | Cyberattaques etatiques |
| CN | Chine | APT, espionnage |
| KP | Coree du Nord | Lazarus Group |
| IR | Iran | Campagnes de phishing |
| BY | Bielorussie | Proxy cyberattaques |
| NG | Nigeria | Fraude, BEC |
| RO | Roumanie | Fraude financiere |
| UA | Ukraine | Botnets |
| VN | Vietnam | Scans massifs |
| IN | Inde | Attaques brute force |

### 17.3 Detection VPN/Proxy/Tor

Le service GeoIP detecte automatiquement:

| Flag | Description | Impact Score |
|------|-------------|--------------|
| `is_vpn` | Service VPN commercial | +20 |
| `is_proxy` | Proxy public/commercial | +15 |
| `is_tor` | Noeud de sortie Tor | +30 |
| `is_datacenter` | IP de datacenter/hosting | +10 |

### 17.4 API Endpoints

| Methode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/v1/geoblocking/rules` | Liste des regles actives |
| POST | `/api/v1/geoblocking/rules` | Creer une regle |
| PUT | `/api/v1/geoblocking/rules/{id}` | Modifier une regle |
| DELETE | `/api/v1/geoblocking/rules/{id}` | Supprimer une regle |
| GET | `/api/v1/geoblocking/check/{ip}` | Verifier une IP |
| GET | `/api/v1/geoblocking/lookup/{ip}` | Geolocalisation complete |
| GET | `/api/v1/geoblocking/stats` | Statistiques par pays/ASN |
| GET | `/api/v1/geoblocking/countries/high-risk` | Liste pays haute-risque |

---

## 18. Freshness Score (v2.0)

Le **Freshness Score** applique une decroissance temporelle aux scores de menace pour privilegier les donnees recentes.

### 18.1 Principe

Les informations de threat intelligence perdent leur pertinence avec le temps. Un IP malveillante il y a 6 mois peut etre devenue legitime.

### 18.2 Formule de Decroissance

```
freshness_multiplier = exp(-age_days / half_life)

Avec:
- age_days: Nombre de jours depuis la detection
- half_life: 7 jours (configurable)
- Minimum: 0.1 (ne descend jamais en dessous de 10%)
```

### 18.3 Table de Multiplicateurs

| Age des Donnees | Multiplicateur | Impact |
|-----------------|----------------|--------|
| Aujourd'hui | 1.25x | Boost recence |
| 1-3 jours | 1.0x | Score complet |
| 7 jours | ~0.75x | 3/4 du score |
| 14 jours | ~0.37x | 1/3 du score |
| 21 jours | ~0.22x | 1/5 du score |
| 30+ jours | 0.10x | Score minimal |

### 18.4 Application

Le multiplicateur s'applique a:
1. Scores Threat Intel agriges
2. Scores individuels par provider
3. Compteurs de blocklist

```go
func ApplyFreshnessScore(baseScore int, lastSeen time.Time) int {
    ageHours := time.Since(lastSeen).Hours()
    ageDays := ageHours / 24

    // Decroissance exponentielle avec demi-vie de 7 jours
    multiplier := math.Exp(-ageDays / 7.0)

    // Minimum 10%
    if multiplier < 0.1 {
        multiplier = 0.1
    }

    // Boost pour donnees recentes (< 3 jours)
    if ageDays < 3 {
        multiplier = 1.25
    }

    return int(float64(baseScore) * multiplier)
}
```

---

## 19. Risk Scoring UI (v2.3)

L'interface **Risk Scoring** permet de visualiser et comprendre les scores de risque calcules.

### 19.1 Composants Visuels

| Element | Description |
|---------|-------------|
| **Jauge circulaire** | Score agrege (0-100) avec code couleur |
| **Badge niveau** | critical/high/medium/low/none |
| **Breakdown par provider** | Score individuel pour chaque source |
| **Timeline historique** | Evolution du score dans le temps |
| **Tags de risque** | Indicateurs visuels (Tor, VPN, Botnet, etc.) |

### 19.2 Code Couleur

```css
.score-critical { background: #dc2626; } /* 80-100 - Rouge */
.score-high     { background: #f97316; } /* 60-79  - Orange */
.score-medium   { background: #eab308; } /* 40-59  - Jaune */
.score-low      { background: #3b82f6; } /* 20-39  - Bleu */
.score-none     { background: #22c55e; } /* 0-19   - Vert */
```

### 19.3 Modal IP Threat

Le modal IP Threat affiche pour chaque IP:

```
┌─────────────────────────────────────────────────────────────┐
│  IP: 192.168.1.100                        Score: 72/100    │
│  Level: HIGH                              [████████░░]     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Provider Scores:                                           │
│  ├─ AbuseIPDB:    75  [████████░░]  45 reports            │
│  ├─ VirusTotal:   68  [███████░░░]  3/90 malicious        │
│  └─ OTX:          65  [███████░░░]  2 pulses              │
│                                                             │
│  Geolocation:                                               │
│  ├─ Country: CN (China)                                    │
│  ├─ ASN: AS4134 ChinaNet                                   │
│  └─ City: Beijing                                          │
│                                                             │
│  Indicators:  🌐 VPN  🕵️ Proxy  📡 Datacenter             │
│                                                             │
│  Tags: botnet, trojan, scanning                            │
│                                                             │
│  [Refresh] [Ban IP] [Add to Whitelist]                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 20. System Protected IPs (v2.5)

Les **System Protected IPs** sont des adresses IP critiques pour le fonctionnement d'Internet qui ne doivent jamais etre bloquees.

### 20.1 Categories Protegees

| Categorie | Fournisseurs | IPs |
|-----------|-------------|-----|
| **DNS** | Cloudflare, Google, Quad9, OpenDNS | 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 208.67.222.222 |
| **Cloud Health** | AWS, Google Cloud | Plages health check |
| **Monitoring** | UptimeRobot, Pingdom, StatusCake | IPs de monitoring |
| **NTP** | NIST | time.nist.gov |

### 20.2 Structure de Donnees

```go
type SystemWhitelistEntry struct {
    IP       string `json:"ip"`
    Name     string `json:"name"`
    Provider string `json:"provider"`
    Category string `json:"category"` // dns, cloud, monitoring, ntp
}

var SystemWhitelist = []SystemWhitelistEntry{
    // DNS Providers
    {IP: "1.1.1.1", Name: "Cloudflare DNS Primary", Provider: "Cloudflare", Category: "dns"},
    {IP: "1.0.0.1", Name: "Cloudflare DNS Secondary", Provider: "Cloudflare", Category: "dns"},
    {IP: "8.8.8.8", Name: "Google DNS Primary", Provider: "Google", Category: "dns"},
    {IP: "8.8.4.4", Name: "Google DNS Secondary", Provider: "Google", Category: "dns"},
    {IP: "9.9.9.9", Name: "Quad9 DNS Primary", Provider: "Quad9", Category: "dns"},
    {IP: "208.67.222.222", Name: "OpenDNS Primary", Provider: "OpenDNS", Category: "dns"},
    // ... autres entrees
}
```

### 20.3 Interface Whitelist

La page Whitelist affiche une section **System Protected IPs** avec:
- Toggle pour afficher/masquer
- Groupage par categorie
- Compteur d'IPs par categorie
- Detail complet (IP, nom, provider)

### 20.4 API Endpoint

```
GET /api/v1/config/system-whitelist
```

Retourne:
```json
{
  "categories": {
    "dns": [
      {"ip": "1.1.1.1", "name": "Cloudflare DNS Primary", "provider": "Cloudflare"},
      {"ip": "8.8.8.8", "name": "Google DNS Primary", "provider": "Google"}
    ],
    "cloud": [...],
    "monitoring": [...],
    "ntp": [...]
  },
  "total_count": 24
}
```

---

## 21. Personnalisation Interface (v2.5)

### 21.1 Style des Icones Sidebar

Deux styles disponibles pour les icones de navigation:

| Style | Description | Code |
|-------|-------------|------|
| **Monochrome** | Icones d'une seule couleur (classique) | `iconStyle: 'mono'` |
| **Color** | Icones colorees par categorie de page | `iconStyle: 'color'` |

**Couleurs par categorie (mode Color):**

| Page | Couleur |
|------|---------|
| Dashboard | Bleu |
| WAF Explorer | Violet |
| Attacks | Rouge |
| Threats | Orange |
| VPN/Network | Vert |
| Active Bans | Rouge fonce |
| Reports | Bleu clair |
| Settings | Gris |

### 21.2 Filtrage IPs Systeme

Option pour masquer les IPs systeme protegees dans les logs et tableaux:

```typescript
interface AppSettings {
  // ... autres settings
  iconStyle: 'mono' | 'color';
  hideSystemIPs: boolean;  // Masquer 1.1.1.1, 8.8.8.8, etc. dans logs
}
```

### 21.3 Persistance

Les preferences sont sauvegardees dans `localStorage`:

```javascript
// Cle: vigilancex-settings
{
  "theme": "dark",
  "language": "fr",
  "iconStyle": "color",
  "hideSystemIPs": false,
  // ... autres settings
}
```

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

**Document genere automatiquement - VIGILANCE X v2.5.0**
