# VIGILANCE X - Claude Code Memory File

> **Version**: 3.54.101 | **Derniere mise a jour**: 2026-01-14

Ce fichier sert de memoire persistante pour Claude Code. Il documente l'architecture, les conventions et les regles du projet VIGILANCE X.

---

## REGLES CRITIQUES - LIRE EN PREMIER (OBLIGATOIRE)

### PROTECTION REPO PUBLIC - NE JAMAIS OUBLIER

**AVANT CHAQUE PUSH VERS `public` (vigilanceX-SOC) ou `forgejo-soc`:**

Le repo PUBLIC ne doit contenir **QUE**:
- `README.md` - Documentation client uniquement
- Code source (backend/, frontend/, docker/)

**FICHIERS INTERDITS SUR REPO PUBLIC** (a supprimer systematiquement):

| Fichier/Dossier | Raison |
|-----------------|--------|
| `CLAUDE.md` | Process internes, architecture, secrets |
| `CHANGELOG.md` | Details implementation, vulnerabilites |
| `RELEASE.md` | Process de release |
| `DESCRIPTIFDET.md` | Descriptions techniques |
| `project.md` | Notes de projet |
| `docs/` | Documentation interne complete |
| `BUGFIXSESSION/` | Sessions de debug |
| `FEATURESPROMPT/` | Prompts de features |

**INFORMATIONS A NE JAMAIS REVELER PUBLIQUEMENT:**
- Seuils de detection (WAF thresholds, nombre d'events)
- Durees de ban (4h, 24h, 7j, permanent)
- Logique de decision D2B (flux, conditions)
- Scores TI et leurs seuils
- Noms des groupes XGS internes
- Architecture de detection
- Process de ban/unban detailles

**POURQUOI?** Les attaquants pourraient adapter leurs techniques pour contourner nos seuils de detection s'ils connaissent nos parametres exacts.

**WORKFLOW GITGO:**
1. Push vers `origin` (private) - OK avec tous les fichiers
2. Push vers `public` - UNIQUEMENT README.md + code source
3. Push vers `forgejo` (private) - OK avec tous les fichiers
4. Push vers `forgejo-soc` (public) - UNIQUEMENT README.md + code source

---

## Architecture de Deploiement Securise

### Modele de Securite

VIGILANCE X est deploye dans un environnement **securise par design**:

| Couche | Protection |
|--------|------------|
| **Reseau** | Pas d'exposition Internet, interne uniquement |
| **Acces** | VPN obligatoire pour acces distant |
| **Firewall** | Regles restrictives, uniquement PC admin autorises |
| **Authentification** | JWT + RBAC (admin/audit) |

### Implications sur la Securite

Cette architecture elimine les vecteurs d'attaque externes:

| Menace | Statut | Raison |
|--------|--------|--------|
| Brute-force login | **Non applicable** | Seuls admins de confiance ont acces |
| DDoS | **Non applicable** | Pas d'exposition Internet |
| Injection depuis Internet | **Non applicable** | Reseau isole |
| Man-in-the-middle externe | **Non applicable** | Trafic interne uniquement |

### Securite Implementee

Les mesures suivantes sont en place et suffisantes pour l'environnement:

- **Hashage bcrypt** (cout 12) pour mots de passe
- **JWT avec validation HMAC** pour sessions
- **RBAC** avec roles admin/audit
- **Rate limiting global** (100 req/min)
- **Placeholders SQL** contre injections
- **Password hash jamais expose** en JSON

### Mesures NON necessaires (environnement controle)

Ces mesures seraient requises uniquement si exposition Internet:

- Lockout apres N tentatives login
- Rate limiting agressif sur /auth/login
- Protection anti-brute-force
- WAF applicatif

---

## Statut des Fonctionnalites

### En Production
- Dashboard temps reel
- WAF Explorer
- Attacks Analyzer
- Advanced Threat (11 providers TI)
- VPN & Network
- Soft Whitelist
- Geoblocking
- Authentication & User Management
- Systeme de licence VX3
- XGS Parser (104 champs, 74 regles, 23 techniques MITRE)
- Log Retention (cleanup automatique configurable)

### En Developpement (Coquille)
- **CrowdSec Blocklist XGS Sync**: Phase 2 - Synchronisation vers groupe XGS en cours
- **Policies de bans**: Logique de decision non finalisee
- **Recidivisme automatique**: A configurer selon besoins

> **Note**: Ne pas modifier la logique des bans sans consultation prealable.

### Detect2Ban Engine (v3.51 - Active)

Moteur de detection et ban automatique des menaces - **remplacement centralise de fail2ban**.

#### Pourquoi D2B vs fail2ban ?

**Problemes fail2ban sur Linux:**
- Configuration lourde (jails, policies par serveur)
- Gestion decentralisee (N serveurs = N configs)
- Interface CLI uniquement, pas de dashboard
- Pas de notifications temps reel
- Pas de correlation cross-server
- Ban local iptables (pas firewall)

**Avantages Detect2Ban:**
- Centralisation totale (1 console = tous serveurs)
- Interface Web moderne (dashboard, graphiques, historique)
- Correlation multi-sources (CrowdSec, AbuseIPDB, VirusTotal, etc.)
- Notifications email temps reel
- Ban au niveau firewall Sophos XGS (pas iptables local)
- Policies YAML configurables
- Tracabilite complete (audit trail)

#### Architecture D2B

```
Servers/Apps (Syslog) ──► Vector.dev ──► ClickHouse
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │  Detect2Ban     │
                                    │  Engine         │
                                    │  ┌───────────┐  │
                                    │  │ Scenarios │◄─┼── Threat Intel APIs
                                    │  │ YAML      │  │   (11 providers)
                                    │  └─────┬─────┘  │
                                    └────────┼────────┘
                                             ▼
                                    ┌─────────────────┐
                                    │  Sophos XGS     │
                                    │  (Ban IP)       │
                                    └─────────────────┘
```

#### Composants

| Composant | Status |
|-----------|--------|
| Engine Core | Active (auto-start au boot) |
| Scenarios YAML | 2 scenarios (waf_attacks, brute_force) |
| Check Interval | 30 secondes |
| Badge D2B | Header (vert/rouge) |
| Immunity Support | v3.51+ (Unban 24h) |

**Criteres de blocage:**
- `waf_attacks`: 5+ events WAF en 5 min (validate_threat: false)
- `brute_force`: 10+ auth failures en 10 min

**Flux Ban/Unban/XGS:**

```
1. Detection (Detect2Ban)
   ├── Verif IP protegee (local/infrastructure) → Skip
   ├── Verif IP whitelistee (hard/soft) → Skip/Alert
   ├── Verif IP immune (immune_until > now) → Skip
   ├── Verif IP deja bannee → Skip
   ├── Verif Threat Intel (si validate_threat: true) → Skip si score < threshold
   └── BAN → ip_ban_status + Sync XGS

2. Ban Manuel (API/UI)
   └── POST /api/v1/bans → BanIP() → Sync XGS

3. Unban Normal (UI: bouton "Unban")
   └── DELETE /api/v1/bans/{ip} → UnbanIP() → Remove XGS

4. Unban avec Immunite (UI: bouton "Unban 24h")
   └── DELETE /api/v1/bans/{ip}?immunity_hours=24
   └── UnbanIP(immunity_hours=24) → Set immune_until
   └── Remove from XGS
   └── Detect2Ban ne peut plus re-bannir pendant 24h
```

**Fichiers cles:**
- `backend/internal/usecase/detect2ban/engine.go` - Detection engine
- `backend/internal/usecase/bans/service.go` - Ban logic + immunity
- `backend/scenarios/*.yaml` - Scenarios YAML
- `backend/internal/entity/ban.go` - BanStatus avec immune_until

### Detect2Ban v2 - Jail System (v3.52 - Phase 1)

**Architecture D2B v2** - Systeme avance de gestion des bans avec:
- **Tiers progressifs** (recidivisme)
- **GeoZone** (classification geographique)
- **Threat Intel validation** avant ban
- **Pending Approval** pour zones autorisees
- **Separation groupes XGS** (temp vs permanent)

#### Tiers de Ban (Recidivisme)

| Tier | Duree | Condition | Groupe XGS |
|------|-------|-----------|------------|
| 0 | 4 heures | Premier ban | grp_VGX-BannedIP |
| 1 | 24 heures | 1ere recidive | grp_VGX-BannedIP |
| 2 | 7 jours | 2eme recidive | grp_VGX-BannedIP |
| 3+ | Permanent | 3+ recidives | grp_VGX-BannedPerm |

**Surveillance conditionnelle**: Apres unban, IP surveillee 30 jours.
Si nouvel incident pendant surveillance → Tier+1 automatique.

#### GeoZone - Classification Geographique (v3.52)

Systeme de classification des IPs par origine geographique pour ajuster les seuils de ban.

| Zone | Description | Seuil WAF | Comportement |
|------|-------------|-----------|--------------|
| **Authorized** | Pays de confiance (FR, BE, LU, DE, CH...) | `waf_threshold_zone` (3) | TI check avant ban, tolerance plus elevee |
| **Hostile** | Pays explicitement non fiables | `waf_threshold_hzone` (1) | Ban rapide, peu de tolerance |
| **Neutral** | Autres pays (selon `default_policy`) | Variable | Depends de la politique par defaut |

**Les 5 Settings GeoZone (Settings UI > Detect2Ban v2):**

| Setting | Type | Defaut | Description |
|---------|------|--------|-------------|
| **Enable GeoZone** | Toggle | OFF | Active/desactive la classification geographique |
| **Default Policy** | Choice | Neutral | Zone attribuee aux pays non listes |
| **WAF Threshold HZone** | 1-5 | 1 | Nombre d'events WAF avant ban pour zone Hostile |
| **WAF Threshold Zone** | 3-15 | 3 | Nombre d'events WAF avant ban pour zone Authorized/Neutral |
| **Threat Score Threshold** | 30-90 | 50 | Score TI minimum pour auto-ban en zone Authorized |

**Explication detaillee des policies:**

1. **Authorized (Trusted)**: Pays de confiance
   - Utilise `waf_threshold_zone` (plus eleve = plus tolerant)
   - Verification Threat Intel obligatoire avant ban
   - Si score TI < threshold → Pending Approval (Phase 2)

2. **Neutral**: Comportement standard
   - Utilise `waf_threshold_zone`
   - Ban automatique apres seuil atteint
   - Pas de validation manuelle requise

3. **Hostile**: Pays suspects
   - Utilise `waf_threshold_hzone` (plus bas = plus strict)
   - Ban rapide des le 1er event WAF si threshold=1
   - Pas d'exception possible

**Fichiers cles:**
- `backend/internal/adapter/controller/http/handlers/geozone.go` - API handlers
- `backend/internal/adapter/repository/clickhouse/geozone_repo.go` - Persistence ClickHouse
- `backend/internal/entity/ban.go` - GeoZoneConfig struct + ClassifyCountry()
- `frontend/src/pages/Settings.tsx` - UI GeoZone section
- `frontend/src/lib/api.ts` - geozoneApi client

**Table ClickHouse:**
```sql
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
) ENGINE = ReplacingMergeTree(version) ORDER BY id
```

#### Flux de Decision D2B v2

```
                            ┌─────────────────────┐
                            │  WAF Event Detected │
                            └──────────┬──────────┘
                                       ▼
                         ┌─────────────────────────┐
                         │  Classify IP GeoZone    │
                         │  (country → zone)       │
                         └──────────┬──────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
        ┌──────────┐          ┌──────────┐          ┌──────────┐
        │ HOSTILE  │          │ NEUTRAL  │          │AUTHORIZED│
        └────┬─────┘          └────┬─────┘          └────┬─────┘
             │                     │                     │
             ▼                     ▼                     ▼
    ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
    │ 1 event WAF?   │   │ 3+ events WAF? │   │ 3+ events WAF? │
    │ → BAN IMMEDIAT │   │ → BAN AUTO     │   │ → TI CHECK     │
    └────────────────┘   └────────────────┘   └───────┬────────┘
                                                      │
                                         ┌────────────┴────────────┐
                                         ▼                        ▼
                                  ┌─────────────┐          ┌─────────────┐
                                  │ Score ≥ 50% │          │ Score < 50% │
                                  │ → BAN AUTO  │          │ → PENDING   │
                                  └─────────────┘          │   APPROVAL  │
                                                           └─────────────┘
```

#### Groupes XGS Sophos

| Groupe | Usage | IPs |
|--------|-------|-----|
| `grp_VGX-BannedIP` | Bans temporaires (Tier 0-2) | Bans actifs non permanents |
| `grp_VGX-BannedPerm` | Bans permanents (Tier 3+) | Recidivistes permanents |

**Avantage**: Regles firewall differentes possibles (ex: log-only pour temp, drop strict pour perm).

#### Entites D2B v2

**BanStatus (champs ajoutes):**
```go
CurrentTier      uint8      // 0-3+ (tier actuel)
ConditionalUntil *time.Time // Fin periode surveillance
GeoZone          string     // authorized/hostile/neutral
ThreatScoreAtBan int        // Score TI au moment du ban
XGSGroup         string     // grp_VGX-BannedIP ou grp_VGX-BannedPerm
```

**GeoZoneConfig:**
```go
Enabled              bool     // Activer systeme GeoZone
AuthorizedCountries  []string // ["FR", "BE", "LU", "DE", "CH", ...]
HostileCountries     []string // Pays hostiles
DefaultPolicy        string   // authorized/hostile/neutral
WAFThresholdHzone    int      // Seuil WAF zone hostile (defaut: 1)
WAFThresholdZone     int      // Seuil WAF zone autorisee (defaut: 3)
ThreatScoreThreshold int      // Seuil TI pour auto-ban (defaut: 50)
```

**PendingBan (nouvelle entite):**
```go
ID           string    // UUID
IP           string    // IP en attente
Country      string    // Code pays
GeoZone      string    // Zone classifiee
ThreatScore  int       // Score TI
ThreatSources []string // Sources TI
EventCount   uint32    // Nombre events WAF
FirstEvent   time.Time // Premier event
LastEvent    time.Time // Dernier event
TriggerRule  string    // Regle declencheur
Reason       string    // Raison du pending
Status       string    // pending/approved/rejected/expired
ReviewedAt   *time.Time
ReviewedBy   string
ReviewNote   string
```

#### Endpoints API D2B v2

```
# GeoZone Configuration
GET    /api/v1/geozone/config              # Get config
PUT    /api/v1/geozone/config              # Update config
GET    /api/v1/geozone/classify?country=XX # Classify country
GET    /api/v1/geozone/countries           # List countries
POST   /api/v1/geozone/countries/authorized # Add authorized
DELETE /api/v1/geozone/countries/authorized?country=XX # Remove authorized
POST   /api/v1/geozone/countries/hostile   # Add hostile
```

#### Migration ClickHouse (007)

```sql
-- Nouveaux champs ip_ban_status
ALTER TABLE ip_ban_status ADD COLUMN current_tier UInt8 DEFAULT 0;
ALTER TABLE ip_ban_status ADD COLUMN conditional_until Nullable(DateTime);
ALTER TABLE ip_ban_status ADD COLUMN geo_zone LowCardinality(String) DEFAULT '';
ALTER TABLE ip_ban_status ADD COLUMN threat_score_at_ban Int32 DEFAULT 0;
ALTER TABLE ip_ban_status ADD COLUMN xgs_group LowCardinality(String) DEFAULT 'grp_VGX-BannedIP';

-- Nouveaux champs ban_history
ALTER TABLE ban_history ADD COLUMN tier UInt8 DEFAULT 0;
ALTER TABLE ban_history ADD COLUMN geo_zone LowCardinality(String) DEFAULT '';
ALTER TABLE ban_history ADD COLUMN threat_score Int32 DEFAULT 0;
ALTER TABLE ban_history ADD COLUMN xgs_group LowCardinality(String) DEFAULT '';

-- Table pending_bans
CREATE TABLE pending_bans (
    id UUID, ip IPv4, country String, geo_zone String,
    threat_score Int32, threat_sources Array(String),
    event_count UInt32, first_event DateTime, last_event DateTime,
    trigger_rule String, reason String, status String,
    created_at DateTime, reviewed_at Nullable(DateTime),
    reviewed_by String, review_note String
) ENGINE = ReplacingMergeTree() ORDER BY (ip, created_at);

-- Table geozone_config
CREATE TABLE geozone_config (
    id UInt8, enabled UInt8, authorized_countries Array(String),
    hostile_countries Array(String), default_policy String,
    waf_threshold_hzone UInt8, waf_threshold_zone UInt8,
    threat_score_threshold UInt8, updated_at DateTime, version UInt64
) ENGINE = ReplacingMergeTree(version) ORDER BY id;
```

#### Fichiers D2B v2

| Fichier | Description |
|---------|-------------|
| `backend/internal/entity/ban.go` | Entites BanStatus, GeoZoneConfig, PendingBan |
| `backend/internal/adapter/repository/clickhouse/geozone_repo.go` | Repositories GeoZone et PendingBans |
| `backend/internal/adapter/controller/http/handlers/geozone.go` | Handler HTTP GeoZone |
| `docker/clickhouse/migrations/007_d2b_v2_ban_system.sql` | Migration DB |
| `frontend/src/lib/api.ts` | API client geozoneApi |
| `frontend/src/pages/Settings.tsx` | UI configuration GeoZone |
| `frontend/src/types/index.ts` | Types TypeScript D2B v2 |

#### Phases Implementation D2B v2

| Phase | Description | Status |
|-------|-------------|--------|
| **Phase 1** | Entites, migration, API GeoZone, UI Settings | **Done** |
| Phase 2 | Decision Engine avec logique zones | Pending |
| Phase 3 | Surveillance et escalade automatique | Pending |
| Phase 4 | Notifications et alarmes UI | Pending |

### Storage External (v3.51 - Wired)

Archivage des logs vers stockage externe SMB/S3.

| Composant | Fichier | Status |
|-----------|---------|--------|
| Provider Interface | `internal/adapter/external/storage/provider.go` | Ready |
| SMB Client | `internal/adapter/external/storage/smb.go` | Ready |
| Storage Manager | `internal/adapter/external/storage/manager.go` | Ready |
| HTTP Handlers | `internal/adapter/controller/http/handlers/storage.go` | Ready |
| Routes API | `backend/cmd/api/main.go` | **Wired** |
| Settings UI | `frontend/src/pages/Settings.tsx` | Ready |
| API Client | `frontend/src/lib/api.ts` | Ready |
| Risk Analysis | `docs/STORAGE-SMB-RISK.md` | Done |

**Dependance requise**: `github.com/hirochachacha/go-smb2`

**Endpoints API**:
```
GET    /api/v1/storage/config   # Get configuration
PUT    /api/v1/storage/config   # Update configuration
PUT    /api/v1/storage/smb      # Update SMB config
GET    /api/v1/storage/status   # Get connection status
POST   /api/v1/storage/test     # Test SMB connection
POST   /api/v1/storage/connect  # Connect to storage
POST   /api/v1/storage/disconnect # Disconnect
POST   /api/v1/storage/enable   # Enable archiving
POST   /api/v1/storage/disable  # Disable archiving
```

**Prochaines etapes**:
1. Ajouter `go-smb2` au go.mod
2. Wirer les routes dans main.go
3. Tester connexion SMB
4. Valider archivage logs

### Log Retention (v3.52.102 - Active)

Gestion configurable de la retention des logs avec cleanup configurable.

#### IMPORTANT - Comportement par Defaut

> **VGX NE SUPPRIME JAMAIS DE DONNEES AUTOMATIQUEMENT PAR DEFAUT**

| Parametre | Valeur par defaut | Signification |
|-----------|-------------------|---------------|
| `retention_enabled` | **false** | Auto-cleanup desactive |
| Periodes de retention | Pre-configurees | N'ont AUCUN effet tant que cleanup inactif |

**Quand les donnees sont-elles supprimees?**
- **JAMAIS** si `retention_enabled = false` (par defaut)
- **Automatiquement** toutes les N heures si `retention_enabled = true`
- **Manuellement** via bouton "Run Manual Cleanup" (meme si auto-cleanup desactive)

**Exemple:**
- Si ModSec Logs = 365 jours et Ban History = 2000 jours
- Ces valeurs sont **ignorees** tant que l'auto-cleanup n'est pas active
- VGX conserve toutes les donnees indefiniment par defaut
- L'admin peut a tout moment lancer un cleanup manuel pour appliquer les periodes

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Retention Service                         │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │ Background      │    │ retention_settings (ClickHouse) │ │
│  │ Cleanup Worker  │◄───┤ - retention_enabled (OFF)       │ │
│  │ (every N hours) │    │ - Per-table retention days      │ │
│  └────────┬────────┘    │ - Cleanup interval              │ │
│           │             └─────────────────────────────────┘ │
│           ▼ (si enabled)                                    │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ ALTER TABLE DELETE WHERE timestamp < now() - INTERVAL   ││
│  │ - events, modsec_logs, firewall_events                  ││
│  │ - vpn_events, heartbeat_events, atp_events              ││
│  │ - antivirus_events, ban_history, audit_log              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

#### Pas de TTL ClickHouse

Les tables ClickHouse n'ont **PAS de TTL hardcode**. La suppression est geree uniquement par:
1. Le cleanup automatique (si active)
2. Le cleanup manuel (bouton UI)

Cela garantit que l'admin a le controle total sur la retention des donnees.

#### Composants

| Composant | Fichier | Status |
|-----------|---------|--------|
| Entity | `internal/entity/retention.go` | Active |
| Repository | `internal/adapter/repository/clickhouse/retention_repo.go` | Active |
| Service | `internal/usecase/retention/service.go` | Active |
| HTTP Handlers | `internal/adapter/controller/http/handlers/retention.go` | Active |
| Migration | `docker/clickhouse/migrations/008_retention_settings.sql` | Active |
| Settings UI | `frontend/src/pages/Settings.tsx` | Active |
| API Client | `frontend/src/lib/api.ts` | Active |

#### Configuration par defaut (periodes suggerees)

| Table | Retention | Description |
|-------|-----------|-------------|
| `events` | 30 jours | WAF, IPS, ATP events |
| `modsec_logs` | 30 jours | ModSecurity detections |
| `firewall_events` | 30 jours | Network events |
| `vpn_events` | 30 jours | VPN sessions |
| `heartbeat_events` | 30 jours | Endpoint health |
| `atp_events` | 90 jours | Advanced threats |
| `antivirus_events` | 90 jours | Malware detections |
| `ban_history` | 365 jours | Audit trail bans |
| `audit_log` | 365 jours | User actions |

> **Rappel**: Ces valeurs ne s'appliquent que lorsqu'un cleanup est execute (auto ou manuel).

#### Endpoints API

```
GET    /api/v1/retention/settings   # Get current settings
PUT    /api/v1/retention/settings   # Update retention periods
GET    /api/v1/retention/status     # Worker status + next cleanup
GET    /api/v1/retention/storage    # Disk usage per table
POST   /api/v1/retention/cleanup    # Manual cleanup trigger
```

#### Fonctionnalites UI

- **Storage Usage**: Barre de progression avec taille DB et espace libre
- **Enable Auto-Cleanup**: Toggle on/off
- **Retention Periods**: Input numerique par type de log
- **Cleanup Interval**: Selecteur 1h/6h/12h/24h
- **Manual Cleanup**: Bouton pour purge immediate

### CrowdSec Blocklist - Neural-Sync ProxyAPI (v3.54 - Active)

Integration des blocklists premium CrowdSec via **VigilanceKey comme ProxyAPI**.
Les VGX clients ne contactent plus CrowdSec directement - ils recuperent les blocklists depuis VigilanceKey.

#### Architecture ProxyAPI (v3.54+)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VIGILANCEKEY SERVER (ProxyAPI)                       │
│                           10.56.126.126 / Port 8080                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐      │
│  │ CrowdSec Client │───►│ Downloader      │───►│ File Storage        │      │
│  │ (API Download)  │    │ Worker (2h)     │    │ /data/blocklists/   │      │
│  └─────────────────┘    │ Keep latest only│    │ - {id}.txt (IPs)    │      │
│                         └────────┬────────┘    │ - {id}.meta.json    │      │
│                                  │             └──────────┬──────────┘      │
│                                  ▼                        │                  │
│                         ┌─────────────────────────────────┴─────────────┐   │
│                         │ PostgreSQL: crowdsec_blocklists               │   │
│                         │ - id, name, label, ip_count, file_hash        │   │
│                         └───────────────────────────────────────────────┘   │
│                                                                              │
│  ENDPOINTS (License-Protected):                                              │
│  GET  /api/v1/blocklist/lists           → Liste blocklists disponibles      │
│  GET  /api/v1/blocklist/{id}/download   → Download fichier IPs (text/plain) │
│  GET  /api/v1/blocklist/status          → Status sync                       │
│                                                                              │
└──────────────────────────────────────────┬──────────────────────────────────┘
                                           │
                          HTTPS + License Validation (X-License-Key, X-Hardware-ID)
                                           │
          ┌────────────────────────────────┼────────────────────────────────┐
          ▼                                ▼                                ▼
┌─────────────────────┐       ┌─────────────────────┐       ┌─────────────────────┐
│    VGX Client #1    │       │    VGX Client #2    │       │    VGX Client #N    │
│                     │       │                     │       │                     │
│ ┌─────────────────┐ │       │ ┌─────────────────┐ │       │ ┌─────────────────┐ │
│ │ VK Blocklist    │ │       │ │ VK Blocklist    │ │       │ │ VK Blocklist    │ │
│ │ Client          │ │       │ │ Client          │ │       │ │ Client          │ │
│ │ - license auth  │ │       │ │ - license auth  │ │       │ │ - license auth  │ │
│ │ - download VK   │ │       │ │ - download VK   │ │       │ │ - download VK   │ │
│ └────────┬────────┘ │       │ └────────┬────────┘ │       │ └────────┬────────┘ │
│          ▼          │       │          ▼          │       │          ▼          │
│ ┌─────────────────┐ │       │ ┌─────────────────┐ │       │ ┌─────────────────┐ │
│ │ Local Process   │ │       │ │ Local Process   │ │       │ │ Local Process   │ │
│ │ - Sync DB       │ │       │ │ - Sync DB       │ │       │ │ - Sync DB       │ │
│ │ - Enrich GeoIP  │ │       │ │ - Enrich GeoIP  │ │       │ │ - Enrich GeoIP  │ │
│ │ - Sync XGS      │ │       │ │ - Sync XGS      │ │       │ │ - Sync XGS      │ │
│ └─────────────────┘ │       │ └─────────────────┘ │       │ └─────────────────┘ │
└─────────────────────┘       └─────────────────────┘       └─────────────────────┘
```

#### Flux de Synchronisation

**Etape 1: VigilanceKey telecharge depuis CrowdSec (toutes les 2h)**

```
CrowdSec API                    VigilanceKey Server
───────────                     ──────────────────────
GET /blocklists/{id}/download   Worker (sync every 2h)
        ─────────────►          │
                                ▼
                                downloadAndCompare()
                                ├─ Download new file
                                ├─ Compute SHA256
                                ├─ Compare with current
                                │
                     ┌──────────┴──────────┐
                     │                     │
                 DIFFERENT              IDENTICAL
                     │                     │
                     ▼                     ▼
             Replace old file         No action
             Update metadata          (already fresh)
             Log to history
```

**Etape 2: VGX Client telecharge depuis VigilanceKey**

```
VGX Client                      VigilanceKey Server
──────────                      ──────────────────────
GET /api/v1/blocklist/lists
Headers:                        Middleware: ValidateLicense()
  X-License-Key: VX3-XXX        ├─ Check license valid
  X-Hardware-ID: abc123         ├─ Check status=ACTIVE
        ─────────────►          └─ If OK → proceed

                        ◄───────────────
                        [{id: "bl_1", label: "Evil IPs", ip_count: 5000}, ...]

GET /api/v1/blocklist/bl_1/download
        ─────────────►          Read /data/blocklists/bl_1.txt

                        ◄───────────────
                        Content-Type: text/plain
                        1.2.3.4
                        5.6.7.8
                        ...
```

**Etape 3: VGX traite les donnees localement (identique)**

```
VGX Client Local Processing
───────────────────────────
1. Download from VigilanceKey
2. Compare with ClickHouse DB (add/remove)
3. Enrich new IPs with GeoIP
4. Persist to ClickHouse
5. Sync to Sophos XGS (grp_VGX-CrowdSBlockL)
```

#### Avantages Architecture ProxyAPI

| Aspect | Avant (Direct) | Apres (ProxyAPI) |
|--------|----------------|------------------|
| **Cles API** | N cles (1 par VGX) | 1 cle (sur VK) |
| **Quota CrowdSec** | N x quota | 1 x quota |
| **Controle d'acces** | Aucun | License-based |
| **Audit** | Disperse | Centralise sur VK |
| **Revocation** | Impossible | License revoked = no access |
| **Bande passante** | CrowdSec → N clients | CrowdSec → VK → N clients |

#### Composants VigilanceKey (ProxyAPI)

| Composant | Fichier | Description |
|-----------|---------|-------------|
| Entity | `internal/entity/blocklist.go` | BlocklistInfo, SyncStatus |
| Repository | `internal/repository/postgres/blocklist_repo.go` | CRUD PostgreSQL |
| Service | `internal/service/blocklist.go` | CrowdSec client + sync worker |
| Handler | `internal/handler/blocklist.go` | HTTP endpoints |
| Migration | `migrations/003_crowdsec_blocklist.sql` | Tables PostgreSQL |

#### Composants VGX Client

| Composant | Fichier | Description |
|-----------|---------|-------------|
| VK Client | `internal/adapter/external/crowdsec/vk_blocklist_client.go` | Client VigilanceKey |
| Service | `internal/usecase/crowdsec/blocklist_service.go` | Logique sync (modifie) |
| Repository | `internal/adapter/repository/clickhouse/crowdsec_blocklist_repo.go` | Persistence ClickHouse |
| Handlers | `internal/adapter/controller/http/handlers/crowdsec_blocklist.go` | Endpoints HTTP |
| Frontend | `frontend/src/pages/NeuralSync.tsx` | Page UI Neural-Sync |

#### Endpoints VigilanceKey (ProxyAPI)

```
# Endpoints VGX Client (License-Protected)
GET  /api/v1/blocklist/lists              # Liste blocklists disponibles
GET  /api/v1/blocklist/{id}/download      # Download fichier IPs
GET  /api/v1/blocklist/status             # Status sync

# Endpoints Admin (JWT + Operator)
GET  /api/v1/blocklist/config             # Configuration actuelle
PUT  /api/v1/blocklist/config             # Update config (api_key)
POST /api/v1/blocklist/sync               # Force sync all
POST /api/v1/blocklist/sync/{id}          # Sync une blocklist
GET  /api/v1/blocklist/history            # Historique sync
```

#### Endpoints VGX Client (inchanges)

```
GET    /api/v1/crowdsec/blocklist/config      # Configuration locale
PUT    /api/v1/crowdsec/blocklist/config      # Update config (plus d'api_key!)
GET    /api/v1/crowdsec/blocklist/lists       # Liste depuis VK
GET    /api/v1/crowdsec/blocklist/status      # Status service
GET    /api/v1/crowdsec/blocklist/ips/list    # Liste paginee IPs locales
GET    /api/v1/crowdsec/blocklist/countries   # Liste pays uniques
POST   /api/v1/crowdsec/blocklist/enrich      # Enrichir GeoIP
POST   /api/v1/crowdsec/blocklist/sync        # Sync depuis VK
```

#### Tables PostgreSQL (VigilanceKey)

```sql
CREATE TABLE crowdsec_config (
    id SERIAL PRIMARY KEY,
    api_key TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT false,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 120,
    last_sync TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE crowdsec_blocklists (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    label VARCHAR(255) NOT NULL,
    description TEXT,
    ip_count INTEGER NOT NULL DEFAULT 0,
    file_path VARCHAR(500),
    file_hash VARCHAR(64),
    last_sync TIMESTAMP,
    enabled BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE crowdsec_sync_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    blocklist_id VARCHAR(100),
    sync_started_at TIMESTAMP NOT NULL,
    sync_completed_at TIMESTAMP,
    ips_in_file INTEGER DEFAULT 0,
    file_hash VARCHAR(64),
    success BOOLEAN DEFAULT false,
    error_message TEXT
);
```

#### Table ClickHouse (VGX Client - inchangee)

```sql
CREATE TABLE vigilance_x.crowdsec_blocklist_ips (
    ip String,
    blocklist_id String,
    blocklist_label String,
    first_seen DateTime DEFAULT now(),
    last_seen DateTime DEFAULT now(),
    country_code LowCardinality(String) DEFAULT '',
    version UInt64 DEFAULT 1
) ENGINE = ReplacingMergeTree(version)
ORDER BY (blocklist_id, ip)
```

#### XGS Integration (VGX Client - inchangee)

```
Groupe XGS: grp_VGX-CrowdSBlockL
Description: "CrowdSec Blocklist IPs - Managed by VIGILANCE X Neural-Sync"
Prefix host: CS_ (format: CS_1.2.3.4)
```

---

## Vue d'Ensemble du Projet

**VIGILANCE X** est une plateforme SOC (Security Operations Center) temps reel qui:
- Collecte les logs Sophos XGS via Syslog
- Analyse les menaces avec 11 providers de Threat Intelligence
- Bannit automatiquement les IPs malveillantes via l'API XML Sophos
- Offre une interface web moderne pour les operateurs de securite

### Stack Technique

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
│   │   ├── pages/             # 14 pages principales
│   │   ├── components/        # Composants UI reutilisables
│   │   ├── contexts/          # AuthContext, SettingsContext, LicenseContext
│   │   ├── stores/            # Zustand stores (bans, events)
│   │   ├── lib/               # API client, WebSocket, utils
│   │   ├── hooks/             # Custom React hooks
│   │   └── types/             # Definitions TypeScript
│   └── dist/                  # Build de production
├── docker/                     # Configuration Docker Compose
│   ├── docker-compose.yml
│   ├── clickhouse/            # Init SQL ClickHouse
│   ├── vector/                # Configuration Vector.dev
│   ├── nginx/                 # Reverse proxy production
│   └── ssh/                   # Cles SSH pour Sophos XGS
├── docs/                       # Documentation
│   ├── architecture/
│   ├── api/
│   └── deployment/
├── .env.example               # Template variables d'environnement
├── README.md                  # Documentation principale
├── CHANGELOG.md               # Historique des versions
└── CLAUDE.md                  # CE FICHIER - Memoire Claude Code
```

---

## Fichiers Cles par Fonction

### Backend - Points d'Entree
| Fichier | Lignes | Description |
|---------|--------|-------------|
| `backend/cmd/api/main.go` | ~600 | Initialisation API, routes, middleware |
| `backend/cmd/detect2ban/main.go` | ~200 | Daemon de detection |
| `backend/cmd/reset-password/main.go` | ~50 | CLI urgence |

### Backend - Services Metier
| Fichier | Description |
|---------|-------------|
| `internal/usecase/auth/service.go` | Authentification JWT, bcrypt |
| `internal/usecase/bans/service.go` | Gestion des bans progressifs |
| `internal/usecase/threats/service.go` | Aggregation Threat Intel |
| `internal/usecase/events/service.go` | Traitement des evenements |
| `internal/usecase/geoblocking/service.go` | Regles geographiques |
| `internal/usecase/modsec/service.go` | Sync ModSecurity SSH |
| `internal/license/client.go` | Systeme licence VX3 |

### Backend - Adaptateurs Externes
| Fichier | Description |
|---------|-------------|
| `internal/adapter/external/threatintel/` | 11 providers TI |
| `internal/adapter/external/sophos/` | Client API XML Sophos |
| `internal/adapter/external/blocklist/` | Ingestion blocklists |
| `internal/adapter/external/geoip/` | Lookup geolocalisation |

### Frontend - Pages Principales
| Fichier | Lignes | Description |
|---------|--------|-------------|
| `src/pages/Dashboard.tsx` | ~400 | Vue d'ensemble securite |
| `src/pages/AttacksAnalyzer.tsx` | ~1060 | Analyse WAF/ModSec |
| `src/pages/Settings.tsx` | ~1164 | Configuration systeme |
| `src/pages/VpnNetwork.tsx` | ~900 | Monitoring VPN |
| `src/pages/Geoblocking.tsx` | ~570 | Regles geo |
| `src/pages/SoftWhitelist.tsx` | ~630 | Whitelist graduee |
| `src/pages/UserManagement.tsx` | ~600 | Gestion utilisateurs |

### Frontend - Infrastructure
| Fichier | Description |
|---------|-------------|
| `src/lib/api.ts` | Client API Axios (~720 lignes) |
| `src/lib/websocket.ts` | Manager WebSocket temps reel |
| `src/contexts/AuthContext.tsx` | Gestion authentification |
| `src/contexts/LicenseContext.tsx` | Gestion licence |
| `src/stores/bansStore.ts` | State management bans |

---

## Conventions de Code

### Backend Go

```go
// Structure Clean Architecture
internal/
├── entity/      // Modeles de donnees (pas de logique)
├── usecase/     // Services metier (logique pure)
├── adapter/     // Implementations concretes
│   ├── repository/   // Acces DB
│   └── controller/   // HTTP handlers
└── domain/      // Regles metier complexes

// Nommage
- Fichiers: snake_case.go
- Packages: lowercase
- Interfaces: PascalCase (ex: BansRepository)
- Structs: PascalCase (ex: BanStatus)
- Variables: camelCase
- Constantes: PascalCase ou ALL_CAPS

// Error handling
- Toujours retourner error en dernier
- Logger les erreurs avec contexte
- Ne pas panic sauf cas critiques
```

### Frontend TypeScript/React

```typescript
// Structure fichiers
src/
├── pages/       // Composants de page (PascalCase.tsx)
├── components/  // Composants reutilisables
├── contexts/    // React Context providers
├── stores/      // Zustand stores (camelCase.ts)
├── lib/         // Utilitaires (camelCase.ts)
├── hooks/       // Custom hooks (useXxx.ts)
└── types/       // Types TypeScript (index.ts)

// Conventions
- Composants: PascalCase
- Hooks: useXxx
- Fichiers utilitaires: camelCase
- Types/Interfaces: PascalCase
- Variables: camelCase

// State Management
- Context API: Global (auth, settings, license)
- Zustand: Domain state (bans, events)
- useState: Local component state
```

### Base de Donnees ClickHouse

```sql
-- Tables principales
vigilance.events           -- Logs Sophos XGS
vigilance.threat_scores    -- Scores Threat Intel
vigilance.ban_status       -- Statut des bans
vigilance.ban_history      -- Historique bans
vigilance.whitelist        -- Soft whitelist
vigilance.geo_block_rules  -- Regles geoblocking
vigilance.users            -- Utilisateurs
vigilance.modsec_logs      -- Logs ModSecurity

-- Conventions
- Tables: snake_case
- Colonnes: snake_case
- Index: idx_table_column
```

---

## API Endpoints Principaux

### Authentication
```
POST   /api/v1/auth/login              # Login (public)
POST   /api/v1/auth/logout             # Logout
GET    /api/v1/auth/me                 # User info
POST   /api/v1/auth/change-password    # Change password
```

### Events & Stats (Free)
```
GET    /api/v1/events                  # Liste events
GET    /api/v1/events/timeline         # Timeline
GET    /api/v1/stats/overview          # Stats globales
GET    /api/v1/stats/top-attackers     # Top IPs
```

### Threats (Licensed)
```
GET    /api/v1/threats/check/{ip}      # Check IP
GET    /api/v1/threats/risk/{ip}       # Risk combine
GET    /api/v1/threats/providers       # Status providers
POST   /api/v1/threats/batch           # Batch check
```

### Bans (Licensed)
```
GET    /api/v1/bans                    # Liste bans
POST   /api/v1/bans                    # Creer ban
DELETE /api/v1/bans/{ip}               # Supprimer ban
POST   /api/v1/bans/sync               # Sync Sophos XGS
```

### Geoblocking (Licensed)
```
GET    /api/v1/geoblocking/rules       # Liste regles
POST   /api/v1/geoblocking/rules       # Creer regle
GET    /api/v1/geoblocking/check/{ip}  # Check IP
GET    /api/v1/geoblocking/lookup/{ip} # Lookup geo
```

### WebSocket
```
GET    /ws                             # Real-time updates
GET    /api/v1/ws?token=xxx            # With auth token
```

---

## Variables d'Environnement Critiques

```bash
# Sophos XGS
SOPHOS_HOST=10.x.x.x
SOPHOS_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASSWORD=xxx

# Database
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_DATABASE=vigilance_x
CLICKHOUSE_USER=vigilance
CLICKHOUSE_PASSWORD=xxx

# Authentication
JWT_SECRET=min-32-chars-secret
JWT_EXPIRY=24h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!

# License (v3.0)
LICENSE_ENABLED=true
LICENSE_SERVER_URL=https://vigilancexkey.cloudcomputing.lu
LICENSE_KEY=xxx
LICENSE_GRACE_PERIOD=168h  # 7 jours

# Threat Intelligence (optionnel)
ABUSEIPDB_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
GREYNOISE_API_KEY=xxx
```

---

## Regles de Developpement

### OBLIGATOIRE - A Respecter

1. **Ne jamais modifier** les fichiers de configuration production (.env)
2. **Toujours tester** les modifications backend avec `go build` avant commit
3. **Toujours tester** les modifications frontend avec `npm run build`
4. **Respecter** l'architecture Clean Architecture existante
5. **Ne pas ajouter** de nouvelles dependances sans justification
6. **Documenter** les nouveaux endpoints dans README.md
7. **Mettre a jour** CHANGELOG.md pour chaque version
8. **Documenter** les bugs dans `docs/BUGFIX-KB.md` pour la KB

### Gestion des Bugs (BUGFIX-KB)

Apres chaque session de debug, documenter les corrections dans `docs/BUGFIX-KB.md`:

**Structure d'une entree bug:**
```markdown
### [BUG-XXXX] Titre court

**Date**: YYYY-MM-DD
**Version**: vX.Y.Z
**Severite**: Critical | High | Medium | Low
**Composant**: Frontend | Backend | Infrastructure
**Fichiers affectes**: Liste des fichiers

#### Symptome
Description du comportement observe.

#### Cause Racine
Explication technique du pourquoi.

#### Solution
Description de la correction avec code avant/apres.

#### Lecons Apprises
- Points cles pour eviter ce bug a l'avenir

#### Tags
`#composant` `#type-bug` `#technologie`
```

**Patterns recurrents documentes:**
1. Persistance filtres → `sessionStorage`
2. Null safety API → `data || []`
3. Filtrage centralise → `shouldShowIP()` dans Context
4. Conversion period → `getStartTimeFromPeriod()`

### Regles de Versioning (X.YY.Z)

Les projets **VigilanceX** et **VigilanceKey** suivent une numerotation stricte des versions.

**Format**: `X.YY.Z` (exemple: `3.50.101`)

| Digit | Nom | Description | Reset |
|-------|-----|-------------|-------|
| **X** | MAJOR | Montee de version majeure (sur demande explicite) | - |
| **YY** | FEATURE | 2 digits, petites features incrementent de 1 (50→51→52) | → 0 lors d'un bump MAJOR |
| **Z** | BUGFIX | Corrections de bugs, hotfixes (commence a 100) | → 100 lors d'un bump FEATURE |

**Montee BUGFIX** (X.YY.Z → X.YY.Z+1):
- Corrections de bugs et crashs
- Hotfixes necessitant un rebuild
- Exemple: `3.50.101` → `3.50.102`

**Montee FEATURE** (X.YY.Z → X.YY+1.100):
- Ajout de nouvelles fonctionnalites
- Ameliorations significatives
- Le digit BUGFIX revient a 100
- Exemple: `3.50.105` → `3.51.100`

**Montee MAJOR** (X.YY.Z → X+1.0.100):
- Uniquement sur demande explicite de l'utilisateur
- Changements majeurs d'architecture
- Les digits FEATURE et BUGFIX reviennent a 0 et 100
- Exemple: `3.59.115` → `4.0.100`

> **Important**: A chaque release, mettre a jour:
> - `CHANGELOG.md` - Historique des versions
> - `frontend/src/pages/Settings.tsx` - Version affichee dans l'interface (ligne ~966)
> - `CLAUDE.md` - Header du fichier (version et date)
> - Tags git: `vX.Y.Z` sur les deux repos (private et public)

### Commandes Frequentes

```bash
# Backend
cd backend
go mod tidy          # Deps
go build ./cmd/api   # Build API
go test ./...        # Tests

# Frontend
cd frontend
npm install          # Deps
npm run dev          # Dev server
npm run build        # Production
npm run lint         # Linting

# Docker
cd docker
docker compose up -d           # Start
docker compose logs -f         # Logs
docker compose restart api     # Restart service
```

### Workflow Git (gitgo)

Quand l'utilisateur dit "gitgo":

> **CRITIQUE**: Toujours verifier et mettre a jour la version AVANT le commit!

**Etape 0 - Version (OBLIGATOIRE):**
1. Verifier version dans `frontend/src/pages/Settings.tsx` (ligne ~2129)
2. Si nouvelle feature/fix, incrementer selon regles versioning X.YY.Z
3. Mettre a jour header CLAUDE.md avec nouvelle version et date

**Etape 1 - Commit et Push Private (origin):**
4. `git status` - Verifier les changements
5. `git add .` - Ajouter les fichiers
6. `git commit -m "feat(vX.YY.Z): description"` - Commit avec version
7. `git push origin main` - Pousser vers origin (private)

**Etape 2 - Repo Public (vigilanceX-SOC):**
8. Creer branche temporaire: `git checkout -b public-sync`
9. Supprimer fichiers internes: `git rm --cached CLAUDE.md`
10. Commit: `git commit -m "chore: Remove internal docs"`
11. Push: `git push public public-sync:main --force`
12. Retour main: `mv CLAUDE.md /tmp/bak && git checkout main && mv /tmp/bak CLAUDE.md`
13. Cleanup: `git branch -D public-sync`

**Etape 3 - Forgejo (backup):**
14. `git push forgejo main` - Private Forgejo (avec CLAUDE.md)
15. Repeter etapes 8-13 pour `forgejo-soc` (sans CLAUDE.md)

**Etape 4 - GitHub Releases (OBLIGATOIRE):**
16. Creer tag: `git tag vX.YY.Z && git push origin vX.YY.Z && git push public vX.YY.Z`
17. Release private: `gh release create vX.YY.Z --repo kr1s57/vigilanceX --title "VIGILANCE X vX.YY.Z" --notes "..."`
18. Release public: `gh release create vX.YY.Z --repo kr1s57/vigilanceX-SOC --title "VIGILANCE X vX.YY.Z" --notes "..."`

> **RAPPEL**: Sans les releases GitHub, la page "Releases" affiche l'ancienne version comme "Latest"!

---

### Protection Propriete Intellectuelle (IMPORTANT)

**Strategie 2 repos:**

| Repo | Visibilite | Contenu | Audience |
|------|------------|---------|----------|
| **vigilanceX** (private) | Interne | Code source + Full docs techniques | Developpeurs |
| **vigilanceX-SOC** (public) | Client | Code + README client only | Clients/Admins |

**Repo PRIVATE (vigilanceX) - Documentation complete:**
- CLAUDE.md - Memoire technique complete
- CHANGELOG.md - Historique detaille des versions
- docs/ - Documentation technique complete
- BUGFIXSESSION/ - Sessions de debug
- FEATURESPROMPT/ - Prompts de features
- Tous fichiers .md techniques

**Repo PUBLIC (vigilanceX-SOC) - Protection IP:**

Fichiers a SUPPRIMER/EXCLURE systematiquement:
- `CLAUDE.md` - Process internes, methodologie
- `CHANGELOG.md` - Details implementation
- `DESCRIPTIFDET.md` - Descriptions techniques
- `RELEASE.md` - Process de release
- `project.md` - Notes de projet
- `docs/` - Documentation interne
- `BUGFIXSESSION/` - Sessions debug
- `FEATURESPROMPT/` - Prompts features

Fichier UNIQUE a maintenir:
- `README.md` - Wiki client (voir structure ci-dessous)

**Structure README.md Public (Client-Oriented):**
```markdown
# VigilanceX-SOC

## Presentation
- Description commerciale de VigilanceX
- Fonctionnalites principales
- Avantages securite

## Pre-requis
- Configuration systeme minimale
- Ports reseau requis
- Certificats SSL

## Installation
- Guide deploiement Docker
- Configuration initiale
- Premier demarrage

## Configuration Admin VGX
- Interface web
- Parametres principaux
- Integration Sophos XGS

## Maintenance
- Scripts utilitaires:
  - reset-password.sh
  - stop-vgx.sh / start-vgx.sh
  - update-vgx.sh
- Logs et diagnostics
- Backup/Restore

## Support
- Contact et licence
```

**Meme regles sur Forgejo local:**
- `itsadm/vigilanceX` = Master complet (private)
- `itsadm/vigilanceX-SOC` = Copie client (public)

---

### Workflow Deploiement (3 environnements)

| Environnement | Machine | Description |
|---------------|---------|-------------|
| **DEV** | 10.25.72.28 (/opt/vigilanceX) | Code source, builds locaux |
| **VPS-TEST** | vps-b3a1bf23 (OVH) | Simulation client distant |
| **vigilanceKey** | 10.56.126.126 | Serveur de licences |

**Deploiement vers VPS-TEST (via GHCR):**
```bash
# 1. Sur DEV - Build et push images
cd /opt/vigilanceX
echo "TOKEN" | docker login ghcr.io -u kr1s57 --password-stdin
docker build -t ghcr.io/kr1s57/vigilancex-api:VERSION -f backend/Dockerfile backend/
docker build -t ghcr.io/kr1s57/vigilancex-frontend:VERSION -f frontend/Dockerfile frontend/
docker push ghcr.io/kr1s57/vigilancex-api:VERSION
docker push ghcr.io/kr1s57/vigilancex-frontend:VERSION

# 2. Sur VPS-TEST - Pull et restart
cd ~/vigilanceX-SOC/deploy
docker compose pull backend frontend
docker compose up -d backend frontend --force-recreate
```

**Synchronisation des 3 repos Git:**
1. vigilanceX (private): Code source complet + full documentation
2. vigilanceX-SOC (public): Code + README client uniquement
3. vigilanceKey (private): Serveur de licences

A chaque release, creer les GitHub Releases via API pour afficher "Latest".

---

## Threat Intelligence Providers

### Tiers de Cascade (v2.9.5)

| Tier | Providers | Quota | Seuil |
|------|-----------|-------|-------|
| **Tier 1** (Free) | IPSum, OTX, ThreatFox, URLhaus, Shodan InternetDB | Illimite | Toujours |
| **Tier 2** | AbuseIPDB, GreyNoise, CrowdSec | Modere | Score > 30 |
| **Tier 3** | VirusTotal, CriminalIP, Pulsedive | Limite | Score > 60 |

### Format Score Agrege

```go
type ThreatScore struct {
    IP               string
    AggregatedScore  float64  // 0-100
    ThreatLevel      string   // critical/high/medium/low/minimal
    IsMalicious      bool
    Sources          []string
    Categories       []string
}
```

---

## Systeme de Licence VX3

### Binding Hardware

```
VX3 Hardware ID = SHA256("VX3:" + machine_id + ":" + firewall_serial)
```

- **machine_id**: UUID de la VM (/etc/machine-id)
- **firewall_serial**: Extrait des logs Sophos XGS

### Workflow Fresh Deploy (v3.2)

Flux semi-automatise "Request & Sync" pour l'onboarding client:

```
Installation -> Login -> Email + Generate Trial (15j) -> FDEPLOY
                                    |
                    [Sync auto 12h ou manuel]
                                    |
                    XGS detecte -> FWID envoye -> TRIAL valide
                                    |
                    "Ask Pro License" -> ASKED -> Admin approuve -> ACTIVE
```

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

### Endpoints Licence

```
GET  /api/v1/license/status        # Status (public)
POST /api/v1/license/activate      # Activation manuelle (public)
POST /api/v1/license/fresh-deploy  # Trial automatique (public, rate limit 5/h)
POST /api/v1/license/ask-pro       # Demande upgrade Pro (auth)
POST /api/v1/license/sync-firewall # Sync firewall binding (auth)
GET  /api/v1/license/info          # Details (admin)
POST /api/v1/license/validate      # Force validation (admin)
```

---

## Integrations Sophos XGS

### Ports et Protocoles

| Service | Port | Protocole | Usage |
|---------|------|-----------|-------|
| Syslog | 514/UDP, 1514/TCP | Syslog | Reception logs |
| API XML | 4444 | HTTPS | Ban/Unban IPs |
| SSH | 22 | SSH | Sync ModSecurity |

### Groupes IP Sophos

- `VIGILANCE_X_BLOCKLIST` - Bans temporaires
- `VIGILANCE_X_PERMANENT` - Bans permanents

---

## Backup Git - Forgejo Local

### Architecture

Backup automatise vers une instance Forgejo locale (air-gapped).

| Composant | Details |
|-----------|---------|
| **Serveur** | 10.56.121.100 (Docker) |
| **Image** | codeberg.org/forgejo/forgejo:13 |
| **Web UI** | http://10.56.121.100:3000 |
| **SSH** | Port 2222 (via ProxyJump) |
| **User** | itsadm (admin) |

### Repos Sauvegardes

| Repo Forgejo | Source | Description |
|--------------|--------|-------------|
| `itsadm/vigilanceX` | /opt/vigilanceX | Code source principal |
| `itsadm/vigilanceX-SOC` | /opt/vigilanceX | Deploiement public |
| `itsadm/vigilanceKey` | 10.56.126.126:/opt/vigilanceKey | Serveur licences |

### Configuration SSH

```bash
# ~/.ssh/config
Host forgejo
    HostName localhost
    Port 2222
    User git
    IdentityFile ~/.ssh/id_forgejo
    IdentitiesOnly yes
    ProxyJump itsadm@10.56.121.100
```

### Git Remotes

```bash
# vigilanceX
git remote -v
# origin   -> GitHub (kr1s57/vigilanceX)
# public   -> GitHub (kr1s57/vigilanceX-SOC)
# forgejo  -> Forgejo (itsadm/vigilanceX)
# forgejo-soc -> Forgejo (itsadm/vigilanceX-SOC)
```

### Script de Backup

**Chemin**: `/opt/vigilanceX/scripts/backup-to-forgejo.sh`

```bash
# Usage
./backup-to-forgejo.sh --all           # Backup tout
./backup-to-forgejo.sh --vigilancex    # vigilanceX + SOC
./backup-to-forgejo.sh --vigilancekey  # vigilanceKey seulement
./backup-to-forgejo.sh --check         # Test connexion
```

### Cron Automatique

```bash
# Backup quotidien a 2h du matin
0 2 * * * /opt/vigilanceX/scripts/backup-to-forgejo.sh --all >> /var/log/forgejo-backup.log 2>&1
```

### Commandes Manuelles

```bash
# Push manuel vers Forgejo
cd /opt/vigilanceX
git push forgejo main --tags
git push forgejo-soc main --tags

# Verifier les logs
tail -f /var/log/forgejo-backup.log
```

### Strategie 3-2-1

| Copie | Emplacement | Type |
|-------|-------------|------|
| 1 | Machine DEV (/opt/vigilanceX) | Local |
| 2 | GitHub (kr1s57/*) | Cloud |
| 3 | Forgejo (10.56.121.100) | Local air-gapped |

---

## Sous-Agents Claude (Regles)

### Configuration Requise

Tous les sous-agents DOIVENT utiliser le modele **Opus** pour garantir la coherence.

### Agents Recommandes

```yaml
# ~/.claude/agents/code-reviewer.yaml
name: code-reviewer
model: opus
focus:
  - security
  - maintainability
  - clean-architecture

# ~/.claude/agents/test-writer.yaml
name: test-writer
model: opus
focus:
  - test-coverage
  - edge-cases
  - error-handling
```

---

## Hooks de Securite

Configuration dans `~/.claude/settings.json` et scripts dans `~/.claude/hooks/`.

### Scripts de Hooks

| Script | Type | Description |
|--------|------|-------------|
| `block-dangerous-commands.sh` | PreToolUse | Bloque rm -rf, DROP DATABASE, etc. |
| `validate-git-operations.sh` | PreToolUse | Bloque force push sur main/master |
| `protect-env-files.sh` | PreToolUse | Protege .env, credentials, cles SSH |
| `post-write-linter.sh` | PostToolUse | gofmt pour .go, prettier pour .ts/.tsx |

### Commandes Bloquees

```bash
# Suppression systeme
rm -rf /
rm -rf /*
rm -rf /etc /var /usr /root /opt

# Base de donnees
DROP DATABASE
TRUNCATE TABLE
DELETE FROM ... WHERE 1

# Git destructif (sur main/master/develop)
git push --force origin main
git reset --hard
git clean -fd

# Systeme
shutdown, reboot, halt
dd if=/dev/zero of=/dev/sd*
chmod -R 777 /
```

### Fichiers Proteges

```
.env, .env.local, .env.production
credentials.json, secrets.json
*.pem, *.key, id_rsa, id_ed25519
license.json, .credentials.json
```

### Auto-Formatage (PostToolUse)

| Extension | Formateur |
|-----------|-----------|
| `.go` | gofmt -w |
| `.ts`, `.tsx`, `.js`, `.jsx` | prettier --write |
| `.json` | jq '.' |

### Logs des Hooks

```bash
# Voir les logs des hooks
tail -f /tmp/claude-hooks.log
```

---

## References Documentation Anthropic

- [Claude Code Memory Files](https://docs.anthropic.com/en/docs/claude-code/memory)
- [Claude Code Hooks](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [Claude Code Agents](https://docs.anthropic.com/en/docs/claude-code/agents)

---

## Notes de Version Recentes

### v3.54.100 (2026-01-14)
- **Vigimail Checker Module**: Nouveau module complet de verification emails et securite DNS
  - **Backend Go**:
    - Migration ClickHouse `013_vigimail_checker.sql` (5 tables)
    - Entity `vigimail.go` avec 8 structures (Config, Domain, Email, Leak, DNSCheck, etc.)
    - Repository ClickHouse avec CRUD complet
    - Clients externes: HIBP v3, LeakCheck.io, DNS checker natif
    - Service metier avec background worker configurable (6h/12h/24h/48h/7d)
    - 14 endpoints HTTP sous `/api/v1/vigimail/*`
  - **Frontend React**:
    - Types TypeScript complets
    - API client `vigimailApi` dans api.ts
    - Page `VigimailChecker.tsx` avec UI complete
    - Navigation dans Sidebar (categorie Detection)
  - **Fonctionnalites**:
    - Gestion multi-domaines avec emails associes
    - Detection de leaks via HIBP + LeakCheck
    - Verification DNS: SPF, DKIM, DMARC, MX, DNSSEC
    - Score global securite domaine (0-100)
    - Worker background pour checks automatiques
- **Settings Reorganisation**: Integrations reorganisees par categories
  - Nouveau composant `IntegrationCategory` avec accordeon collapsible
  - 5 categories: Sophos Firewall, CrowdSec, Threat Intelligence, Email & Notifications, Premium
  - UX amelioree avec navigation plus claire

### v3.53.105 (2026-01-14)
- **Attack Map Date Picker Fix**: Backend supporte maintenant `start_time` et `end_time` params
  - Nouvelle methode `GetGeoHeatmapFilteredRange(ctx, startTime, endTime, attackTypes)`
  - Query avec `WHERE timestamp >= ? AND timestamp <= ?`
  - Fichiers: `events.go`, `service.go`, `events_repo.go`
- **Disconnect Button Fix**: Bouton "Disconnect" s'affiche maintenant correctement
  - `handleEditPlugin` charge les configs AVANT d'ouvrir le modal
  - Evite la race condition qui causait `isPluginConfigured` a retourner false
- **Attack History Modal Fix**: Section visible independamment du threat score
  - Ban History et Attack History extraits du bloc conditionnel `score ?`
  - S'affichent maintenant meme si l'IP n'a pas de threat score en DB

### v3.53.104 (2026-01-14)
- **Neural-Sync ProxyAPI Architecture**: VGX clients now fetch blocklists via VigilanceKey
  - **VigilanceKey Backend** (Phase 1 - Complete):
    - New PostgreSQL tables: `crowdsec_config`, `crowdsec_blocklists`, `crowdsec_sync_history`
    - Entity/Repository/Service/Handler for blocklist management
    - CrowdSec API key stored centrally on VigilanceKey
    - Background sync worker (every 2 hours by default)
    - File-based caching with SHA256 hash comparison
  - **VigilanceKey Endpoints for VGX Clients** (license-protected):
    - `GET /api/v1/blocklist/lists` - List available blocklists
    - `GET /api/v1/blocklist/{id}/download` - Download blocklist IPs (plain text)
    - `GET /api/v1/blocklist/status` - Service status
  - **VigilanceKey Admin Endpoints** (JWT + Operator):
    - `GET/PUT /api/v1/admin/blocklist/config` - Configuration management
    - `POST /api/v1/admin/blocklist/test` - Test CrowdSec connection
    - `POST /api/v1/admin/blocklist/sync` - Trigger manual sync
  - **VGX Client Changes** (Phase 2 - Complete):
    - New `VigilanceKeyClient` in `internal/adapter/external/crowdsec/vigilancekey_client.go`
    - `BlocklistProvider` interface for both direct and proxy clients
    - `BlocklistService` now supports proxy mode (`UseProxy` config option)
    - Auto-switch between direct CrowdSec and VigilanceKey proxy
  - **New Config Fields**:
    - `use_proxy` (bool) - Enable VigilanceKey proxy mode
    - `proxy_server_url` (string) - VigilanceKey server URL
  - **Migration 012**: Added `use_proxy`, `proxy_server_url` columns to `crowdsec_blocklist_config`
- **Benefit**: Single CrowdSec API key on VigilanceKey, all VGX clients share via license auth

### v3.53.103 (2026-01-13)
- **Neural-Sync XGS Integration**: Synchronisation automatique vers Sophos XGS Firewall
  - Groupe XGS `grp_VGX-CrowdSBlockL` cree automatiquement si absent
  - Sync des IPs blocklist vers le groupe XGS apres chaque telechargement CrowdSec
  - Prefix host: `CS_x.x.x.x` pour identifier les IPs CrowdSec
  - Status endpoint retourne `xgs_configured`, `xgs_group_ready`, `xgs_ip_count`
- **XGSClient Interface**: Nouvelle interface pour decouplage Sophos client
  - `EnsureGroupExists(groupName, description)` - Creation groupe si absent
  - `GetGroupIPs(groupName)` - Liste IPs dans le groupe
  - `SyncGroupIPs(groupName, hostPrefix, targetIPs)` - Sync bidirectionnel
- **Constantes XGS**:
  - `XGSGroupName = "grp_VGX-CrowdSBlockL"`
  - `XGSGroupDescription = "CrowdSec Blocklist IPs - Managed by VIGILANCE X Neural-Sync"`
  - `XGSHostPrefix = "CS"` (format: CS_1.2.3.4)
- **Wiring main.go**: `crowdsecBlocklistService.SetXGSClient(sophosClient)`

### v3.53.102 (2026-01-13)
- **Neural-Sync UI Complete**: Interface utilisateur finalisee pour CrowdSec Blocklist
  - Boutons clairement labelises: "Sync Blocklists" (mauve), "Refresh" (gris)
  - Carte verte "Country Enrichment Required" prominente avec bouton "Start Country Enrichment"
  - Filtre pays avec drapeaux + noms complets (50+ pays mappes)
  - Auto-enrichment en background avec progression et bouton Stop
  - Filtre pays desactive tant que l'enrichissement n'est pas complete
- **Country Name Mapping**: Dictionnaire COUNTRY_NAMES avec 50+ pays
  - Affiche "🇫🇷 France" au lieu de "🇫🇷 FR"
  - Fallback sur le code si pays non mappe
- **Backend Enrichment**:
  - Endpoint `POST /api/v1/crowdsec/blocklist/enrich` (40 IPs/batch)
  - `GetIPsWithoutCountry()` et `UpdateIPCountry()` dans repository
  - Rate limit respecte (45 req/min ip-api.com)
- **GeoIP Fallback**: Si aucun pays en DB, sampling GeoIP pour afficher les pays disponibles

### v3.53.101 (2026-01-13)
- **abuse.ch Auth-Key Support**: ThreatFox et URLhaus necessitent maintenant un Auth-Key
  - Nouvelle variable `ABUSECH_API_KEY` (meme cle pour les 2 APIs)
  - Modifie `ThreatFoxClient` et `URLhausClient` pour ajouter header `Auth-Key`
  - Corrige le decodage JSON ThreatFox (data peut etre string ou array)
- **API Tracking Callback Wiring**: Connection aggregator → apiUsageService
  - Callback `trackAPICall()` ajoute apres chaque appel provider (11 providers)
  - Compteurs success/errors mis a jour en temps reel dans ClickHouse
  - `last_success` et `last_error_message` traces par provider
- **Settings UI - CrowdSec APIs**:
  - CrowdSec CTI et CrowdSec Blocklist positionnes ensemble
  - Chaque API editable separement
- **CrowdSec CTI**: Fonctionne avec la cle `46JAnA7b...`
- **CrowdSec Blocklist**: Necessite une Service API Key separee (scope Blocklist)

### v3.53.100 (2026-01-13)
- **API Usage Tracking System**: Tracking quotas et compteurs par provider TI
- Nouveau systeme de gestion des cles API via Settings UI (pas de cles hardcodees)
- **Tables ClickHouse** (Migration 010):
  - `api_provider_config`: Configuration par provider (quota, cle, enabled)
  - `api_usage_daily`: Compteurs quotidiens success/errors
  - `api_request_log`: Log detaille des requetes (7 jours TTL)
- **Backend Components**:
  - Repository: `internal/adapter/repository/clickhouse/api_usage_repo.go`
  - Service: `internal/usecase/apiusage/service.go` (cache + quota check)
  - Handler: `internal/adapter/controller/http/handlers/api_usage.go`
- **API Endpoints**:
  - `GET /api/v1/integrations/providers` - Liste tous les providers avec quotas
  - `GET /api/v1/integrations/providers/{id}` - Status d'un provider
  - `PUT /api/v1/integrations/providers/{id}` - Update config provider
- **Frontend Settings.tsx**:
  - Affichage quota `X / Y /day` pour chaque provider TI
  - Indicateur erreur orange avec "Last OK: date"
  - Mapping providers vers plugin ID pour edition
- **12 Providers Tracked**:
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
  | ThreatFox | Unlimited | Yes (v3.53.101) |
  | URLhaus | Unlimited | Yes (v3.53.101) |
  | CrowdSec Blocklist | Unlimited | Yes (Service Key) |

### v3.52.103 (2026-01-13)
- **CrowdSec Blocklist Integration**: Synchronisation des blocklists premium vers XGS
- Nouveau client API CrowdSec Blocklist (`internal/adapter/external/crowdsec/blocklist_client.go`)
- Service de synchronisation (`internal/usecase/crowdsec/blocklist_service.go`)
- Handlers HTTP (`internal/adapter/controller/http/handlers/crowdsec_blocklist.go`)
- Plugin Settings UI (`crowdsec_blocklist` dans Settings.tsx)
- Groupe XGS dedié: `grp_VGX-CrowdSec` (créé sur XGS)
- **API Endpoints**:
  - `GET /api/v1/crowdsec/blocklist/config` - Configuration
  - `PUT /api/v1/crowdsec/blocklist/config` - Update config (api_key, enabled, enabled_lists)
  - `POST /api/v1/crowdsec/blocklist/test` - Test connexion API
  - `GET /api/v1/crowdsec/blocklist/lists` - Liste blocklists (subscribed + available)
  - `GET /api/v1/crowdsec/blocklist/status` - Status du service
  - `GET /api/v1/crowdsec/blocklist/history` - Historique syncs
  - `POST /api/v1/crowdsec/blocklist/sync` - Sync all enabled
  - `POST /api/v1/crowdsec/blocklist/sync/{id}` - Sync blocklist specifique

### v3.52.102 (2026-01-13)
- **Log Retention - Safe by Default**: Auto-cleanup desactive par defaut
- VGX ne supprime JAMAIS de donnees automatiquement sauf activation explicite
- Suppression de tous les TTL hardcodes des tables ClickHouse
- Les periodes de retention ne s'appliquent que lors d'un cleanup (auto ou manuel)
- Documentation etoffee dans CLAUDE.md et tooltips UI
- Migration: `retention_enabled = 0` par defaut

### v3.52.101 (2026-01-13)
- **Log Retention**: Configuration retention des logs avec cleanup automatique
- Nouvelle table `retention_settings` avec periodes configurables par table
- Background cleanup worker (intervalle configurable 1h/6h/12h/24h)
- Retention par defaut: 30 jours events, 90 jours ATP/AV, 365 jours audit
- Storage stats avec affichage taille DB et espace disque libre
- Bouton cleanup manuel pour purge immediate
- API: GET/PUT /retention/settings, GET /status, GET /storage, POST /cleanup
- UI: Nouvelle section "Log Retention" dans Settings

### v3.52.100 (2026-01-12)
- **D2B v2 - Jail System Phase 1**: Systeme avance de gestion des bans
- **Tiers progressifs**: Tier 0 (4h) → Tier 1 (24h) → Tier 2 (7d) → Tier 3+ (Permanent)
- **Surveillance conditionnelle**: 30 jours apres unban, escalade si recidive
- **GeoZone Classification**: Authorized / Hostile / Neutral
  - Authorized: TI check avant ban, pending approval si score < seuil
  - Hostile: Ban immediat des le 1er event WAF
  - Neutral: Seuil WAF standard avec ban auto
- **Groupes XGS separes**: grp_VGX-BannedIP (temp) vs grp_VGX-BannedPerm (perm)
- **Nouvelles entites**: GeoZoneConfig, PendingBan, PendingBanStats
- **Nouveaux champs BanStatus**: current_tier, conditional_until, geo_zone, threat_score_at_ban, xgs_group
- **API GeoZone**: GET/PUT /geozone/config, GET /geozone/classify, POST/DELETE /geozone/countries/*
- **Migration 007**: Tables pending_bans, geozone_config + colonnes ip_ban_status/ban_history
- **UI Settings**: Section "GeoZone (D2B v2)" avec configuration complete
  - Enable/disable, default policy, WAF thresholds, threat score threshold
  - Gestion liste pays autorises et hostiles

### v3.51.102 (2026-01-12)
- **Report Recipients**: Configuration des emails destinataires pour scheduled reports
- Nouveau champ `report_recipients` dans NotificationSettings (backend + frontend)
- Input comma-separated dans Settings > Email Notifications > Scheduled Reports
- **Country Flags**: Affichage drapeau pays a cote des IPs dans Active Bans
- Enrichissement GeoIP automatique des bans via le client GeoIP existant
- Nouveau champ `Country` dans BanStatus (enrichi via API, non stocke en DB)
- Interface `GeoIPClient` dans handlers pour decouplage

### v3.51.101 (2026-01-12)
- **WAF Event Watcher**: Trigger instantane de sync ModSec sur detection WAF
- Nouveau service `wafwatcher.Service` qui monitore ClickHouse pour les events WAF blocking
- Poll toutes les 15s, cooldown 30s entre syncs
- Bridge le gap entre Syslog real-time et SSH rule ID retrieval
- Endpoint status: `GET /api/v1/modsec/watcher`
- Detect2Ban peut maintenant reagir quasi-instantanement aux attaques WAF

### v3.51.100 (2026-01-12)
- **Detect2Ban Immunity**: Nouveau bouton "Unban 24h" pour faux positifs
- IP unban avec immunite temporaire contre auto-ban
- Nouveau champ `immune_until` dans `ip_ban_status`
- Detect2Ban verifie immunite avant de re-bannir
- API: `DELETE /api/v1/bans/{ip}?immunity_hours=24`
- Frontend: Bouton bleu "Unban 24h" dans Active Bans
- **Ban History Modal**: Section historique des bans dans IPThreatModal
- Affiche tous les evenements: ban, unban, unban_immunity, extend, permanent, expire
- Icones colorees par type d'action (rouge=ban, vert=unban, bleu=immunity, etc.)
- Nouveau badge Whitelist (Hard/Soft/Monitor) dans le modal
- **Fix API Endpoint**: `/bans/${ip}/history` (etait `/bans/history/${ip}`)
- **Fix ClickHouse Types**: UInt32 → uint32, UInt8 → uint8 pour scan correct
- **Fix Detect2Ban**: EventCount int64 → uint64 (ClickHouse UInt64)
- **Fix Detect2Ban**: Query `FROM events` → `FROM vigilance_x.events`
- **Fix WAF Scenario**: Remove action=drop condition (events have action=unknown)
- **Storage SMB**: Fix "Save & Enable" button (now calls enable endpoint)
- **Storage SMB**: Added security options (RequireSigning, MinVersion 3.x)

### v3.5.100 (2026-01-12)
- **Interactive Attack Map**: Nouvelle page de visualisation des attaques
- Carte mondiale avec flux animes (source vers infrastructure)
- Filtres par type: WAF (orange), IPS/IDS (rouge), Malware (violet), Threat (vert)
- Selection multiple de types d'attaques simultanement
- Selecteur periode: Live/24h/7d/30d
- Modal details pays avec Top IPs et categories
- Service d'enrichissement geo automatique (toutes les 5 min)
- Enrichit IPS/Anti-Virus sans geolocalisation via ip-api.com
- Nouveaux composants: AttackMap, CountryLayer, AttackFlowLayer, etc.
- Nouveau store Zustand: attackMapStore.ts

### v3.4.100 (2026-01-11)
- **Debug Session**: 8 corrections UX et ameliorations
- Attack Analyzer: Fix tooltip graphique (Triggers/Unique IPs)
- Attack Analyzer: Loupe sur Top Attack pour voir IPs associees
- Attack Analyzer: Unique Attackers avec compteur total + tabs filtres
- Reports: Bouton "Send by Mail" avec piece jointe PDF/XML
- Reports: Fix SMTP hot-reload (utilise notificationService)
- WAF Explorer: Bouton Expand/Collapse All
- WAF Explorer: Stats header (Total Events, Blocked, Detected)
- Nouvelle methode `SendEmailWithAttachment` dans notifications service

### v3.3.100 (2026-01-11)
- **SMTP Email Notifications**: Nouvelle integration (partiellement fonctionnelle)
- Configuration SMTP avec support TLS/STARTTLS/SSL
- **Office365**: AUTH LOGIN prioritaire, STARTTLS port 587
- Rapports programmes: Daily, Weekly, Monthly avec choix horaire
- Alertes temps-reel: WAF Detection/Blocked, New Bans, Critical Events
- Seuil de severite configurable (Critical/High/Medium/Low)
- Templates HTML professionnels pour tous les emails
- Nouvelle section "Email Notifications" dans Settings
- Nouveaux endpoints: /notifications/settings, /test-email, /status
- Hot-reload SMTP client (pas de redemarrage necessaire)
- **Bug connu**: Notification settings multi-toggle ne persist pas (race condition)
- **Voir**: `docs/bugfix/SMTP_IMPLEMENTATION_NOTES.md` pour details debug

### v3.2.102 (2026-01-10)
- WAF Explorer: Selecteur periode (7d/14d/30d) et date picker
- Auto-expansion de tous les jours par defaut
- Fix Zone Traffic API 500 (check colonne existence)

### v3.2.101 (2026-01-10)
- **Bug Fix Session**: 6 corrections UX et stabilite
- Dashboard: Persistance filtre temps via sessionStorage
- Attack Analyzer: Filtrage IPs systeme (0.0.0.0, 127.0.0.1)
- WAF Explorer: Limite augmentee (500) + bouton "Load More"
- VPN Page: start_time passe a eventsApi pour filtrage correct
- Settings: Nouveau plugin Syslog avec bouton edition IP
- Pages vides: Gestion defensive null sur APIs (serveur test)
- **Documentation**: Nouveau fichier `docs/BUGFIX-KB.md` pour KB

### v3.2.100 (2026-01-10)
- **Fresh Deploy System**: Workflow semi-automatise "Request & Sync"
- Nouveaux statuts licence: FDEPLOY, TRIAL, ASKED
- Trial automatique 15 jours (format VX3-TRIAL-XXXX-XXXX)
- Detection et binding XGS automatique
- Bouton "Ask Pro License" pour demande upgrade
- Interface LicenseActivation refaite completement
- Section Fresh Deploy dans dashboard admin VigilanceKey
- Nouveaux endpoints: /fresh-deploy, /ask-pro, /sync-firewall
- **Fix**: NeedsFreshDeploy retourne true pour licences invalid/expired

### v3.1.6 (2026-01-10)
- Fix dashboard page blanche (APIs retournaient null au lieu de [])
- Erreur corrigee: `Cannot read properties of null (reading 'slice')`
- Initialisation des slices avec `[]Type{}` au lieu de `var []Type`

### v3.1.5 (2026-01-10)
- Fix nginx proxy_pass: preserve /api prefix for correct routing
- Ajout `LICENSE_INSECURE_SKIP_VERIFY` pour certificats self-signed
- Fix: `/api/v1/license/status` retournait 404 (trailing slash dans proxy_pass)
- Support certificats SSL sans SANs sur serveur de licence interne
- Fix WebSocket routing `/api/v1/ws`

### v3.1.4 (2026-01-10)
- Fix frontend React build (Terser property mangling cassait React internals)
- Erreur corrigee: `Cannot read properties of undefined (reading 'ReactCurrentOwner')`
- Suppression du property mangling `/^_/` dans vite.config.ts

### v3.1.3 (2026-01-10)
- Fix backend signal handler crash (Garble `-tiny` flag)
- Suppression du flag `-tiny` de Garble dans release.yml
- Erreur corrigee: `fatal: bad g in signal handler` (SIGSEGV)

### v3.1.1 (2026-01-09)
- Fix backend signal handler crash (UPX compression)
- Suppression de la compression UPX dans release.yml

### v3.1.0 (2026-01-09)
- XGS Decoders & Rules Engine (Sophos Log Parser)
- 104 champs dans 17 groupes (vigilanceX_XGS_decoders.xml)
- 74 regles dans 10 categories (vigilanceX_XGS_rules.xml)
- 23 techniques MITRE ATT&CK mappees
- Parser Go natif avec API endpoints (/parser/stats, /fields, /rules, /mitre, /test)
- 27 nouveaux champs dans Vector.toml et ClickHouse

### v3.0.1 (2026-01-09)
- Script de maintenance Docker (nettoyage build cache)
- VPN Sessions: Groupement par jour avec accordeon
- Geoblocking: Top 10 pays attaquants avec modal details

### v3.0.0 (2026-01-08)
- VX3 Secure Firewall Binding (VM + Firewall serial)
- Grace Period etendu a 7 jours
- Migration automatique VX2 → VX3

### v2.9.7 (2026-01-06)
- License Sync & Grace Mode
- Heartbeat monitoring

### v2.6.0 (2025-12-xx)
- Authentication JWT
- User Management
- RBAC (admin/audit)

---

*Fichier de memoire genere par Claude Code - Maintenir a jour lors des evolutions majeures du projet.*
