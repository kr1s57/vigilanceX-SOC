# Changelog

All notable changes to VIGILANCE X will be documented in this file.

---

## [2.0.0] - 2026-01-07

### Major Release - Advanced Risk Scoring & Geoblocking

Cette version majeure introduit trois nouveaux modules de sécurité avancés pour une protection plus granulaire et intelligente.

---

### 🛡️ Soft Whitelist System

Remplacement du système de whitelist binaire par un système gradué avec trois niveaux de confiance.

#### Types de Whitelist
| Type | Comportement | Cas d'usage |
|------|--------------|-------------|
| `hard` | Bypass total - jamais banni, score ignoré | Infrastructure critique, partenaires vérifiés |
| `soft` | Score réduit, alerte uniquement (pas de ban auto) | Clients connus, services tiers |
| `monitor` | Logging uniquement, pas d'impact sur score/bans | Surveillance, investigation |

#### Fonctionnalités
- **TTL Support**: Whitelist temporaire avec expiration automatique
- **Score Modifiers**: Réduction de score configurable (0-100%)
- **Tags**: Catégorisation flexible des entrées
- **CIDR Support**: Whitelist de plages IP complètes

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/whitelist` | GET | Liste toutes les entrées whitelist |
| `/whitelist` | POST | Ajoute une entrée (type, TTL, score_modifier) |
| `/whitelist/{ip}` | DELETE | Supprime une entrée |
| `/whitelist/check/{ip}` | GET | Vérifie le statut whitelist d'une IP |

---

### 📊 Freshness Score

Système de scoring temporel qui ajuste les scores de menace selon la fraîcheur des données.

#### Algorithme
```
multiplier = max(minMult, maxMult * e^(-daysOld / decayFactor))

Paramètres par défaut:
- decayFactor: 7 jours (demi-vie)
- minMultiplier: 0.1 (score minimum = 10% après décroissance)
- maxMultiplier: 1.5 (boost activité récente)
- recentActivityBoostDays: 3 jours
- staleThresholdDays: 30 jours
```

#### Comportement
| Âge des données | Multiplicateur | Effet |
|-----------------|----------------|-------|
| < 3 jours | 1.25x | Boost récent |
| 7 jours | ~0.75x | Score réduit |
| 14 jours | ~0.37x | Fortement réduit |
| > 30 jours | 0.1x | Score minimal |

#### Combined Scorer
Le `CombinedScorer` intègre tous les facteurs de risque:
- Score Threat Intel (7 providers)
- Score Blocklists (Feed Ingester)
- Freshness Score (décroissance temporelle)
- Geoblocking Score (pays/ASN)
- Whitelist Modifier (réduction)

---

### 🌍 Geoblocking

Système de blocage géographique par pays et ASN avec lookup GeoIP intégré.

#### Types de Règles
| Type | Description |
|------|-------------|
| `country_block` | Bloquer toutes les IPs d'un pays |
| `country_watch` | Surveiller un pays (boost score) |
| `asn_block` | Bloquer un ASN spécifique |
| `asn_watch` | Surveiller un ASN (boost score) |

#### Actions
| Action | Effet |
|--------|-------|
| `block` | Blocage automatique, `should_block: true` |
| `watch` | Surveillance, boost de score configurable |
| `boost` | Augmentation du score de risque |

#### GeoIP Lookup
- **Provider**: ip-api.com (gratuit, 45 req/min)
- **Cache local**: 24h TTL, 10000 entrées max
- **Détection**: VPN, Proxy, Tor, Datacenter
- **Données**: Pays, Ville, Région, ASN, Coordonnées

#### Pays Haute-Risque par Défaut
| Code | Pays | Score Base |
|------|------|------------|
| RU | Russia | 25 |
| CN | China | 25 |
| KP | North Korea | 30 |
| IR | Iran | 25 |
| BY | Belarus | 20 |
| VE | Venezuela | 15 |
| NG | Nigeria | 15 |
| PK | Pakistan | 15 |
| UA | Ukraine | 10 |
| VN | Vietnam | 10 |

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/geoblocking/rules` | GET | Liste toutes les règles |
| `/geoblocking/rules` | POST | Créer une règle |
| `/geoblocking/rules/{id}` | PUT | Modifier une règle |
| `/geoblocking/rules/{id}` | DELETE | Supprimer une règle |
| `/geoblocking/stats` | GET | Statistiques geoblocking |
| `/geoblocking/check/{ip}` | GET | Vérifier une IP contre les règles |
| `/geoblocking/lookup/{ip}` | GET | Lookup géolocalisation complète |
| `/geoblocking/countries/blocked` | GET | Liste des pays bloqués |
| `/geoblocking/countries/watched` | GET | Liste des pays surveillés |
| `/geoblocking/countries/high-risk` | GET | Liste des pays haute-risque |
| `/geoblocking/cache/refresh` | POST | Rafraîchir le cache des règles |

---

### Database Changes

#### Nouvelles Tables ClickHouse
```sql
-- Whitelist v2.0 avec soft whitelist
CREATE TABLE ip_whitelist_v2 (
    ip IPv4,
    cidr_mask UInt8,
    type LowCardinality(String),      -- hard, soft, monitor
    reason String,
    description String,
    score_modifier Int32,             -- % reduction (0-100)
    alert_only UInt8,
    expires_at Nullable(DateTime),
    tags Array(String),
    created_by String,
    created_at DateTime,
    updated_at DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)

-- Règles de geoblocking
CREATE TABLE geoblock_rules (
    id UUID,
    rule_type LowCardinality(String), -- country_block, country_watch, asn_block, asn_watch
    target String,                    -- Country code (ISO 3166-1) ou ASN
    action LowCardinality(String),    -- block, watch, boost
    score_modifier Int32,
    reason String,
    is_active UInt8,
    created_by String,
    created_at DateTime,
    updated_at DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)

-- Cache géolocalisation
CREATE TABLE ip_geolocation (
    ip IPv4,
    country_code LowCardinality(String),
    country_name String,
    city String,
    region String,
    asn UInt32,
    as_org String,
    is_vpn UInt8,
    is_proxy UInt8,
    is_tor UInt8,
    is_datacenter UInt8,
    latitude Float64,
    longitude Float64,
    last_updated DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
```

#### Migration
```bash
# Appliquer la migration v2.0
docker exec -i vigilancex-clickhouse clickhouse-client < docker/clickhouse/migrations/005_soft_whitelist_v2.sql
```

---

### Fichiers Créés/Modifiés

#### Nouveaux Fichiers
| Fichier | Description |
|---------|-------------|
| `internal/domain/scoring/freshness.go` | Module Freshness Score avec CombinedScorer |
| `internal/entity/geoblocking.go` | Entités geoblocking (règles, location, résultats) |
| `internal/adapter/external/geoip/client.go` | Client GeoIP avec cache local |
| `internal/adapter/repository/clickhouse/geoblocking_repo.go` | Repository ClickHouse geoblocking |
| `internal/usecase/geoblocking/service.go` | Service geoblocking avec cache règles |
| `internal/adapter/controller/http/handlers/geoblocking.go` | Handlers API geoblocking |
| `docker/clickhouse/migrations/005_soft_whitelist_v2.sql` | Migration tables v2.0 |

#### Fichiers Modifiés
| Fichier | Modifications |
|---------|---------------|
| `internal/entity/ban.go` | Ajout types whitelist (hard/soft/monitor), TTL, tags |
| `internal/adapter/repository/clickhouse/bans_repo.go` | Méthodes whitelist v2 |
| `internal/usecase/bans/service.go` | Logique soft whitelist |
| `cmd/api/main.go` | Intégration services et routes v2.0 |

---

### Technical Stack v2.0
| Component | Technology |
|-----------|------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind CSS |
| Database | ClickHouse (ReplacingMergeTree) |
| Cache | Redis + In-memory (GeoIP) |
| GeoIP | ip-api.com (free tier) |
| Log Pipeline | Vector.dev |
| Deployment | Docker Compose |

---

## [1.6.5] - 2026-01-07

### New Features

#### Blocklist Feed Ingester
Système d'ingestion de blocklists publiques avec synchronisation dynamique pour une protection proactive.

| Feed | Source | Catégorie | IPs |
|------|--------|-----------|-----|
| Firehol Level 1 | GitHub | mixed | ~565k |
| Firehol Level 2 | GitHub | mixed | ~28k |
| Spamhaus DROP | spamhaus.org | malware | ~166k |
| Spamhaus EDROP | spamhaus.org | malware | - |
| Blocklist.de | blocklist.de | attacker | ~24k |
| CI Army | cinsscore.com | attacker | 15k |
| Binary Defense | binarydefense.com | attacker | ~4k |
| Emerging Threats | emergingthreats.net | attacker | ~1.5k |
| DShield | dshield.org | scanner | 20 |
| Feodo Tracker | abuse.ch | botnet | ~4 |
| SSL Blacklist | abuse.ch | c2 | - |

**Caractéristiques clés:**
- Synchronisation automatique avec intervalles configurables (30min - 4h)
- Désactivation dynamique des IPs retirées des sources (`is_active=0`)
- Détection des IPs haute-risque (présentes dans 2+ blocklists)
- Expansion CIDR pour les blocs /24 et plus petits

#### Combined Risk Assessment API
Nouveau endpoint `/api/v1/threats/risk/{ip}` combinant:
- Score Threat Intel (7 providers: AbuseIPDB, VirusTotal, OTX, GreyNoise, IPSum, CriminalIP, Pulsedive)
- Présence dans les blocklists Feed Ingester
- Score combiné avec boost (+10pts par blocklist, max +50pts)
- Recommandation de ban automatique (`recommend_ban: true` si score >= 70)

### API Endpoints

#### Blocklists API (`/api/v1/blocklists`)
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/stats` | GET | Statistiques globales (total IPs, feeds) |
| `/feeds` | GET | Status de tous les feeds |
| `/feeds/configured` | GET | Liste des feeds configurés |
| `/sync` | POST | Synchronisation manuelle de tous les feeds |
| `/feeds/{name}/sync` | POST | Synchronisation d'un feed spécifique |
| `/check/{ip}` | GET | Vérifier si une IP est dans les blocklists |
| `/high-risk` | GET | IPs présentes dans plusieurs blocklists |

#### Threats API (Enhanced)
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/risk/{ip}` | GET | **Nouveau:** Évaluation combinée threat+blocklist |

### Database Changes

#### New ClickHouse Tables
- `blocklist_ips` - IPs de toutes les sources avec versioning ReplacingMergeTree
- `blocklist_ip_summary` - Agrégation par IP (multi-source)
- `blocklist_feeds` - Status de synchronisation des feeds

### Technical Details

**Fichiers créés:**
- `backend/internal/adapter/external/blocklist/` - Package blocklist complet
  - `feeds.go` - 11 sources configurées
  - `parser.go` - Parseurs multi-formats (IP list, netset, CIDR, DShield, Spamhaus)
  - `ingester.go` - Service d'ingestion avec sync dynamique
- `backend/internal/adapter/repository/clickhouse/blocklist_repo.go`
- `backend/internal/usecase/blocklists/service.go`
- `backend/internal/adapter/controller/http/handlers/blocklists.go`
- `docker/clickhouse/migrations/004_add_blocklist_tables.sql`

---

## [1.6.0] - 2026-01-07

### Threat Intelligence Stack Enhancement

#### New Providers (v1.6)
| Provider | Description | API Key Required |
|----------|-------------|------------------|
| GreyNoise | Benign scanner identification (FP reduction) | Yes |
| IPSum | Aggregated blocklists (30+ sources) | No |
| CriminalIP | C2/VPN/Proxy infrastructure detection | Yes |
| Pulsedive | IOC correlation & threat actors | Yes |

**Total: 7 providers** (AbuseIPDB, VirusTotal, AlienVault OTX + 4 nouveaux)

#### Aggregation Improvements
- Rebalanced weights for 7 providers
- GreyNoise benign flag reduces score by 50% (FP reduction)
- IPSum blocklist count tracked
- CriminalIP VPN/Proxy/Tor/Scanner flags
- Pulsedive threat actors, malware families, campaigns

---

## [1.5.0] - 2026-01-07

### New Features

#### Settings Page
- **Display Settings**: Theme (Dark/Light/System), Language (FR/EN), Time format (24h/12h), Number format
- **Dashboard Settings**: Auto-refresh interval (15s/30s/60s/Manual), Top Attackers count (5/10/20), Animations toggle
- **Notifications**: Enable/disable notifications, Alert sounds, Severity threshold (Critical only / Critical+High)
- **Security**: Session timeout configuration, Mask sensitive IPs option
- **Integrations Status**: Real-time connection status for all integrations

#### Sophos XGS Triple Integration
| Method | Description |
|--------|-------------|
| **Syslog** | Real-time log ingestion (UDP 514 / TCP 1514) with events/min display |
| **SSH** | ModSecurity rules synchronization with last sync timestamp |
| **API** | Ban management via XML API with host and ban count display |

#### Reports Page
- Database statistics (size, event counts, date range)
- Quick reports: Daily, Weekly, Monthly
- Custom reports with date range and module selection
- Export formats: PDF and XML

#### Dashboard Enhancements
- Configurable default time period (1h, 24h, 7d, 30d)
- Dynamic refresh based on user settings
- Top Attackers with country flags (geolocation)
- Clickable Critical Alerts card with modal detail view

### Improvements
- Settings persistence via localStorage
- React Context for global settings state
- Enhanced type definitions for API responses
- JSON tags for proper Go struct serialization

### Technical Stack
| Component | Technology |
|-----------|------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind CSS |
| Database | ClickHouse |
| Cache | Redis |
| Log Pipeline | Vector.dev |
| Deployment | Docker Compose |

---

## [1.0.0] - 2026-01-04

### Initial Release
- Dashboard with real-time security overview
- WAF Explorer for web traffic analysis
- Attacks Analyzer for IPS events
- Advanced Threat tracking (ATP/APT)
- VPN & Network audit
- Active Bans management
- Detect2Ban engine with YAML scenarios
- Threat Intelligence integration (AbuseIPDB, VirusTotal, AlienVault OTX)
- ModSecurity log correlation via SSH
- Sophos XGS API integration for ban sync
