# Changelog

All notable changes to VIGILANCE X will be documented in this file.

---

## [2.3.0] - 2026-01-07

### UI Improvements & Plugin Configuration Management

Améliorations de l'interface utilisateur et ajout de la gestion des plugins avec test de connexion.

---

### 🛡️ System Whitelist - Protected IPs

Nouveau système de whitelist pour les IPs légitimes (DNS, CDN, health checks) qui ne doivent jamais être bloquées.

#### IPs Protégées
| Provider | IPs | Category |
|----------|-----|----------|
| **Cloudflare DNS** | 1.1.1.1, 1.0.0.1 | DNS |
| **Google DNS** | 8.8.8.8, 8.8.4.4 | DNS |
| **Quad9** | 9.9.9.9, 149.112.112.112 | DNS |
| **OpenDNS** | 208.67.222.222, 208.67.220.220 | DNS |
| **AWS** | 54.243.31.192 | Cloud |
| **Google Cloud** | 35.191.0.1, 130.211.0.1 | Cloud |
| **UptimeRobot** | 216.144.250.150 | Monitoring |
| **Pingdom** | 76.72.167.154 | Monitoring |
| **NIST NTP** | 129.6.15.28, 129.6.15.29 | Monitoring |

#### Fonctionnalités
- Filtrage automatique des IPs système dans tous les logs (WAF, Threats, etc.)
- Option "Hide system IPs" dans Settings > Security & Privacy
- API endpoints pour consulter et vérifier la whitelist système

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/config/system-whitelist` | GET | Liste complète des IPs protégées |
| `/config/system-whitelist/check/{ip}` | GET | Vérifier si une IP est protégée |

---

### 🎨 Icon Style Option

Nouvelle option pour choisir le style des icônes de la sidebar.

#### Options
| Style | Description |
|-------|-------------|
| **Monochrome** | Icônes monochromes (style par défaut) |
| **Color** | Icônes colorées par catégorie |

#### Couleurs par Page
| Page | Couleur |
|------|---------|
| Dashboard | Blue |
| WAF Explorer | Emerald |
| Attacks Analyzer | Red |
| Advanced Threat | Orange |
| VPN & Network | Purple |
| Active Bans | Red |
| Geoblocking | Cyan |
| Whitelist | Green |
| Risk Scoring | Yellow |
| Reports | Indigo |

---

### ⚙️ Plugin Configuration Management

Nouvelle fonctionnalité permettant de configurer et tester les intégrations directement depuis l'interface.

#### Fonctionnalités
| Feature | Description |
|---------|-------------|
| **Edit Button** | Bouton crayon sur chaque intégration dans Settings |
| **Configuration Modal** | Formulaire de configuration avec champs appropriés |
| **Connection Testing** | Test automatique de la connexion lors de la sauvegarde |
| **Visual Feedback** | Indicateur vert (Connected) ou rouge (Failed) |
| **Save & Restart** | Sauvegarde et rechargement automatique |

#### Plugins Configurables
| Plugin | Champs |
|--------|--------|
| **Sophos XGS - API** | Host, Port, Username, Password |
| **Sophos XGS - SSH** | Host, Port, Username, SSH Key Path |
| **AbuseIPDB** | API Key |
| **VirusTotal** | API Key |
| **AlienVault OTX** | API Key |
| **GreyNoise** | API Key |
| **Criminal IP** | API Key |
| **Pulsedive** | API Key |

#### Tests de Connexion
| Type | Méthode de Test |
|------|-----------------|
| Sophos API | Test TCP vers le port configuré |
| Sophos SSH | Connexion SSH avec clé privée |
| Threat Intel | Validation du format de clé API |

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/config/test` | POST | Tester une configuration |
| `/config/save` | POST | Sauvegarder et tester |
| `/config` | GET | Récupérer les configurations (masquées) |

---

### 🔄 Active Bans - Simplification

Suppression du module Whitelist de la page Active Bans (page dédiée existante).

#### Changements
- Suppression de la section "Whitelist" de Active Bans
- Suppression du badge "Whitelisted" sur les IPs
- La gestion des whitelists se fait désormais via la page dédiée `/whitelist`

---

### 🌍 High Risk Countries - Extension

Extension de la liste des pays à haut risque de 5 à 10 pays avec affichage du code pays.

#### Nouveaux Pays
| Code | Pays | Risk Level | Base Score |
|------|------|------------|------------|
| KP | North Korea | Critical | 90 |
| IR | Iran | Critical | 85 |
| RU | Russia | High | 70 |
| CN | China | High | 65 |
| BY | Belarus | High | 60 |
| VE | Venezuela | Medium | 50 |
| SY | Syria | Medium | 50 |
| CU | Cuba | Medium | 45 |
| NG | Nigeria | Medium | 40 |
| PK | Pakistan | Medium | 35 |

#### Améliorations UI
- Affichage du country code entre parenthèses : `Russia (RU)`
- Message explicatif : "Reference list - create rules to customize behavior"
- Scroll automatique pour les 10 entrées

---

### 📊 Risk Scoring Dashboard

Nouvelle page dédiée à l'évaluation des risques IP avec scoring multi-facteurs.

#### Scoring Weights
| Composant | Poids | Description |
|-----------|-------|-------------|
| **Threat Intel** | 40% | Score agrégé des 7 providers OSINT |
| **Blocklist** | 30% | Présence dans les listes de blocage |
| **Freshness** | 20% | Fraîcheur des données (decay temporel) |
| **Geolocation** | 10% | Score de risque géographique |

#### Freshness Algorithm
| Paramètre | Valeur | Effet |
|-----------|--------|-------|
| Recent window | ≤ 3 jours | +25% boost |
| Normal window | ≤ 30 jours | 100% (pas de modification) |
| Stale threshold | > 30 jours | Decay exponentiel |
| Decay factor | 7 jours | Half-life du score |
| Floor | 10% | Score minimum après decay |

#### Risk Levels
| Niveau | Score | Couleur |
|--------|-------|---------|
| Critical | ≥ 80 | Rouge |
| High | ≥ 60 | Orange |
| Medium | ≥ 40 | Jaune |
| Low | ≥ 20 | Bleu |
| None | < 20 | Vert |

---

### 📝 Version Update

- Version affichée dans Settings : `v2.3.0`

---

### Fichiers Créés/Modifiés

#### Nouveaux Fichiers
| Fichier | Description |
|---------|-------------|
| `backend/internal/adapter/controller/http/handlers/config.go` | Handler configuration avec test de connexion |

#### Fichiers Modifiés
| Fichier | Modifications |
|---------|---------------|
| `backend/cmd/api/main.go` | Routes `/api/v1/config/*` |
| `backend/internal/entity/geoblocking.go` | 10 pays high-risk |
| `frontend/src/lib/api.ts` | Module `configApi` |
| `frontend/src/pages/Settings.tsx` | Plugin editor modal, version v2.3.0 |
| `frontend/src/pages/ActiveBans.tsx` | Suppression section whitelist |
| `frontend/src/pages/Geoblocking.tsx` | Country codes, message explicatif |

---

## [2.2.0] - 2026-01-07

### Frontend Integration - Soft Whitelist UI

Intégration complète de l'interface utilisateur pour le système Soft Whitelist v2.0.

---

### 🛡️ Soft Whitelist Dashboard

Nouvelle page dédiée à la gestion des whitelists avec support des trois niveaux de confiance.

#### Fonctionnalités UI
| Section | Description |
|---------|-------------|
| **Stats Cards** | Total entries, Hard whitelist, Soft whitelist, Monitor only |
| **IP Check** | Vérification d'une IP avec résultat détaillé (type, score modifier, auto-ban) |
| **Entries List** | Liste filtrable par type avec détails complets |
| **Add Entry Modal** | Création d'entrée avec type, raison, score modifier, TTL, tags |
| **Type Legend** | Explication des trois niveaux de whitelist |

#### Types de Whitelist
| Type | Comportement | Icône |
|------|--------------|-------|
| `hard` | Full bypass - jamais banni, score ignoré | ShieldCheck (vert) |
| `soft` | Score réduit, alerte uniquement (pas d'auto-ban) | Shield (bleu) |
| `monitor` | Logging uniquement, pas d'impact sur score/bans | Eye (jaune) |

#### Fonctionnalités Avancées
- **Score Modifier** : Slider 0-100% pour réduction du score (type soft)
- **Alert Only** : Option pour alerter sans auto-ban
- **TTL Support** : Durée en jours (vide = permanent)
- **Tags** : Catégorisation flexible (CDN, partner, pentest, etc.)
- **CIDR Support** : Affichage des masques CIDR

#### Navigation
- Nouvelle entrée "Whitelist" dans la sidebar avec icône ShieldCheck
- Route `/whitelist` accessible

#### Corrections Backend
- Routes API whitelist corrigées (`/stats`, `/check/{ip}`, `PUT /{ip}`)
- Fix type `int32` pour `ScoreModifier` (compatibilité ClickHouse Int32)

#### Fichiers Ajoutés/Modifiés
| Fichier | Changement |
|---------|------------|
| `frontend/src/types/index.ts` | Types WhitelistEntry, WhitelistRequest, WhitelistCheckResult, WhitelistStats |
| `frontend/src/lib/api.ts` | Module `softWhitelistApi` |
| `frontend/src/pages/SoftWhitelist.tsx` | Page complète |
| `frontend/src/App.tsx` | Route `/whitelist` |
| `frontend/src/components/layout/Sidebar.tsx` | Navigation |
| `backend/cmd/api/main.go` | Routes whitelist v2.0 |
| `backend/internal/entity/ban.go` | Fix int32 ScoreModifier |

---

## [2.1.0] - 2026-01-07

### Frontend Integration - Geoblocking UI

Intégration complète de l'interface utilisateur pour le module Geoblocking v2.0.

---

### 🌍 Geoblocking Dashboard

Nouvelle page dédiée à la gestion du geoblocking avec interface complète.

#### Fonctionnalités UI
| Section | Description |
|---------|-------------|
| **Stats Cards** | Total rules, Active rules, Blocked countries, Watched countries |
| **Rules Management** | Liste, création et suppression des règles |
| **IP Check** | Vérification d'une IP contre les règles actives |
| **GeoIP Lookup** | Recherche géographique avec détection VPN/Proxy/Tor/Datacenter |
| **High-Risk Countries** | Affichage des pays à risque élevé avec scores |

#### Types de Règles Supportés
- `country_block` - Blocage par pays (ISO 3166-1 alpha-2)
- `country_watch` - Surveillance par pays
- `asn_block` - Blocage par ASN
- `asn_watch` - Surveillance par ASN

#### Actions Disponibles
- `block` - Blocage immédiat
- `watch` - Surveillance avec score modifier
- `boost` - Augmentation du score de risque

#### Navigation
- Nouvelle entrée "Geoblocking" dans la sidebar avec icône Globe
- Route `/geoblocking` accessible

#### Fichiers Ajoutés/Modifiés
| Fichier | Changement |
|---------|------------|
| `frontend/src/types/index.ts` | Types TypeScript geoblocking |
| `frontend/src/lib/api.ts` | Module `geoblockingApi` |
| `frontend/src/pages/Geoblocking.tsx` | Page complète |
| `frontend/src/App.tsx` | Route `/geoblocking` |
| `frontend/src/components/layout/Sidebar.tsx` | Navigation |

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
