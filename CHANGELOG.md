# Changelog

All notable changes to VIGILANCE X will be documented in this file.

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
