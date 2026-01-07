# API VIGILANCE X v1.6.5

> Documentation complète de l'API REST VIGILANCE X

## Base URL

```
http://localhost:8080/api/v1
```

## Authentification

JWT Bearer token dans le header `Authorization`:
```
Authorization: Bearer <token>
```

## Changelog API

| Version | Changements |
|---------|-------------|
| 1.6.5 | Ajout API Blocklists, Combined Risk Assessment |
| 1.6.0 | Ajout 4 nouveaux providers Threat Intel |
| 1.5.0 | Ajout Reports, Settings, ModSec |
| 1.0.0 | Release initiale |

## Endpoints

### Health Check

```http
GET /health
```

Réponse :
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "2h30m15s",
  "environment": "production",
  "timestamp": "2025-01-06T12:00:00Z",
  "checks": {
    "api": "ok",
    "clickhouse": "ok",
    "redis": "ok"
  },
  "system": {
    "go_version": "go1.22",
    "num_cpu": 4,
    "num_goroutine": 12,
    "mem_alloc_mb": 24
  }
}
```

---

### Events

#### Liste des événements

```http
GET /api/v1/events
```

Paramètres :
| Param | Type | Description |
|-------|------|-------------|
| `log_type` | string | Filtrer par type (WAF, IPS, ATP, etc.) |
| `severity` | string | Filtrer par sévérité (critical, high, medium, low) |
| `src_ip` | string | Filtrer par IP source |
| `action` | string | Filtrer par action (drop, allow) |
| `start_time` | datetime | Début de la période |
| `end_time` | datetime | Fin de la période |
| `limit` | int | Nombre max de résultats (défaut: 50) |
| `offset` | int | Pagination offset |

#### Timeline

```http
GET /api/v1/events/timeline
```

Paramètres :
| Param | Type | Description |
|-------|------|-------------|
| `period` | string | Période (24h, 7d, 30d) |
| `interval` | string | Intervalle (hour, day) |

Réponse :
```json
{
  "data": [
    {
      "time": "2025-01-06T10:00:00Z",
      "total_events": 1250,
      "blocked_events": 890,
      "unique_ips": 45
    }
  ]
}
```

---

### Stats

#### Overview

```http
GET /api/v1/stats/overview
```

Réponse :
```json
{
  "total_events": 125000,
  "blocked_events": 89000,
  "block_rate": 71.2,
  "unique_ips": 4523,
  "critical_events": 234,
  "high_events": 1567,
  "by_log_type": {
    "WAF": 45000,
    "IPS": 35000,
    "Firewall": 40000
  }
}
```

#### Top Attackers

```http
GET /api/v1/stats/top-attackers
```

Paramètres :
| Param | Type | Description |
|-------|------|-------------|
| `period` | string | Période (24h, 7d, 30d) |
| `limit` | int | Nombre de résultats (défaut: 10) |

---

### Bans

#### Liste des bans actifs

```http
GET /api/v1/bans
```

#### Créer un ban

```http
POST /api/v1/bans
Content-Type: application/json

{
  "ip": "192.168.1.100",
  "reason": "Multiple WAF attacks detected",
  "duration_days": 7,
  "permanent": false
}
```

#### Débannir une IP

```http
DELETE /api/v1/bans/{ip}
```

#### Étendre un ban

```http
PUT /api/v1/bans/{ip}/extend
Content-Type: application/json

{
  "duration_days": 7,
  "reason": "Continued malicious activity"
}
```

#### Rendre permanent

```http
PUT /api/v1/bans/{ip}/permanent
```

#### Synchroniser avec Sophos

```http
POST /api/v1/bans/sync
```

---

### Threats (v1.6)

7 providers intégrés : AbuseIPDB, VirusTotal, AlienVault OTX, GreyNoise, IPSum, CriminalIP, Pulsedive

#### Check IP (Threat Intel complet)

```http
GET /api/v1/threats/check/{ip}
```

Réponse :
```json
{
  "ip": "45.148.10.121",
  "aggregated_score": 65,
  "threat_level": "high",
  "confidence": 0.85,
  "sources": [
    {"provider": "AbuseIPDB", "score": 95, "available": true},
    {"provider": "VirusTotal", "score": 45, "available": true},
    {"provider": "GreyNoise", "score": 80, "is_benign_source": false},
    {"provider": "IPSum", "score": 70, "available": true}
  ],
  "is_tor": false,
  "is_vpn": false,
  "is_benign": false,
  "in_blocklists": 3,
  "tags": ["internet_scanner", "greynoise_malicious"]
}
```

#### Combined Risk Assessment (v1.6.5)

```http
GET /api/v1/threats/risk/{ip}
```

Combine Threat Intel + Blocklist Feed Ingester pour une évaluation complète.

Réponse :
```json
{
  "ip": "45.148.10.121",
  "threat_score": 65,
  "threat_level": "high",
  "blocklist_count": 5,
  "blocklist_sources": ["firehol_level1", "spamhaus_drop", "blocklist_de"],
  "blocklist_categories": ["mixed", "malware", "attacker"],
  "combined_score": 100,
  "combined_risk": "critical",
  "recommend_ban": true,
  "is_tor": false,
  "is_vpn": false,
  "tags": ["in_blocklists", "internet_scanner"]
}
```

#### Should Ban

```http
GET /api/v1/threats/should-ban/{ip}?threshold=80
```

#### Providers Status

```http
GET /api/v1/threats/providers
```

Réponse :
```json
[
  {"name": "AbuseIPDB", "configured": true, "description": "IP abuse reports"},
  {"name": "VirusTotal", "configured": true, "description": "Multi-AV consensus"},
  {"name": "AlienVault OTX", "configured": true, "description": "Threat context"},
  {"name": "GreyNoise", "configured": true, "description": "FP reduction"},
  {"name": "IPSum", "configured": true, "description": "30+ blocklists"},
  {"name": "CriminalIP", "configured": true, "description": "C2/VPN/Proxy"},
  {"name": "Pulsedive", "configured": true, "description": "IOC correlation"}
]
```

---

### Blocklists (v1.6.5)

Ingestion de 11 blocklists publiques avec synchronisation dynamique.

#### Statistiques

```http
GET /api/v1/blocklists/stats
```

Réponse :
```json
{
  "total_blocked_ips": 803544,
  "feed_count": 11,
  "feed_stats": [...]
}
```

#### Status des Feeds

```http
GET /api/v1/blocklists/feeds
```

Réponse :
```json
{
  "feeds": [
    {
      "source": "firehol_level1",
      "display_name": "Firehol Level 1",
      "url": "https://...",
      "last_sync": "2026-01-07T10:00:00Z",
      "ip_count": 564941,
      "status": "success"
    }
  ],
  "count": 11
}
```

#### Synchronisation manuelle

```http
POST /api/v1/blocklists/sync
```

Réponse :
```json
{
  "message": "Sync completed",
  "total_feeds": 11,
  "success_count": 9,
  "results": [
    {"source": "firehol_level1", "success": true, "ip_count": 564941}
  ]
}
```

#### Sync d'un feed spécifique

```http
POST /api/v1/blocklists/feeds/{name}/sync
```

#### Vérifier une IP

```http
GET /api/v1/blocklists/check/{ip}
```

Réponse :
```json
{
  "ip": "1.0.170.22",
  "is_blocked": true,
  "source_count": 3,
  "sources": ["binary_defense", "firehol_level1", "blocklist_de"],
  "categories": ["attacker", "mixed"],
  "max_confidence": 90,
  "first_seen": "2026-01-07T09:00:00Z",
  "last_seen": "2026-01-07T10:00:00Z"
}
```

#### IPs haute-risque (multi-sources)

```http
GET /api/v1/blocklists/high-risk?min_lists=3
```

Réponse :
```json
{
  "min_lists": 3,
  "count": 1000,
  "ips": [
    {
      "ip": "45.148.10.121",
      "source_count": 5,
      "sources": ["firehol_level1", "firehol_level2", "spamhaus_drop", "binary_defense", "blocklist_de"],
      "max_confidence": 95
    }
  ]
}
```

---

### Whitelist

#### Liste

```http
GET /api/v1/whitelist
```

#### Ajouter

```http
POST /api/v1/whitelist
Content-Type: application/json

{
  "ip": "10.0.0.1",
  "description": "Internal monitoring server"
}
```

#### Supprimer

```http
DELETE /api/v1/whitelist/{ip}
```

---

### Anomalies

#### Liste des anomalies

```http
GET /api/v1/anomalies
```

#### Nouvelles IPs

```http
GET /api/v1/anomalies/new-ips
```

#### Acknowledger une anomalie

```http
PUT /api/v1/anomalies/{id}/acknowledge
```

---

### WebSocket

```
ws://localhost:8080/ws
```

Messages entrants (subscribe) :
```json
{"action": "subscribe", "topic": "events:critical"}
```

Topics disponibles :
- `events:all` - Tous les événements
- `events:critical` - Événements critiques uniquement
- `events:waf` - Événements WAF
- `bans` - Mises à jour des bans
- `anomalies` - Alertes d'anomalies
- `stats` - Stats temps réel

Messages sortants :
```json
{
  "type": "new_event",
  "payload": { ... },
  "time": "2025-01-06T12:00:00Z"
}
```

---

## Codes d'erreur

| Code | Description |
|------|-------------|
| 200 | Succès |
| 201 | Créé |
| 400 | Requête invalide |
| 401 | Non authentifié |
| 403 | Non autorisé |
| 404 | Non trouvé |
| 409 | Conflit (ex: IP déjà bannie) |
| 429 | Trop de requêtes |
| 500 | Erreur serveur |
| 501 | Non implémenté |

## Pagination

Toutes les listes supportent la pagination :

```http
GET /api/v1/events?limit=50&offset=100
```

Réponse :
```json
{
  "data": [...],
  "pagination": {
    "total": 5000,
    "limit": 50,
    "offset": 100,
    "has_more": true
  }
}
```
