# API VIGILANCE X

## Base URL

```
http://localhost:8080/api/v1
```

## Authentification

JWT Bearer token dans le header `Authorization`:
```
Authorization: Bearer <token>
```

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

### Threats

#### Score de menace

```http
GET /api/v1/threats/score/{ip}
```

Réponse :
```json
{
  "ip": "192.168.1.100",
  "total_score": 85,
  "reputation_score": 35,
  "activity_score": 35,
  "severity_score": 15,
  "threat_level": "critical",
  "is_malicious": true,
  "sources": ["abuseipdb", "virustotal"],
  "categories": ["Scanner", "Brute Force"],
  "abuseipdb_score": 95,
  "virustotal_positives": 12,
  "last_checked": "2025-01-06T12:00:00Z"
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
