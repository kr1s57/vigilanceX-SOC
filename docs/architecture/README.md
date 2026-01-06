# Architecture VIGILANCE X

## Vue d'ensemble

VIGILANCE X est une solution SOC (Security Operations Center) avec réponse active automatisée pour Sophos XGS.

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOPHOS XGS                                │
│  Syslog (UDP 514) ──────────────────────────────────────────────┤
│  API XML (4444) ────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     VECTOR.DEV                                   │
│  • Parse logs Sophos (key=value)                                 │
│  • Normalise timestamps, IPs, actions                            │
│  • Catégorise les attaques (SQLi, XSS, RCE, etc.)               │
│  • Route vers ClickHouse                                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     CLICKHOUSE                                   │
│  • events (logs principaux, partitionné par jour)               │
│  • ip_threat_scores (cache threat intel, TTL 24h)               │
│  • ip_ban_status (état des bans)                                │
│  • stats_hourly, stats_ip_daily (Materialized Views)            │
│  • anomaly_spikes, new_ips_detected                             │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌──────────────────────┐         ┌──────────────────────────────┐
│   BACKEND GO         │         │    DETECT2BAN ENGINE         │
│                      │         │                              │
│ • API REST (/api/v1) │◄───────►│ • Scénarios YAML             │
│ • WebSocket (/ws)    │  Redis  │ • Matching temps réel        │
│ • Threat Intel       │         │ • Actions automatiques       │
│ • Ban Management     │         │ • Sync Sophos XGS            │
└──────────────────────┘         └──────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│              FRONTEND REACT                                      │
│  • Dashboard (KPIs, Timeline, Heatmap)                          │
│  • WAF Explorer                                                  │
│  • Attacks Analyzer                                              │
│  • Advanced Threat                                               │
│  • VPN & Network                                                 │
│  • Active Bans                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Composants

### Vector.dev (Ingestion)

Vector.dev reçoit les logs Syslog du Sophos XGS et effectue :
- Parsing des logs format `key=value`
- Normalisation des champs (timestamps, IPs, actions)
- Catégorisation des attaques (SQL Injection, XSS, RCE, LFI, etc.)
- Enrichissement basique
- Insertion dans ClickHouse

### ClickHouse (Storage)

Base de données analytique optimisée pour :
- Requêtes agrégées rapides (timeline, stats)
- Partitionnement par jour (rétention 90 jours)
- Materialized Views pour stats temps réel
- Index Bloom Filter sur IPs et règles

### Backend Go (API)

Architecture Clean avec :
- **Entities** : Event, Ban, Threat, Anomaly
- **Use Cases** : Services métier (events, bans, threats, anomalies)
- **Adapters** : HTTP handlers, WebSocket, repositories ClickHouse
- **External** : Client Sophos API XML, Threat Intel APIs

### Detect2Ban (Engine)

Moteur de détection et réponse :
- Scénarios YAML configurables
- Détection en temps réel (polling ClickHouse)
- Actions automatiques (ban, alert)
- Gestion du récidivisme (4 bans = permanent)

### Frontend React (UI)

SPA moderne avec :
- Shadcn UI + Tailwind CSS (Dark mode)
- Zustand (state management)
- Recharts (graphiques)
- Leaflet (carte géographique)
- WebSocket (temps réel)

## Flux de données

1. **Logs** : Sophos XGS → Syslog → Vector → ClickHouse
2. **Détection** : ClickHouse → Detect2Ban → Actions
3. **Bans** : Backend → API XML Sophos → Groupe `VIGILANCE_X_BLOCKLIST`
4. **UI** : Frontend → API REST → ClickHouse
5. **Temps réel** : Backend → WebSocket → Frontend

## Sécurité

- JWT pour l'authentification API
- Rate limiting (100 req/min par IP)
- HTTPS obligatoire en production
- Whitelist pour éviter les faux positifs
- Audit trail des actions de ban
