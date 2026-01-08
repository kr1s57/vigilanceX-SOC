# Architecture Overview

## System Requirements

### Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB SSD | 100+ GB SSD |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

| Component | Version |
|-----------|---------|
| Docker | 20.10+ |
| Docker Compose | v2.0+ |
| OS | Linux (Ubuntu 22.04 LTS recommended) |

## Architecture Diagram

```
                                    INTERNET
                                        │
                                        ▼
┌───────────────────────────────────────────────────────────────┐
│                        SOPHOS XGS                             │
│                    (Firewall/WAF/IPS)                         │
└───────────────────────────────────────────────────────────────┘
            │                    │                    │
            │ Syslog             │ API                │ SSH
            │ (514/1514)         │ (4444)             │ (22)
            ▼                    ▼                    ▼
┌───────────────────────────────────────────────────────────────┐
│                     VIGILANCE X STACK                          │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│ │   Vector    │  │   Backend   │  │   Backend   │            │
│ │  (Syslog)   │  │  (Go API)   │  │  (ModSec)   │            │
│ └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
│        │                │                │                    │
│        ▼                ▼                ▼                    │
│ ┌─────────────────────────────────────────────────┐          │
│ │              ClickHouse (Analytics)              │          │
│ │         + Redis (Cache) + Backend Data           │          │
│ └─────────────────────────────────────────────────┘          │
│        │                                                      │
│        ▼                                                      │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│ │  Frontend   │◀─│    Nginx    │◀─│   Users     │            │
│ │   (React)   │  │   (HTTPS)   │  │ (Browser)   │            │
│ └─────────────┘  └─────────────┘  └─────────────┘            │
└───────────────────────────────────────────────────────────────┘
            │
            ▼
┌───────────────────────────────────────────────────────────────┐
│                  EXTERNAL SERVICES                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │AbuseIPDB │  │VirusTotal│  │ GreyNoise│  │ CrowdSec │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │   OTX    │  │ThreatFox │  │ URLhaus  │  │  Shodan  │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────────┐      │
│  │CriminalIP│  │Pulsedive │  │ License Server (VX3)  │      │
│  └──────────┘  └──────────┘  └────────────────────────┘      │
└───────────────────────────────────────────────────────────────┘
```

## Network Flows

### Inbound Ports

| Port | Protocol | Source | Description |
|------|----------|--------|-------------|
| 443 | TCP | Users | HTTPS Dashboard |
| 80 | TCP | Users | HTTP (redirects to HTTPS) |
| 514 | UDP | Sophos XGS | Syslog (standard) |
| 1514 | TCP | Sophos XGS | Syslog (reliable) |

### Outbound Ports

| Port | Protocol | Destination | Description |
|------|----------|-------------|-------------|
| 443 | TCP | License Server | License validation |
| 443 | TCP | TI Providers | Threat Intelligence APIs |
| 4444 | TCP | Sophos XGS | XML API (ban management) |
| 22 | TCP | Sophos XGS | SSH (ModSec logs) |

## Container Services

| Service | Image | Purpose |
|---------|-------|---------|
| clickhouse | clickhouse-server:24.1 | Analytics database |
| redis | redis:7-alpine | Session cache |
| vector | vector:0.34.1-debian | Log ingestion |
| backend | vigilancex-api | REST API server |
| detect2ban | vigilancex-detect2ban | Detection engine |
| frontend | vigilancex-frontend | Web dashboard |
| nginx | nginx:alpine | TLS reverse proxy |

## Data Flow

1. **Sophos XGS** sends logs via Syslog (UDP 514 / TCP 1514)
2. **Vector** parses and transforms logs
3. **ClickHouse** stores logs for analytics
4. **Backend** processes events, queries Threat Intel
5. **Frontend** displays real-time dashboard
6. **Backend** syncs bans to Sophos via XML API

## License Binding (VX3)

The VX3 license system binds to:
- **VM Identity**: `/etc/machine-id`
- **Firewall Serial**: Extracted from Sophos XGS logs

This prevents license copying between different installations.
