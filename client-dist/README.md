# VIGILANCE X - SOC Platform

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://docs.docker.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)

**VIGILANCE X** is a real-time Security Operations Center (SOC) platform that collects Sophos XGS logs, analyzes threats with 11 Threat Intelligence providers, and automatically bans malicious IPs.

## Quick Start

### Prerequisites

- **Docker** 20.10+ with Docker Compose v2
- **4 GB RAM** minimum (8 GB recommended)
- **20 GB disk** space
- **Sophos XGS** firewall with Syslog enabled
- **License Key** (contact support@vigilancex.io)

### Installation

```bash
# 1. Clone this repository
git clone https://github.com/kr1s57/vigilanceX-SOC.git
cd vigilanceX-SOC

# 2. Configure your environment
cp deploy/config.template deploy/.env
nano deploy/.env  # Edit with your settings

# 3. Install and start
./vigilance.sh install
```

### Configuration

Edit `deploy/.env` with your settings:

| Variable | Description | Required |
|----------|-------------|----------|
| `CLICKHOUSE_PASSWORD` | ClickHouse database password | Yes |
| `REDIS_PASSWORD` | Redis cache password | Yes |
| `JWT_SECRET` | JWT signing key (32+ chars) | Yes |
| `SOPHOS_HOST` | Sophos XGS IP address | Yes |
| `SOPHOS_PASSWORD` | Sophos API password | Yes |
| `LICENSE_KEY` | Your VigilanceX license | Yes |

Generate a secure JWT secret:
```bash
openssl rand -hex 32
```

### Sophos XGS Configuration

1. **Enable Syslog**: System > Administration > Notification > Syslog
2. **Add Server**: IP of your VIGILANCE X server, port 514 (UDP) or 1514 (TCP)
3. **Select Logs**: Web filter, IPS, WAF, Authentication

## Usage

```bash
# Show help
./vigilance.sh help

# Check status
./vigilance.sh status

# View logs
./vigilance.sh logs backend

# Update to latest version
./vigilance.sh update

# Create backup
./vigilance.sh backup
```

## Access

After installation:

- **Dashboard**: https://localhost
- **Default Login**: admin / VigilanceX2024!

> **Important**: Change the default password after first login!

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Sophos XGS  │────▶│   Vector    │────▶│ ClickHouse  │
│  Firewall   │     │   (Syslog)  │     │  (Analytics)│
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
┌─────────────┐     ┌─────────────┐            │
│   Nginx     │────▶│  Frontend   │            │
│  (Reverse   │     │   (React)   │            │
│   Proxy)    │     └─────────────┘            │
└─────────────┘            │                   │
       │                   ▼                   │
       │            ┌─────────────┐            │
       └───────────▶│   Backend   │◀───────────┘
                    │   (Go API)  │
                    └─────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
             ┌───────────┐ ┌───────────┐
             │  Sophos   │ │   Threat  │
             │  XML API  │ │   Intel   │
             │  (Bans)   │ │ (11 APIs) │
             └───────────┘ └───────────┘
```

## Network Ports

| Port | Protocol | Direction | Description |
|------|----------|-----------|-------------|
| 443 | TCP | Inbound | Web Dashboard (HTTPS) |
| 80 | TCP | Inbound | HTTP redirect to HTTPS |
| 514 | UDP | Inbound | Sophos Syslog |
| 1514 | TCP | Inbound | Sophos Syslog (reliable) |

## Support

- **Email**: support@vigilancex.io
- **Documentation**: See `wiki/` folder

## License

This software is proprietary and requires a valid license.
Contact support@vigilancex.io for licensing information.

---

**VIGILANCE X** - Real-time SOC Platform for Sophos XGS
