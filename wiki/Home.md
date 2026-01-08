# VIGILANCE X Documentation

Welcome to the VIGILANCE X documentation. This wiki provides comprehensive guides for IT administrators to deploy, configure, and maintain the VIGILANCE X SOC platform.

## Quick Links

- [Architecture Overview](Architecture.md)
- [Installation Guide](Installation-Guide.md)
- [Configuration Reference](Configuration.md)
- [Security & Hardening](Security-Hardening.md)
- [Administration Guide](Administration.md)
- [Troubleshooting](Troubleshooting.md)

## What is VIGILANCE X?

VIGILANCE X is a real-time Security Operations Center (SOC) platform that:

- **Collects** logs from Sophos XGS firewalls via Syslog
- **Analyzes** threats using 11 Threat Intelligence providers
- **Bans** malicious IPs automatically via Sophos XML API
- **Provides** a modern web dashboard for security operators

## Features

### Core Modules
- **Dashboard**: Real-time security overview with key metrics
- **WAF Explorer**: Web Application Firewall log analysis
- **Attacks Analyzer**: IPS/IDS event investigation
- **Advanced Threat**: OSINT intelligence with 11 providers
- **VPN & Network**: VPN session monitoring
- **Active Bans**: IP ban management with Sophos sync
- **Geoblocking**: Country/ASN-based blocking rules
- **Soft Whitelist**: Graduated whitelist (hard/soft/monitor)

### Technical Stack
| Component | Technology |
|-----------|------------|
| Backend | Go 1.22 (Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind |
| Database | ClickHouse (real-time analytics) |
| Cache | Redis 7 |
| Logs | Vector.dev (Syslog ingestion) |
| Proxy | Nginx (TLS termination) |

## Support

- **Email**: support@vigilancex.io
- **License**: Contact sales@vigilancex.io

---

*VIGILANCE X v3.0.0 - SOC Platform for Sophos XGS*
