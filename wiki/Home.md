# VIGILANCE X Documentation

Welcome to the VIGILANCE X documentation. This wiki provides comprehensive guides for IT administrators to deploy, configure, and maintain the VIGILANCE X SOC platform.

## Quick Links

- [Architecture Overview](Architecture.md)
- [Installation Guide](Installation-Guide.md)
- [Configuration Reference](Configuration.md)
- [Upgrade Guide](Upgrade-Guide.md) *(v3.1.0)*
- [Risk Scoring Engine](Risk-Scoring.md)
- [Security & Hardening](Security-Hardening.md)
- [Administration Guide](Administration.md)
- [Troubleshooting](Troubleshooting.md)

## What is VIGILANCE X?

VIGILANCE X is a real-time Security Operations Center (SOC) platform that:

- **Debug WAF en 30 secondes** : Identifiez instantanément les règles ModSec bloquantes
- **Risk Scoring intelligent** : Score contextuel basé sur 11 providers + vos policies
- **Active Response** : Ban automatique des IPs malveillantes sur Sophos XGS
- **Syslog nouvelle génération** : Extraction des IDs ModSecurity (unique sur le marché)

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
- **XGS Parser Engine**: Native Sophos log parser (104 fields, 74 rules, 23 MITRE techniques) *(v3.1)*

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

*VIGILANCE X v3.1.0 - SOC Platform for Sophos XGS*
