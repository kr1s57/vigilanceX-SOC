# Changelog

All notable changes to VIGILANCE X will be documented in this file.

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
