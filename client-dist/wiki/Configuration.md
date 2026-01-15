# Configuration Reference

## Environment Variables

All configuration is done via the `deploy/.env` file.

### Database - ClickHouse

| Variable | Default | Description |
|----------|---------|-------------|
| `CLICKHOUSE_USER` | vigilance | Database username |
| `CLICKHOUSE_PASSWORD` | *required* | Database password |

### Cache - Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_PASSWORD` | *required* | Redis authentication password |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | *required* | JWT signing key (min 32 chars) |
| `JWT_EXPIRY` | 24h | Token expiration time |
| `ADMIN_USERNAME` | admin | Default admin username |
| `ADMIN_PASSWORD` | VigilanceX2024! | Default admin password |

### Sophos XGS Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `SOPHOS_HOST` | *required* | Sophos firewall IP address |
| `SOPHOS_PORT` | 4444 | XML API port |
| `SOPHOS_USER` | admin | API username |
| `SOPHOS_PASSWORD` | *required* | API password |
| `SOPHOS_BAN_GROUP` | VIGILANCE_X_BLOCKLIST | IP group for temporary bans |
| `SOPHOS_PERMANENT_GROUP` | VIGILANCE_X_PERMANENT | IP group for permanent bans |

### Sophos SSH (ModSecurity)

| Variable | Default | Description |
|----------|---------|-------------|
| `SOPHOS_SSH_HOST` | | SSH host for ModSec logs |
| `SOPHOS_SSH_PORT` | 22 | SSH port |
| `SOPHOS_SSH_USER` | admin | SSH username |
| `SOPHOS_SSH_KEY_PATH` | /app/.ssh/id_rsa_xgs | Path to SSH private key |

### License

| Variable | Default | Description |
|----------|---------|-------------|
| `LICENSE_KEY` | | Your license key |
| `LICENSE_SERVER_URL` | https://vgxkey.vigilancex.lu | License server |
| `LICENSE_GRACE_PERIOD` | 72h | Offline grace period |
| `LICENSE_HEARTBEAT_INTERVAL` | 12h | License check interval |

### Threat Intelligence

All API keys are optional. Leave empty to skip the provider.

#### Tier 1 (Unlimited - Free)

| Variable | Description |
|----------|-------------|
| `ALIENVAULT_API_KEY` | AlienVault OTX API key |

*IPSum, ThreatFox, URLhaus, Shodan InternetDB require no API key.*

#### Tier 2 (Moderate Rate Limits)

| Variable | Rate Limit | Description |
|----------|------------|-------------|
| `ABUSEIPDB_API_KEY` | 1000/day | AbuseIPDB API key |
| `GREYNOISE_API_KEY` | 500/day | GreyNoise API key |
| `CROWDSEC_API_KEY` | 50/day | CrowdSec CTI API key |

#### Tier 3 (Limited Rate Limits)

| Variable | Rate Limit | Description |
|----------|------------|-------------|
| `VIRUSTOTAL_API_KEY` | 500/day | VirusTotal API key |
| `CRIMINALIP_API_KEY` | 100/day | CriminalIP API key |
| `PULSEDIVE_API_KEY` | 100/day | Pulsedive API key |

### Cascade System

| Variable | Default | Description |
|----------|---------|-------------|
| `CASCADE_ENABLED` | true | Enable tiered API querying |
| `CASCADE_TIER2_THRESHOLD` | 30 | Score to trigger Tier 2 |
| `CASCADE_TIER3_THRESHOLD` | 60 | Score to trigger Tier 3 |

## Configuration Files

### Vector (Syslog Parser)

Location: `config/vector/vector.toml`

Modify to:
- Change syslog ports
- Add custom parsing rules
- Adjust batch sizes

### Nginx (Reverse Proxy)

Location: `config/nginx/nginx.conf`

Modify to:
- Configure SSL certificates
- Adjust rate limits
- Add custom headers

### ClickHouse (Database)

Location: `config/clickhouse/init-db.sql`

Modify to:
- Adjust data retention (TTL)
- Add custom indexes
- Create additional tables

## API Endpoints

### Public Endpoints (No Auth)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/auth/login` | POST | User login |
| `/api/v1/license/status` | GET | License status |
| `/api/v1/license/activate` | POST | Activate license |

### Free Endpoints (Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/events` | GET | List events |
| `/api/v1/stats/overview` | GET | Dashboard stats |
| `/api/v1/stats/top-attackers` | GET | Top attacker IPs |
| `/api/v1/auth/me` | GET | Current user info |

### Premium Endpoints (License Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/threats/check/{ip}` | GET | Check IP threat score |
| `/api/v1/threats/risk/{ip}` | GET | Combined risk assessment |
| `/api/v1/bans` | GET/POST | Ban management |
| `/api/v1/geoblocking/rules` | GET/POST | Geoblocking rules |
| `/api/v1/whitelist` | GET/POST | Soft whitelist |
| `/api/v1/reports/generate` | GET/POST | Generate reports |

### WebSocket

| Endpoint | Description |
|----------|-------------|
| `/ws` | Real-time event stream |

Authentication via query parameter: `?token=JWT_TOKEN`

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| Global API | 100 req/min per IP |
| Login | 5 req/min per IP |
| License Activate | 5 req/hour per IP |

## SSL/TLS Configuration

### Certificate Locations

- Certificate: `config/nginx/ssl/vigilance.crt`
- Private Key: `config/nginx/ssl/vigilance.key`

### TLS Settings

Nginx enforces:
- TLS 1.2 minimum
- Strong cipher suites (ECDHE, AES-GCM)
- HSTS enabled (2 years)

### Custom Certificates

```bash
# Copy your certificates
cp your-cert.crt config/nginx/ssl/vigilance.crt
cp your-key.key config/nginx/ssl/vigilance.key

# Set permissions
chmod 600 config/nginx/ssl/*

# Restart
./vigilance.sh restart
```
