# Administration Guide

## Daily Operations

### Starting and Stopping

```bash
# Start all services
./vigilance.sh start

# Stop all services
./vigilance.sh stop

# Restart all services
./vigilance.sh restart

# Check status
./vigilance.sh status
```

### Viewing Logs

```bash
# All services (follow mode)
./vigilance.sh logs

# Specific service
./vigilance.sh logs backend
./vigilance.sh logs frontend
./vigilance.sh logs clickhouse
./vigilance.sh logs nginx
./vigilance.sh logs vector
```

## Backup & Restore

### Creating Backups

```bash
# Manual backup
./vigilance.sh backup
```

Backups are stored in `./backups/` directory:
- `clickhouse_YYYYMMDD_HHMMSS.tar.gz` - Database
- `redis_YYYYMMDD_HHMMSS.tar.gz` - Cache
- `license_YYYYMMDD_HHMMSS.tar.gz` - License data

### Automatic Backups

Backups are automatically created before updates.

To schedule daily backups, add to crontab:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /path/to/vigilanceX-SOC/vigilance.sh backup >> /var/log/vigilance-backup.log 2>&1
```

### Retention Policy

- Last 7 backups are retained automatically
- Older backups are deleted during backup process

### Restoring from Backup

```bash
# List available backups
./vigilance.sh restore

# Restore specific backup (manual process)
# 1. Stop services
./vigilance.sh stop

# 2. Extract backup
tar xzf backups/clickhouse_20240101_020000.tar.gz -C /tmp/restore

# 3. Copy to volume
docker run --rm -v vigilance_clickhouse_data:/data -v /tmp/restore:/backup alpine cp -r /backup/* /data/

# 4. Start services
./vigilance.sh start
```

## Updates

### Updating VIGILANCE X

```bash
# Update with automatic backup
./vigilance.sh update
```

The update process:
1. Creates backup of all data
2. Pulls latest configuration from git
3. Pulls new Docker images
4. Restarts services with new images
5. Cleans up old images

### Rollback

If an update causes issues:

```bash
# 1. Stop services
./vigilance.sh stop

# 2. Pull specific version
docker pull ghcr.io/kr1s57/vigilancex-api:2.9.7

# 3. Update docker-compose.yml with old version
nano deploy/docker-compose.yml

# 4. Start services
./vigilance.sh start
```

## User Management

### Via Web Interface

1. Login as admin
2. Go to: Settings > Users
3. Create/Edit/Delete users

### Roles

| Role | Description |
|------|-------------|
| admin | Full access, including user management |
| audit | Read-only access, no ban/unban actions |

### Password Reset

If admin password is lost:

```bash
# Reset via CLI
docker exec vigilance_backend /app/reset-password admin NewPassword123!
```

## License Management

### Activation

1. Go to: Settings > License
2. Enter license key
3. Click "Activate"

### Sync License

Force license sync with server:

```bash
# Via API
curl -X POST http://localhost:8080/api/v1/license/validate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Grace Mode

If license server is unreachable:
- System enters "Grace Mode"
- Full functionality for 72 hours
- After grace, premium features disabled

## Monitoring

### Health Check

```bash
# API health
curl http://localhost:8080/health

# Via script
./vigilance.sh status
```

### Disk Usage

```bash
# Docker disk usage
docker system df

# Volume sizes
docker system df -v | grep vigilance
```

### Database Size

```sql
-- Connect to ClickHouse
docker exec -it vigilance_clickhouse clickhouse-client

-- Check database size
SELECT
    database,
    formatReadableSize(sum(bytes_on_disk)) as size
FROM system.parts
WHERE database = 'vigilance_x'
GROUP BY database;
```

## Performance Tuning

### ClickHouse

For high-volume environments, increase memory:

```yaml
# docker-compose.yml
clickhouse:
  environment:
    MAX_MEMORY_USAGE: 4000000000  # 4GB
```

### Redis

Increase max memory:

```yaml
redis:
  command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD} --maxmemory 512mb
```

### Vector

Adjust batch size for high throughput:

```toml
# config/vector/vector.toml
[sinks.clickhouse]
batch.max_bytes = 10485760  # 10MB
batch.timeout_secs = 5
```

## Maintenance Tasks

### Cleanup Old Data

ClickHouse automatically expires data after 90 days. To force cleanup:

```sql
-- Remove data older than 30 days
ALTER TABLE vigilance_x.events
DELETE WHERE timestamp < now() - INTERVAL 30 DAY;

-- Optimize table
OPTIMIZE TABLE vigilance_x.events FINAL;
```

### Docker Cleanup

```bash
# Remove unused images
docker image prune -f

# Remove all unused resources
docker system prune -f

# Remove unused volumes (CAREFUL!)
docker volume prune -f
```

### Log Rotation

Docker logs are managed by the Docker daemon. Configure in `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  }
}
```

Then restart Docker: `sudo systemctl restart docker`
