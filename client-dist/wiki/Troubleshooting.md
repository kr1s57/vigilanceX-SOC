# Troubleshooting Guide

## Common Issues

### Services Not Starting

**Symptom**: `./vigilance.sh status` shows services as "Exited" or "Restarting"

**Solutions**:

1. Check Docker logs:
```bash
docker logs vigilance_backend
docker logs vigilance_clickhouse
```

2. Verify disk space:
```bash
df -h
# Ensure at least 10% free space
```

3. Check memory:
```bash
free -h
# Ensure at least 1GB free
```

4. Verify configuration:
```bash
# Check .env file syntax
cat deploy/.env | grep -v "^#" | grep -v "^$"
```

### No Events in Dashboard

**Symptom**: Dashboard shows 0 events, no data in WAF Explorer

**Solutions**:

1. Verify Sophos Syslog configuration:
   - Check Sophos XGS: System > Administration > Syslog
   - Ensure correct IP and port (514/UDP or 1514/TCP)

2. Check firewall rules:
```bash
sudo iptables -L -n | grep 514
# Should show ACCEPT rule for port 514
```

3. Check Vector is receiving logs:
```bash
./vigilance.sh logs vector
# Look for "Received X events" messages
```

4. Test syslog connectivity:
```bash
# From another machine
nc -u VIGILANCE_IP 514
# Type a test message
```

5. Check ClickHouse is storing data:
```bash
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT count() FROM vigilance_x.events"
```

### License Activation Failed

**Symptom**: "Activation failed" error when entering license key

**Solutions**:

1. Verify internet connectivity:
```bash
curl -I https://vigilancexkey.cloudcomputing.lu
```

2. Check machine ID exists:
```bash
cat /etc/machine-id
# Should return a UUID
```

3. Verify license key format:
   - Format: XXXX-XXXX-XXXX-XXXX
   - No spaces or extra characters

4. Check rate limiting:
   - Only 5 activation attempts per hour
   - Wait 1 hour if exceeded

5. Contact support: support@vigilancex.io

### Login Failed

**Symptom**: Cannot login to dashboard, "Invalid credentials" error

**Solutions**:

1. Verify default credentials:
   - Username: admin
   - Password: VigilanceX2024!

2. Reset admin password:
```bash
docker exec vigilance_backend /app/reset-password admin NewPassword123!
```

3. Check JWT secret is set:
```bash
grep JWT_SECRET deploy/.env
# Must be at least 32 characters
```

### WebSocket Disconnected

**Symptom**: Dashboard shows "WebSocket Disconnected" in red

**Solutions**:

1. Check backend is running:
```bash
./vigilance.sh status
# Backend should be "Up"
```

2. Check nginx configuration:
```bash
./vigilance.sh logs nginx
# Look for WebSocket proxy errors
```

3. Verify browser console:
   - Open Developer Tools (F12)
   - Check Console for WebSocket errors

4. Check firewall allows WebSocket:
```bash
# WebSocket uses same port as HTTPS (443)
curl -I https://localhost/ws
```

### Sophos Sync Failed

**Symptom**: Bans not syncing to Sophos XGS

**Solutions**:

1. Check Sophos API configuration:
```bash
grep SOPHOS deploy/.env
# Verify host, port, user, password
```

2. Test Sophos API connectivity:
```bash
curl -k "https://SOPHOS_IP:4444/webconsole/APIController?&reqxml=<Request><Login><Username>admin</Username><Password>PASS</Password></Login></Request>"
```

3. Check backend logs:
```bash
./vigilance.sh logs backend | grep -i sophos
```

4. Verify Sophos API is enabled:
   - Go to Sophos: System > Admin Settings
   - Enable "Allow API access"

### High Memory Usage

**Symptom**: Server running out of memory, services crashing

**Solutions**:

1. Check memory usage:
```bash
docker stats --no-stream
```

2. Identify largest consumer:
```bash
docker stats --no-stream | sort -k4 -h
```

3. Reduce ClickHouse memory:
```bash
# Add to docker-compose.yml under clickhouse:
environment:
  MAX_MEMORY_USAGE: 2000000000  # 2GB
```

4. Clean up old data:
```bash
docker exec vigilance_clickhouse clickhouse-client \
  --query "ALTER TABLE vigilance_x.events DELETE WHERE timestamp < now() - INTERVAL 30 DAY"
```

### Slow Dashboard

**Symptom**: Dashboard loads slowly, queries timeout

**Solutions**:

1. Check ClickHouse performance:
```bash
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT query, elapsed FROM system.processes"
```

2. Optimize tables:
```bash
docker exec vigilance_clickhouse clickhouse-client \
  --query "OPTIMIZE TABLE vigilance_x.events FINAL"
```

3. Check disk I/O:
```bash
iostat -x 1 5
# High await or %util indicates disk bottleneck
```

4. Consider SSD upgrade if using HDD

## Diagnostic Commands

### Container Status

```bash
# All containers
docker ps -a | grep vigilance

# Specific container details
docker inspect vigilance_backend

# Container resource usage
docker stats vigilance_backend
```

### Network Diagnostics

```bash
# Check container networking
docker network inspect vigilance_net

# Test internal connectivity
docker exec vigilance_backend ping clickhouse

# Check port bindings
docker port vigilance_nginx
```

### Database Diagnostics

```bash
# ClickHouse status
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT * FROM system.metrics LIMIT 10"

# Table sizes
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT table, formatReadableSize(sum(bytes)) as size FROM system.parts GROUP BY table"

# Active queries
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT * FROM system.processes"
```

### Log Analysis

```bash
# Backend errors only
docker logs vigilance_backend 2>&1 | grep -i error

# Last 100 lines
docker logs --tail 100 vigilance_backend

# Since specific time
docker logs --since "2024-01-01T00:00:00" vigilance_backend
```

## Getting Help

### Before Contacting Support

Please gather:
1. Output of `./vigilance.sh status`
2. Backend logs: `docker logs vigilance_backend 2>&1 | tail -100`
3. Error messages from dashboard
4. Your license key (first 4 characters only)
5. Server specs (RAM, CPU, disk)

### Contact Support

- **Email**: support@vigilancex.io
- Include diagnostic information above
- Response time: 24-48 hours
