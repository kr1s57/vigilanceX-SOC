# Security & Hardening

## Security Architecture

VIGILANCE X is built with security in mind, implementing multiple layers of protection.

## Binary Protection

### Obfuscation

All binaries are protected using:

| Protection | Tool | Effect |
|------------|------|--------|
| Code Obfuscation | Garble | Function names, strings obfuscated |
| Compression | UPX | Binary compressed, harder to analyze |
| Symbol Stripping | `-ldflags "-w -s"` | Debug symbols removed |

### Image Signing

Docker images are signed using [Sigstore Cosign](https://github.com/sigstore/cosign):

```bash
# Verify image signature
./vigilance.sh verify

# Manual verification
cosign verify ghcr.io/kr1s57/vigilancex-api:3.1.4
```

## License Security (VX3)

### Hardware Binding

Licenses are bound to:
- **VM Machine ID**: `/etc/machine-id`
- **Firewall Serial**: Extracted from Sophos XGS logs

This prevents:
- Copying license files between VMs
- Cloning VMs with active licenses
- Transferring licenses between customers

### Grace Period

If the license server is unreachable:
- **Grace Period**: 72 hours (3 days)
- Features remain functional during grace
- After grace expiration, premium features disabled

### Rate Limiting

License activation is rate-limited:
- **5 attempts per hour** per IP address
- Prevents brute-force attacks on license keys

## Container Security

### Non-Root Execution

All containers run as non-root users:

| Container | User |
|-----------|------|
| backend | vigilance (uid 1000) |
| detect2ban | vigilance (uid 1000) |
| frontend | nginx (default) |
| clickhouse | clickhouse |

### Read-Only Mounts

Configuration files are mounted read-only:
- `/etc/vector/vector.toml:ro`
- `/etc/nginx/nginx.conf:ro`
- `/etc/machine-id:ro`

### Resource Limits

Recommended Docker resource limits:

```yaml
# Add to docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

## Network Security

### Firewall Rules

Recommended iptables rules:

```bash
# Allow only necessary inbound ports
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # HTTP redirect
iptables -A INPUT -p udp --dport 514 -j ACCEPT  # Syslog UDP
iptables -A INPUT -p tcp --dport 1514 -j ACCEPT # Syslog TCP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH (management)
iptables -A INPUT -j DROP                        # Drop everything else
```

### Internal Network Isolation

The Docker network `vigilance_net` isolates containers:
- Only nginx is exposed to external network
- Internal services communicate only within Docker network

### TLS Configuration

Nginx is configured with secure TLS settings:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
```

HSTS is enabled with a 2-year max-age.

## Authentication Security

### Password Hashing

Passwords are hashed using **bcrypt** with cost factor 12:
- Resistant to brute-force attacks
- GPU-resistant algorithm

### JWT Tokens

- Signed with HMAC-SHA256
- Default expiry: 24 hours
- Minimum secret length: 32 characters

### Rate Limiting

API rate limits:
- **Global**: 100 requests/minute per IP
- **Login**: 5 attempts/minute per IP
- **License Activation**: 5 attempts/hour per IP

## Data Security

### Encryption at Rest

Recommended: Enable disk encryption on host:

```bash
# Ubuntu with LUKS
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup open /dev/sdb encrypted_data
sudo mkfs.ext4 /dev/mapper/encrypted_data
```

### Backup Encryption

Encrypt backups before offsite storage:

```bash
# Encrypt backup
gpg --symmetric --cipher-algo AES256 backup.tar.gz

# Decrypt
gpg --decrypt backup.tar.gz.gpg > backup.tar.gz
```

### Log Retention

ClickHouse retains events for 90 days by default. Adjust in:
- `config/clickhouse/init-db.sql`

## Security Checklist

### Pre-Deployment

- [ ] Change all default passwords
- [ ] Generate secure JWT secret (32+ chars)
- [ ] Configure firewall rules
- [ ] Enable disk encryption
- [ ] Set up regular backups

### Post-Deployment

- [ ] Change default admin password
- [ ] Activate license
- [ ] Verify image signatures
- [ ] Test backup/restore procedure
- [ ] Configure monitoring/alerting

### Ongoing

- [ ] Apply updates promptly (`./vigilance.sh update`)
- [ ] Review access logs regularly
- [ ] Rotate secrets periodically
- [ ] Monitor disk space
- [ ] Test backup restores

## Reporting Security Issues

If you discover a security vulnerability, please contact:
- **Email**: security@vigilancex.io
- Do NOT create public GitHub issues for security vulnerabilities
