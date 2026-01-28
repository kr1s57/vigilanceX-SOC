# Guide de Déploiement

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

VIGILANCE X est déployé via Docker Compose avec 6 services.

---

## Prérequis

### Serveur

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| **CPU** | 4 cores | 8 cores |
| **RAM** | 8 GB | 16 GB |
| **Disque** | 100 GB SSD | 500 GB NVMe |
| **OS** | Ubuntu 22.04 | Ubuntu 24.04 |

### Logiciels

| Logiciel | Version |
|----------|---------|
| Docker | 24+ |
| Docker Compose | 2.20+ |
| Git | 2.40+ |

### Réseau

| Port | Service | Direction |
|------|---------|-----------|
| 80/443 | Nginx | Inbound |
| 514/UDP | Vector (Syslog) | Inbound |
| 1514/TCP | Vector (Syslog) | Inbound |
| 8080 | Backend API | Internal |
| 3000 | Frontend | Internal |

---

## Installation

### 1. Cloner le Projet

```bash
cd /opt
git clone https://github.com/kr1s57/vigilanceX.git
cd vigilanceX
```

### 2. Configuration

```bash
cd docker
cp .env.example .env
nano .env
```

### Variables Requises

```env
# Database
CLICKHOUSE_PASSWORD=votre_mot_de_passe_securise
REDIS_PASSWORD=votre_mot_de_passe_redis

# Sophos XGS
SOPHOS_HOST=10.x.x.x
SOPHOS_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASSWORD=xxx

# Sophos SSH (ModSec sync)
SOPHOS_SSH_HOST=10.x.x.x
SOPHOS_SSH_PORT=22
SOPHOS_SSH_USER=admin

# JWT
JWT_SECRET=votre_secret_jwt_32_chars_min

# Licence
LICENSE_ENABLED=true
LICENSE_SERVER_URL=https://license.example.com

# TI APIs (optionnel, au moins un recommandé)
ABUSEIPDB_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
ALIENVAULT_API_KEY=xxx
```

### 3. Clé SSH Sophos

```bash
# Copier votre clé SSH
cp /path/to/id_rsa_xgs docker/ssh/id_rsa_xgs
chmod 600 docker/ssh/id_rsa_xgs
```

### 4. Démarrer

```bash
docker compose up -d
```

### 5. Vérifier

```bash
# Status
docker compose ps

# Logs
docker compose logs -f

# Health
curl http://localhost:8080/health
```

---

## Configuration Sophos XGS

### Syslog

1. Accéder à **Logging > Log Settings**
2. Ajouter un serveur Syslog:
   - IP: `<IP_VIGILANCE_X>`
   - Port: `514` (UDP) ou `1514` (TCP)
   - Facility: Local0
3. Sélectionner les logs à envoyer:
   - WAF
   - IPS
   - ATP
   - Anti-Virus
   - Firewall

### API XML

1. Accéder à **Administration > Admin Settings**
2. Activer l'API XML sur port 4444
3. Configurer un utilisateur API

### SSH (ModSec)

1. Activer SSH sur le firewall
2. Ajouter la clé publique de VIGILANCE X
3. Autoriser l'accès aux logs `/log/reverseproxy.log`

---

## Configuration Nginx (Production)

### Certificats SSL

```bash
# Let's Encrypt
certbot certonly --standalone -d vigilance.example.com

# Copier vers docker
cp /etc/letsencrypt/live/vigilance.example.com/fullchain.pem docker/nginx/ssl/
cp /etc/letsencrypt/live/vigilance.example.com/privkey.pem docker/nginx/ssl/
```

### Activer le Profil Production

```bash
docker compose --profile production up -d
```

---

## Mise à Jour

### Via Git

```bash
cd /opt/vigilanceX

# Sauvegarder
docker compose down

# Mettre à jour
git pull origin main

# Rebuild et restart
docker compose up -d --build
```

### Via GHCR (Production)

```bash
cd /opt/vigilanceX/docker

# Pull nouvelles images
docker compose pull

# Restart
docker compose up -d --force-recreate
```

---

## Sauvegarde

### Base de Données

```bash
# Backup ClickHouse
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT * FROM vigilance_x.events" \
  --format Native > backup_events.native

# Ou via volume
docker run --rm -v vigilance_clickhouse_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/clickhouse_backup.tar.gz /data
```

### Configuration

```bash
# Sauvegarder .env et configs
tar czf backup_config.tar.gz docker/.env docker/clickhouse docker/vector
```

### Volumes Docker

```bash
# Liste des volumes
docker volume ls | grep vigilance

# Backup tous les volumes
for vol in $(docker volume ls -q | grep vigilance); do
  docker run --rm -v $vol:/data -v $(pwd):/backup \
    alpine tar czf /backup/${vol}.tar.gz /data
done
```

---

## Monitoring

### Health Checks

```bash
# API
curl http://localhost:8080/health

# ClickHouse
docker exec vigilance_clickhouse clickhouse-client --query "SELECT 1"

# Redis
docker exec vigilance_redis redis-cli -a $REDIS_PASSWORD ping
```

### Logs

```bash
# Tous les services
docker compose logs -f

# Service spécifique
docker compose logs -f api

# Avec timestamps
docker compose logs -f --timestamps api
```

### Métriques

| Métrique | Commande |
|----------|----------|
| CPU/RAM | `docker stats` |
| Disque | `df -h` |
| Events/hour | `SELECT count() FROM events WHERE timestamp > now() - INTERVAL 1 HOUR` |
| Bans actifs | `SELECT count() FROM bans WHERE status = 'active'` |

---

## Dépannage

### Problème: API ne démarre pas

```bash
# Vérifier logs
docker compose logs api

# Causes communes:
# - ClickHouse pas prêt → Attendre health check
# - .env manquant → Vérifier configuration
# - Port 8080 utilisé → Vérifier netstat -tlpn
```

### Problème: Pas de logs Syslog

```bash
# Vérifier Vector
docker compose logs vector

# Tester réception
nc -ul 514  # Écouter UDP

# Vérifier firewall
ufw status
```

### Problème: Bans non synchronisés vers XGS

```bash
# Vérifier connexion Sophos
curl -k https://$SOPHOS_HOST:4444/webconsole/APIController

# Logs ban sync
docker compose logs api | grep -i sophos
```

### Problème: Performances lentes

```bash
# Vérifier ressources
docker stats

# Vérifier ClickHouse
docker exec vigilance_clickhouse clickhouse-client \
  --query "SELECT query, elapsed FROM system.processes"

# Optimiser
docker exec vigilance_clickhouse clickhouse-client \
  --query "OPTIMIZE TABLE vigilance_x.events"
```

---

## Sécurité

### Recommandations

1. **Réseau**: Déployer sur réseau interne uniquement
2. **VPN**: Accès via VPN obligatoire
3. **Firewall**: Limiter les ports exposés
4. **SSL**: Activer HTTPS en production
5. **Updates**: Mettre à jour régulièrement

### Hardening

```bash
# Désactiver accès root SSH
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Firewall UFW
ufw default deny incoming
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw allow 514/udp  # Syslog
ufw enable
```

---

## Environnements

| Environnement | Machine | Usage |
|---------------|---------|-------|
| **DEV** | 10.25.72.28 | Développement |
| **VPS-TEST** | OVH vps-* | Tests client |
| **PROD** | Client | Production |

---

## Support

- **Issues**: https://github.com/kr1s57/vigilanceX/issues
- **Wiki**: https://github.com/kr1s57/vigilanceX/wiki
- **Docs**: `/opt/vigilanceX/docs/`

---

*Documentation générée par le workflow document-project*
