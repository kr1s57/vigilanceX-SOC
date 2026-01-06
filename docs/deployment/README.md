# Déploiement VIGILANCE X

## Prérequis

### Serveur

- **OS** : Ubuntu Server 22.04+ ou Debian 12+
- **CPU** : 4 cores minimum
- **RAM** : 8 GB minimum (16 GB recommandé)
- **Disque** : 100 GB SSD minimum pour `/var/lib/vigilance_x`
- **Docker** : 24.0+
- **Docker Compose** : v2.20+

### Réseau

| Port | Service | Direction |
|------|---------|-----------|
| 514/udp | Syslog (Vector) | Entrant |
| 1514/tcp | Syslog TCP (Vector) | Entrant |
| 80/443 | Web UI | Entrant |
| 4444 | API XML Sophos | Sortant |

### Sophos XGS

1. **Activer l'API XML** :
   - `System > Administration > API Configuration`
   - Activer "API Configuration"
   - Noter le mot de passe API

2. **Autoriser le serveur VIGILANCE X** :
   - `System > Administration > Device Access`
   - Ajouter l'IP du serveur pour API et SSH

3. **Configurer Syslog** :
   - `System Services > Log Settings`
   - Ajouter serveur Syslog : IP VIGILANCE X, port 514, UDP
   - Sélectionner les logs : Firewall, IPS, WAF, ATP, VPN

4. **Créer les groupes IP** :
   - `Hosts and Services > IP Host Group`
   - Créer `VIGILANCE_X_BLOCKLIST` (vide)
   - Créer `VIGILANCE_X_PERMANENT` (vide)

5. **Créer la règle de blocage** :
   - `Rules and Policies > Firewall Rules`
   - Nouvelle règle en position 1 (priorité haute)
   - Source : Groupe `VIGILANCE_X_BLOCKLIST` + `VIGILANCE_X_PERMANENT`
   - Action : Drop
   - Log : Activé

---

## Installation

### 1. Cloner le projet

```bash
cd /opt
git clone https://github.com/Kr1s57/vigilanceX.git
cd vigilanceX
```

### 2. Configurer l'environnement

```bash
cp .env.example .env
nano .env
```

Variables obligatoires :
```bash
# ClickHouse
CLICKHOUSE_PASSWORD=VotreMotDePasseSecurise

# Redis
REDIS_PASSWORD=VotreMotDePasseRedis

# Sophos XGS
SOPHOS_HOST=192.168.1.1
SOPHOS_USER=admin
SOPHOS_PASSWORD=VotreMotDePasseSophos

# JWT
JWT_SECRET=$(openssl rand -hex 32)
```

### 3. Générer les certificats SSL (production)

```bash
cd docker/nginx/ssl

# Auto-signé (dev/test)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout vigilance.key -out vigilance.crt \
  -subj "/CN=vigilance.local"

# Ou utilisez Let's Encrypt / vos propres certificats
```

### 4. Démarrer les services

```bash
cd docker

# Mode développement (sans nginx)
docker-compose up -d

# Mode production (avec nginx HTTPS)
docker-compose --profile production up -d
```

### 5. Vérifier le déploiement

```bash
# Status des containers
docker-compose ps

# Logs
docker-compose logs -f

# Health check
curl http://localhost:8080/health
```

---

## Configuration Avancée

### ClickHouse

Modifier `docker/clickhouse/config.xml` pour :
- Ajuster la mémoire max
- Configurer la rétention
- Activer la réplication (cluster)

### Vector

Modifier `docker/vector/vector.toml` pour :
- Ajouter des sources de logs
- Modifier les règles de parsing
- Ajuster les batches

### Scénarios Detect2Ban

Créer/modifier des scénarios dans `backend/scenarios/` :

```yaml
name: custom_scenario
description: Mon scénario personnalisé
enabled: true
priority: 10
window: 5

conditions:
  - type: log_type
    value: WAF
  - type: count
    operator: gte
    value: 10

actions:
  - type: ban
    params:
      reason: "Custom detection"
      use_progressive_duration: true
```

---

## Mise à jour

```bash
cd /opt/vigilanceX

# Sauvegarder la config
cp .env .env.backup

# Pull les changements
git pull

# Reconstruire les images
cd docker
docker-compose build

# Redémarrer
docker-compose down
docker-compose up -d
```

---

## Sauvegarde

### Données ClickHouse

```bash
# Backup
docker exec vigilance_clickhouse clickhouse-client \
  --query "BACKUP DATABASE vigilance_x TO Disk('backups', 'vigilance_x_$(date +%Y%m%d).zip')"

# Ou via volume
docker run --rm -v vigilance_clickhouse_data:/data \
  -v /backup:/backup alpine \
  tar czf /backup/clickhouse_$(date +%Y%m%d).tar.gz /data
```

### Configuration

```bash
tar czf vigilance_config_$(date +%Y%m%d).tar.gz \
  .env \
  docker/clickhouse/*.xml \
  docker/vector/vector.toml \
  backend/scenarios/
```

---

## Monitoring

### Métriques disponibles

- Vector : http://localhost:8686/metrics
- ClickHouse : http://localhost:8123/metrics
- Backend : http://localhost:8080/metrics (à implémenter)

### Logs

```bash
# Tous les logs
docker-compose logs -f

# Service spécifique
docker-compose logs -f backend
docker-compose logs -f vector
docker-compose logs -f clickhouse
```

### Alerting

Configurer Prometheus + Alertmanager pour :
- Disk space ClickHouse > 80%
- Erreurs Vector
- Latence API > 1s
- Connexion Sophos perdue

---

## Dépannage

### Vector ne reçoit pas de logs

1. Vérifier le port 514 UDP : `ss -ulnp | grep 514`
2. Vérifier les règles firewall : `ufw status`
3. Tester depuis Sophos : logs doivent apparaître dans Vector

### ClickHouse ne démarre pas

1. Vérifier les permissions : `chown -R 101:101 docker/clickhouse/`
2. Vérifier la syntaxe XML : `xmllint --noout docker/clickhouse/*.xml`
3. Consulter les logs : `docker logs vigilance_clickhouse`

### Backend ne se connecte pas à ClickHouse

1. Vérifier le réseau Docker : `docker network inspect vigilance_net`
2. Tester la connexion : `docker exec vigilance_backend wget -qO- http://clickhouse:8123/ping`

### API Sophos non accessible

1. Vérifier l'IP autorisée dans Sophos
2. Tester manuellement :
   ```bash
   curl -k "https://SOPHOS_IP:4444/webconsole/APIController?reqxml=<Request><Login><Username>admin</Username><Password>xxx</Password></Login></Request>"
   ```
