# Procédure de Mise à Jour VIGILANCE X (Serveur Dev/Production)

> **Document interne** - Procédure complète pour les montées de version

---

## Table des Matières

1. [Prérequis](#prérequis)
2. [Procédure Standard (Update)](#procédure-standard-update)
3. [Procédure Majeure (Upgrade)](#procédure-majeure-upgrade)
4. [Migrations Base de Données](#migrations-base-de-données)
5. [Rollback en Cas de Problème](#rollback-en-cas-de-problème)
6. [Checklist Post-Upgrade](#checklist-post-upgrade)
7. [Scripts Utilitaires](#scripts-utilitaires)

---

## Prérequis

### Accès Requis
- SSH root sur le serveur
- Accès au repository Git
- Accès à l'interface web (pour vérification)

### Vérifications Préalables

```bash
# Vérifier l'espace disque (minimum 2GB libres)
df -h /opt

# Vérifier la version actuelle
cat /opt/vigilanceX/CLAUDE.md | head -5

# Vérifier le statut des services
cd /opt/vigilanceX/docker
docker compose ps

# Vérifier qu'il n'y a pas d'erreurs critiques
docker compose logs --tail=50 backend | grep -i error
```

---

## Procédure Standard (Update)

**Durée estimée : 5-10 minutes**
**Downtime : ~30 secondes**

### Étape 1 : Backup

```bash
# Créer le dossier backups
mkdir -p /opt/vigilanceX/backups

# Backup ClickHouse
docker exec vigilance_clickhouse tar czf /tmp/ch_backup.tar.gz -C /var/lib/clickhouse .
docker cp vigilance_clickhouse:/tmp/ch_backup.tar.gz /opt/vigilanceX/backups/clickhouse_$(date +%Y%m%d_%H%M%S).tar.gz

# Backup Redis
docker exec vigilance_redis redis-cli -a 'V1g1l@nc3X_R3d1s!' BGSAVE
sleep 2
docker cp vigilance_redis:/data/dump.rdb /opt/vigilanceX/backups/redis_$(date +%Y%m%d_%H%M%S).rdb

# Vérifier les backups
ls -lh /opt/vigilanceX/backups/
```

### Étape 2 : Pull du Code

```bash
cd /opt/vigilanceX
git fetch origin
git status

# Pull les changements
git pull origin main

# Vérifier la nouvelle version
cat CLAUDE.md | head -5
```

### Étape 3 : Vérifier les Migrations

```bash
# Lister les migrations disponibles
ls -la /opt/vigilanceX/docker/clickhouse/migrations/

# Vérifier si nouvelles migrations à appliquer
# (comparer avec les migrations déjà appliquées)
```

### Étape 4 : Appliquer les Migrations (si nécessaire)

```bash
# Exemple pour migration 006
docker exec -i vigilance_clickhouse clickhouse-client < /opt/vigilanceX/docker/clickhouse/migrations/006_extended_xgs_fields.sql

# Vérifier que la migration s'est bien passée
docker exec vigilance_clickhouse clickhouse-client --query "DESCRIBE vigilance_x.events" | grep -E "device_serial|tls_version"
```

### Étape 5 : Rebuild et Redémarrage

```bash
cd /opt/vigilanceX/docker

# Rebuild tous les conteneurs modifiés
docker compose build --no-cache frontend backend

# Redémarrer les services
docker compose down
docker compose up -d

# Vérifier le statut
docker compose ps
```

### Étape 6 : Vérification

```bash
# Vérifier les logs
docker compose logs --tail=20 backend
docker compose logs --tail=20 frontend

# Tester l'API
curl -s http://localhost:8080/health | jq

# Vérifier la version dans l'interface
# Ouvrir https://IP et aller dans Settings > About
```

---

## Procédure Majeure (Upgrade)

**Durée estimée : 15-30 minutes**
**Downtime : 2-5 minutes**

Pour les montées de version majeures (ex: 3.0.x → 3.1.0), suivre ces étapes additionnelles.

### Étape 1 : Backup Complet

```bash
# Backup standard (voir ci-dessus)
# PLUS backup du code actuel
cd /opt
tar czf vigilanceX_backup_$(date +%Y%m%d_%H%M%S).tar.gz vigilanceX/
```

### Étape 2 : Arrêt des Services

```bash
cd /opt/vigilanceX/docker
docker compose down
```

### Étape 3 : Pull et Vérification des Changements

```bash
cd /opt/vigilanceX
git fetch origin
git log --oneline HEAD..origin/main  # Voir les nouveaux commits

git pull origin main
```

### Étape 4 : Vérifier le CHANGELOG

```bash
# Lire les changements de la nouvelle version
cat CHANGELOG.md | head -100
```

### Étape 5 : Appliquer les Migrations

```bash
# Démarrer uniquement ClickHouse
cd /opt/vigilanceX/docker
docker compose up -d clickhouse
sleep 10

# Appliquer toutes les nouvelles migrations
for migration in /opt/vigilanceX/docker/clickhouse/migrations/*.sql; do
    echo "Applying: $migration"
    docker exec -i vigilance_clickhouse clickhouse-client < "$migration"
done
```

### Étape 6 : Mettre à Jour Vector.toml

```bash
# Le fichier est monté en volume, donc automatiquement à jour
# Mais vérifier la syntaxe
docker run --rm -v /opt/vigilanceX/docker/vector/vector.toml:/etc/vector/vector.toml:ro timberio/vector:latest validate
```

### Étape 7 : Rebuild Complet

```bash
cd /opt/vigilanceX/docker

# Nettoyer les anciens builds
docker compose down --rmi local

# Rebuild tous les conteneurs
docker compose build --no-cache

# Démarrer
docker compose up -d

# Suivre les logs
docker compose logs -f
```

### Étape 8 : Tests de Validation

```bash
# API Health
curl -s http://localhost:8080/health

# API Parser (v3.1+)
curl -s http://localhost:8080/api/v1/parser/stats

# Test d'authentification
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"VotrePassword"}'
```

---

## Migrations Base de Données

### Liste des Migrations

| Version | Migration | Description |
|---------|-----------|-------------|
| 1.0 | init-db.sql | Schéma initial |
| 1.5 | 002_add_modsec_messages.sql | Champs ModSec |
| 1.6 | 003_add_v16_threat_providers.sql | Providers TI |
| 1.6.5 | 004_add_blocklist_tables.sql | Tables blocklists |
| 2.0 | 005_soft_whitelist_v2.sql | Soft whitelist |
| 3.1 | 006_extended_xgs_fields.sql | 27 champs XGS |

### Appliquer une Migration Spécifique

```bash
docker exec -i vigilance_clickhouse clickhouse-client < /opt/vigilanceX/docker/clickhouse/migrations/006_extended_xgs_fields.sql
```

### Vérifier les Colonnes Ajoutées

```bash
docker exec vigilance_clickhouse clickhouse-client --query "DESCRIBE vigilance_x.events FORMAT Pretty"
```

---

## Rollback en Cas de Problème

### Rollback Rapide (Code uniquement)

```bash
cd /opt/vigilanceX

# Voir les commits récents
git log --oneline -10

# Revenir au commit précédent
git reset --hard HEAD~1

# Rebuild et restart
cd docker
docker compose build --no-cache
docker compose up -d
```

### Rollback Complet (avec données)

```bash
# 1. Arrêter les services
cd /opt/vigilanceX/docker
docker compose down

# 2. Restaurer le code
cd /opt
rm -rf vigilanceX
tar xzf vigilanceX_backup_YYYYMMDD_HHMMSS.tar.gz

# 3. Restaurer ClickHouse
docker volume rm vigilance_clickhouse_data
docker volume create vigilance_clickhouse_data
docker run --rm -v vigilance_clickhouse_data:/data -v /opt/vigilanceX/backups:/backup alpine tar xzf /backup/clickhouse_YYYYMMDD_HHMMSS.tar.gz -C /data

# 4. Restaurer Redis
docker cp /opt/vigilanceX/backups/redis_YYYYMMDD_HHMMSS.rdb vigilance_redis:/data/dump.rdb

# 5. Redémarrer
cd /opt/vigilanceX/docker
docker compose up -d
```

---

## Checklist Post-Upgrade

### Vérifications Obligatoires

| Élément | Commande | Résultat Attendu |
|---------|----------|------------------|
| Services UP | `docker compose ps` | Tous "Up (healthy)" |
| API Health | `curl localhost:8080/health` | `{"status":"ok"}` |
| Frontend | Ouvrir https://IP | Page login |
| Version Settings | Settings > About | Version correcte |
| Logs Backend | `docker compose logs backend` | Pas d'erreurs |
| Logs Vector | `docker compose logs vector` | Logs Sophos reçus |

### Tests Fonctionnels

1. **Login** : Se connecter avec admin
2. **Dashboard** : Vérifier l'affichage des events récents
3. **WAF Explorer** : Vérifier le parsing ModSec
4. **Bans** : Créer/supprimer un ban test
5. **Geoblocking** : Vérifier les règles
6. **Parser** (v3.1+) : GET /api/v1/parser/stats

---

## Scripts Utilitaires

### Script de Backup Automatique

Créer `/opt/vigilanceX/scripts/backup.sh` :

```bash
#!/bin/bash
# VIGILANCE X - Backup Script

BACKUP_DIR="/opt/vigilanceX/backups"
DATE=$(date +%Y%m%d_%H%M%S)
REDIS_PASS="V1g1l@nc3X_R3d1s!"

mkdir -p $BACKUP_DIR

echo "[$(date)] Starting backup..."

# ClickHouse
docker exec vigilance_clickhouse tar czf /tmp/ch_backup.tar.gz -C /var/lib/clickhouse .
docker cp vigilance_clickhouse:/tmp/ch_backup.tar.gz $BACKUP_DIR/clickhouse_$DATE.tar.gz
docker exec vigilance_clickhouse rm /tmp/ch_backup.tar.gz

# Redis
docker exec vigilance_redis redis-cli -a "$REDIS_PASS" BGSAVE 2>/dev/null
sleep 2
docker cp vigilance_redis:/data/dump.rdb $BACKUP_DIR/redis_$DATE.rdb

# Cleanup old backups (keep last 7)
cd $BACKUP_DIR
ls -t clickhouse_*.tar.gz | tail -n +8 | xargs -r rm
ls -t redis_*.rdb | tail -n +8 | xargs -r rm

echo "[$(date)] Backup completed: $BACKUP_DIR"
ls -lh $BACKUP_DIR
```

```bash
chmod +x /opt/vigilanceX/scripts/backup.sh
```

### Script d'Update Rapide

Créer `/opt/vigilanceX/scripts/update.sh` :

```bash
#!/bin/bash
# VIGILANCE X - Quick Update Script

set -e

echo "=== VIGILANCE X Update ==="
echo ""

# Backup
echo "[1/5] Creating backup..."
/opt/vigilanceX/scripts/backup.sh

# Pull
echo "[2/5] Pulling latest code..."
cd /opt/vigilanceX
git pull origin main

# Show version
echo "[3/5] New version:"
cat CLAUDE.md | head -5

# Rebuild
echo "[4/5] Rebuilding containers..."
cd /opt/vigilanceX/docker
docker compose build --no-cache frontend backend

# Restart
echo "[5/5] Restarting services..."
docker compose up -d

echo ""
echo "=== Update Complete ==="
docker compose ps
```

```bash
chmod +x /opt/vigilanceX/scripts/update.sh
```

### Cron pour Backup Quotidien

```bash
# Ajouter au crontab
crontab -e

# Backup tous les jours à 3h
0 3 * * * /opt/vigilanceX/scripts/backup.sh >> /var/log/vigilancex-backup.log 2>&1
```

---

## Historique des Versions

| Version | Date | Type | Migration Requise |
|---------|------|------|-------------------|
| 3.1.0 | 2026-01-09 | Major | 006_extended_xgs_fields.sql |
| 3.0.1 | 2026-01-09 | Patch | Non |
| 3.0.0 | 2026-01-08 | Major | Non (auto-migration VX3) |
| 2.9.7 | 2026-01-08 | Patch | Non |
| 2.9.5 | 2026-01-08 | Minor | Non |
| 2.6.0 | 2026-01-07 | Major | users table (init-db.sql) |
| 2.0.0 | 2026-01-07 | Major | 005_soft_whitelist_v2.sql |

---

## Support

En cas de problème :
- Logs : `docker compose logs`
- Email : support@it-secure.lu
- Documentation : /opt/vigilanceX/docs/

---

*Document mis à jour : 2026-01-09 - v3.1.0*
