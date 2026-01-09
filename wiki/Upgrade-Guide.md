# Guide de Mise à Jour VIGILANCE X

Ce guide détaille les étapes de mise à jour entre les versions majeures de VIGILANCE X.

---

## Table des Versions

| Version | Date | Type | Description |
|---------|------|------|-------------|
| 3.1.0 | 2026-01-09 | Major | XGS Parser Engine |
| 3.0.1 | 2026-01-09 | Patch | UI improvements |
| 3.0.0 | 2026-01-08 | Major | VX3 Secure Firewall Binding |
| 2.9.x | 2026-01 | Minor | Licensing, OSINT Proxy |
| 2.6.0 | 2026-01 | Major | Authentication & RBAC |

---

## Mise à Jour Standard

Pour les mises à jour mineures (patch), utilisez la commande standard :

```bash
./vigilance.sh update
```

Cette commande :
1. Crée un backup automatique
2. Pull les dernières images Docker
3. Redémarre les services
4. Nettoie les anciennes images

---

## Upgrade vers v3.1.0 (XGS Parser Engine)

### Nouveautés v3.1.0

- **XGS Parser Engine** : Moteur de parsing natif pour logs Sophos XGS
- **104 champs** extraits dans 17 groupes
- **74 règles de détection** dans 10 catégories
- **23 techniques MITRE ATT&CK** mappées
- **27 nouveaux champs** dans ClickHouse

### Prérequis

- Version actuelle : >= 3.0.0
- Espace disque : 500MB minimum disponible
- Accès admin au serveur

### Étapes de Mise à Jour

#### 1. Backup (Obligatoire)

```bash
./vigilance.sh backup
```

#### 2. Pull des Nouvelles Images

```bash
./vigilance.sh update
```

#### 3. Migration ClickHouse

Exécuter la migration pour ajouter les 27 nouveaux champs :

```bash
# Se connecter au conteneur ClickHouse
docker exec -it vigilance_clickhouse clickhouse-client

# Exécuter les commandes de migration
```

```sql
-- Migration 006: Extended XGS Fields
USE vigilance_x;

-- Device Identification
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_serial_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_model String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_name String DEFAULT '';

-- Log Metadata
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS con_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_component LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_subtype LowCardinality(String) DEFAULT '';

-- TLS/SSL Analysis
ALTER TABLE events ADD COLUMN IF NOT EXISTS tls_version LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS cipher_suite String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS sni String DEFAULT '';

-- Threat Intelligence
ALTER TABLE events ADD COLUMN IF NOT EXISTS threatfeed String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS malware String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS classification LowCardinality(String) DEFAULT '';

-- VPN Extended
ALTER TABLE events ADD COLUMN IF NOT EXISTS connection_name String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS remote_network String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS local_network String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS local_ip String DEFAULT '';

-- Endpoint Health
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_uuid String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_name String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_ip String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS ep_health LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS hb_status LowCardinality(String) DEFAULT '';

-- Email/Anti-Spam
ALTER TABLE events ADD COLUMN IF NOT EXISTS sender String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS recipient String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS subject String DEFAULT '';

-- Network Zones
ALTER TABLE events ADD COLUMN IF NOT EXISTS src_zone LowCardinality(String) DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_zone LowCardinality(String) DEFAULT '';

-- Indexes
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_device_serial device_serial_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_tls_version tls_version TYPE set(20) GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_threatfeed threatfeed TYPE bloom_filter GRANULARITY 4;
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_ep_health ep_health TYPE set(10) GRANULARITY 4;
```

#### 4. Redémarrage des Services

```bash
./vigilance.sh restart
```

#### 5. Vérification

```bash
# Vérifier le status
./vigilance.sh status

# Vérifier la version dans l'interface
# Settings > About > Version: 3.1.0

# Tester l'API Parser
curl http://localhost:8080/api/v1/parser/stats
```

### Réponse API Attendue

```json
{
  "loaded": true,
  "version": "1.0",
  "total_fields": 104,
  "total_rules": 74,
  "total_groups": 17,
  "mitre_techniques": 23
}
```

---

## Upgrade vers v3.0.0 (VX3 Binding)

### Nouveautés v3.0.0

- **VX3 Secure Firewall Binding** : Liaison VM + Serial Firewall
- **Grace Period** étendu à 7 jours
- Migration automatique VX2 → VX3

### Étapes de Mise à Jour

```bash
# 1. Backup
./vigilance.sh backup

# 2. Update
./vigilance.sh update

# 3. Vérifier le binding
curl http://localhost:8080/api/v1/license/status
```

La migration VX2 → VX3 est automatique.

---

## Upgrade vers v2.6.0 (Authentication)

### Nouveautés v2.6.0

- Authentification JWT
- RBAC (admin/audit)
- Gestion utilisateurs

### Étapes Spécifiques

Après la mise à jour, définir les variables d'environnement :

```bash
# Dans deploy/.env
JWT_SECRET=votre-secret-32-caracteres-minimum
JWT_EXPIRY=24h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VotreMotDePasse!
```

Puis redémarrer :

```bash
./vigilance.sh restart
```

---

## Rollback en Cas de Problème

### Rollback Rapide

```bash
# 1. Arrêter les services
./vigilance.sh stop

# 2. Modifier la version dans .env
nano deploy/.env
# VIGILANCE_VERSION=3.0.1

# 3. Redémarrer avec l'ancienne version
./vigilance.sh start
```

### Restauration Complète

```bash
# 1. Arrêter les services
./vigilance.sh stop

# 2. Restaurer le backup
./vigilance.sh restore

# 3. Sélectionner le backup avant upgrade

# 4. Redémarrer
./vigilance.sh start
```

---

## Vérification Post-Upgrade

### Checklist

| Élément | Commande/Action | Résultat Attendu |
|---------|-----------------|------------------|
| Services | `./vigilance.sh status` | Tous UP |
| API | `curl localhost:8080/health` | `{"status":"ok"}` |
| Dashboard | https://IP | Page login |
| Version | Settings > About | Version correcte |
| Logs | `./vigilance.sh logs` | Pas d'erreurs |

### Tests Fonctionnels

1. **Login** : Se connecter avec admin
2. **Dashboard** : Vérifier l'affichage des events
3. **WAF Explorer** : Vérifier le parsing des logs
4. **Bans** : Créer/supprimer un ban test
5. **Parser** (v3.1+) : Tester `/api/v1/parser/test`

---

## FAQ Upgrade

### Q: La migration ClickHouse échoue

Vérifier l'espace disque :
```bash
docker system df
```

### Q: Les nouveaux champs n'apparaissent pas

Relancer Vector pour recharger la config :
```bash
docker compose restart vector
```

### Q: Erreur de licence après upgrade

Forcer une synchronisation :
```bash
curl -X POST http://localhost:8080/api/v1/license/validate \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Support

En cas de problème lors d'une mise à jour :
- **Email** : support@it-secure.lu
- **Logs** : `./vigilance.sh logs` (joindre au ticket)
- **Version** : Indiquer la version source et cible
