# vigilanceKey - Serveur de Licence v1.2

## Vue d'ensemble

**vigilanceKey** est le serveur centralisé de gestion des licences pour VIGILANCE X. Il gère :
- L'activation et la validation des licences
- Le heartbeat périodique des clients (toutes les 12h)
- Le proxy OSINT centralisé (protection des clés API)
- Le portail d'administration avec authentification JWT
- La gestion des utilisateurs (admin, operator, viewer)
- La gestion complète du cycle de vie des licences (revoke, reactivate, renew, extend)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           vigilanceKey Server                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   License API   │    │   OSINT Proxy   │    │   Admin API     │         │
│  │                 │    │                 │    │                 │         │
│  │  /activate      │    │  /osint/check   │    │  /admin/licenses│         │
│  │  /validate      │    │                 │    │  CRUD operations│         │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘         │
│           │                      │                      │                   │
│           └──────────────────────┼──────────────────────┘                   │
│                                  │                                          │
│                          ┌───────┴───────┐                                  │
│                          │   SQLite DB   │                                  │
│                          │ licenses.db   │                                  │
│                          └───────────────┘                                  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                    OSINT API Providers                           │       │
│  │  AbuseIPDB │ VirusTotal │ AlienVault │ GreyNoise │ CriminalIP   │       │
│  └─────────────────────────────────────────────────────────────────┘       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS
                                    ▼
                    ┌───────────────────────────────┐
                    │   Clients VIGILANCE X         │
                    │   (multiples déploiements)    │
                    └───────────────────────────────┘
```

---

## Prérequis

| Composant | Version | Notes |
|-----------|---------|-------|
| **OS** | Ubuntu 22.04+ / Debian 12+ | Serveur Linux |
| **Docker** | 24.0+ | Avec Docker Compose |
| **RAM** | 1 GB minimum | 2 GB recommandé |
| **Disk** | 10 GB | Pour logs et DB |
| **Network** | Port 80/443 | HTTPS recommandé en production |
| **Domaine** | Optionnel | Pour certificat SSL |

---

## Installation

### 1. Préparer le serveur

```bash
# Mettre à jour le système
apt update && apt upgrade -y

# Installer Docker (si pas déjà installé)
curl -fsSL https://get.docker.com | sh
systemctl enable docker
systemctl start docker

# Installer Docker Compose
apt install docker-compose-plugin -y

# Créer le répertoire
mkdir -p /opt/vigilanceKey
cd /opt/vigilanceKey
```

### 2. Créer la structure du projet

```bash
mkdir -p data certs
```

Structure finale :
```
/opt/vigilanceKey/
├── docker-compose.yml
├── .env
├── data/
│   └── licenses.db (créé automatiquement)
└── certs/
    ├── server.crt (optionnel - pour HTTPS)
    └── server.key (optionnel - pour HTTPS)
```

### 3. Créer le fichier docker-compose.yml

```yaml
version: '3.8'

services:
  vigilancekey:
    image: ghcr.io/kr1s57/vigilancekey:latest
    # Ou build local :
    # build: .
    container_name: vigilancekey
    restart: unless-stopped
    ports:
      - "80:8080"      # HTTP (développement)
      # - "443:8080"   # HTTPS (production avec reverse proxy)
    volumes:
      - ./data:/app/data
      - ./certs:/app/certs:ro
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### 4. Créer le fichier .env

```bash
cat > .env << 'EOF'
# ============================================
# vigilanceKey - Configuration
# ============================================

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Database
DB_PATH=/app/data/licenses.db

# ============================================
# Security
# ============================================
# JWT Secret pour les tokens (générer avec: openssl rand -hex 32)
JWT_SECRET=CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32

# Admin API Key pour les opérations CRUD (générer avec: openssl rand -hex 32)
ADMIN_API_KEY=CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32

# ============================================
# OSINT API Keys (pour le proxy centralisé)
# ============================================
# AbuseIPDB - https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=

# VirusTotal - https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=

# AlienVault OTX - https://otx.alienvault.com/api
ALIENVAULT_API_KEY=

# GreyNoise - https://www.greynoise.io/viz/signup
GREYNOISE_API_KEY=

# Criminal IP - https://www.criminalip.io/
CRIMINALIP_API_KEY=

# Pulsedive - https://pulsedive.com/api/
PULSEDIVE_API_KEY=

# ============================================
# Rate Limiting
# ============================================
RATE_LIMIT_PER_LICENSE=60
RATE_LIMIT_BURST=10

# ============================================
# CORS (origines autorisées)
# ============================================
CORS_ORIGINS=https://vigilancex.example.com,http://localhost:3000
EOF
```

### 5. Générer les secrets

```bash
# Générer JWT_SECRET
echo "JWT_SECRET=$(openssl rand -hex 32)"

# Générer ADMIN_API_KEY
echo "ADMIN_API_KEY=$(openssl rand -hex 32)"
```

Copier les valeurs générées dans le fichier `.env`.

### 6. Démarrer le serveur

```bash
# Démarrer
docker compose up -d

# Vérifier les logs
docker compose logs -f

# Vérifier le health
curl http://localhost/health
```

**Réponse attendue :**
```json
{"status":"healthy","service":"vigilancekey"}
```

---

## Configuration HTTPS (Production)

### Option 1 : Reverse Proxy (Nginx)

```bash
apt install nginx certbot python3-certbot-nginx -y
```

Configuration Nginx `/etc/nginx/sites-available/vigilancekey` :

```nginx
server {
    listen 80;
    server_name vigilancexkey.cloudcomputing.lu;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vigilancexkey.cloudcomputing.lu;

    ssl_certificate /etc/letsencrypt/live/vigilancexkey.cloudcomputing.lu/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vigilancexkey.cloudcomputing.lu/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Activer le site
ln -s /etc/nginx/sites-available/vigilancekey /etc/nginx/sites-enabled/

# Obtenir le certificat SSL
certbot --nginx -d vigilancexkey.cloudcomputing.lu

# Redémarrer Nginx
systemctl restart nginx
```

### Option 2 : Traefik (Docker)

Modifier `docker-compose.yml` :

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/letsencrypt

  vigilancekey:
    image: ghcr.io/kr1s57/vigilancekey:latest
    container_name: vigilancekey
    restart: unless-stopped
    volumes:
      - ./data:/app/data
    env_file:
      - .env
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.vigilancekey.rule=Host(`vigilancexkey.cloudcomputing.lu`)"
      - "traefik.http.routers.vigilancekey.entrypoints=websecure"
      - "traefik.http.routers.vigilancekey.tls.certresolver=letsencrypt"
```

---

## API Reference

### Endpoints Publics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/license/activate` | Activer une licence |
| POST | `/api/v1/license/validate` | Valider/Heartbeat |

### Endpoints Admin (Authorization: Bearer JWT_TOKEN)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/licenses` | Lister toutes les licences |
| POST | `/api/v1/admin/licenses` | Créer une licence |
| GET | `/api/v1/admin/licenses/{id}` | Détails d'une licence |
| PUT | `/api/v1/admin/licenses/{id}` | Modifier une licence |
| DELETE | `/api/v1/admin/licenses/{id}` | Supprimer une licence |
| POST | `/api/v1/admin/licenses/{id}/revoke` | Révoquer une licence |
| POST | `/api/v1/admin/licenses/{id}/reactivate` | Réactiver une licence |
| POST | `/api/v1/admin/licenses/{id}/renew` | Renouveler une licence (365 jours) |
| POST | `/api/v1/admin/licenses/{id}/extend` | Prolonger une licence (durée personnalisée) |

### Endpoints Authentification

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Connexion utilisateur |
| POST | `/api/v1/auth/logout` | Déconnexion |
| GET | `/api/v1/auth/me` | Profil utilisateur actuel |
| POST | `/api/v1/admin/users` | Créer un utilisateur (admin only) |
| GET | `/api/v1/admin/users` | Lister les utilisateurs (admin only) |
| DELETE | `/api/v1/admin/users/{id}` | Supprimer un utilisateur (admin only) |

### Endpoint OSINT Proxy

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/osint/check` | Vérifier une IP (requiert licence valide) |

---

## Gestion des Licences

### Créer une licence (API)

```bash
curl -X POST "http://localhost/api/v1/admin/licenses" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_name": "Client ABC",
    "customer_email": "admin@client.com",
    "max_firewalls": 5,
    "expires_at": "2027-12-31T23:59:59Z",
    "features": ["osint", "reports", "geoblocking", "threat_intel"],
    "notes": "Production license"
  }'
```

**Réponse :**
```json
{
  "id": "uuid-here",
  "license_key": "ABCD-EFGH-IJKL-MNOP",
  "customer_name": "Client ABC",
  "expires_at": "2027-12-31T23:59:59Z",
  "features": ["osint", "reports", "geoblocking", "threat_intel"],
  "status": "active",
  "created_at": "2026-01-08T12:00:00Z"
}
```

### Lister les licences

```bash
curl "http://localhost/api/v1/admin/licenses" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY"
```

### Modifier une licence

```bash
curl -X PUT "http://localhost/api/v1/admin/licenses/{license_id}" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "expires_at": "2028-12-31T23:59:59Z",
    "max_firewalls": 10
  }'
```

### Supprimer une licence

```bash
curl -X DELETE "http://localhost/api/v1/admin/licenses/{license_id}" \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY"
```

---

## Dashboard Web

Le serveur vigilanceKey inclut un dashboard web pour la gestion visuelle des licences.

### Accès

- **URL** : `http://localhost/` ou `https://vigilancexkey.cloudcomputing.lu/`
- **Authentification** : Via JWT (login/password)
- **Rôles** : admin, operator, viewer

### Fonctionnalités

| Feature | Description |
|---------|-------------|
| **Liste des licences** | Vue tableau avec statut, expiration, jours restants, client |
| **Créer licence** | Formulaire de création avec tous les champs |
| **Modifier licence** | Édition des paramètres (expiration, features, etc.) |
| **Révoquer licence** | Désactiver immédiatement une licence |
| **Réactiver licence** | Réactiver une licence révoquée |
| **Renouveler licence** | Prolonger de 365 jours |
| **Prolonger licence** | Étendre avec durée personnalisée (30-730 jours) |
| **Supprimer licence** | Suppression définitive avec confirmation |
| **Statistiques** | Nombre de licences actives, expirées, révoquées |
| **Gestion utilisateurs** | Créer/supprimer des utilisateurs (admin only) |

### Rôles Utilisateurs

| Rôle | Permissions |
|------|-------------|
| **admin** | Toutes les opérations, gestion utilisateurs |
| **operator** | CRUD licences, pas de gestion utilisateurs |
| **viewer** | Lecture seule des licences |

---

## Gestion du Cycle de Vie des Licences

### États possibles

| Status | Description |
|--------|-------------|
| `active` | Licence valide et fonctionnelle |
| `expired` | Licence expirée (date dépassée) |
| `revoked` | Licence révoquée par l'administrateur |
| `suspended` | Licence temporairement suspendue |

### Révoquer une licence

```bash
curl -X POST "http://localhost/api/v1/admin/licenses/{id}/revoke" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Effet côté client** : Le client VIGILANCE X perdra l'accès aux fonctionnalités lors du prochain heartbeat ou sync manuel.

### Réactiver une licence

```bash
curl -X POST "http://localhost/api/v1/admin/licenses/{id}/reactivate" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Renouveler une licence (365 jours)

```bash
curl -X POST "http://localhost/api/v1/admin/licenses/{id}/renew" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Prolonger une licence (durée personnalisée)

```bash
curl -X POST "http://localhost/api/v1/admin/licenses/{id}/extend" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"days": 180}'
```

---

## Synchronisation Client (VIGILANCE X)

### Heartbeat Automatique

Le client VIGILANCE X effectue un heartbeat automatique toutes les **12 heures** pour :
- Valider que la licence est toujours active
- Mettre à jour les jours restants
- Vérifier si la licence a été révoquée

### Sync Manuel

Le client peut forcer une synchronisation via le bouton "Sync License Status" dans la page de licence :

```typescript
// Appel API côté client
POST /api/v1/license/force-validate

// Réponse
{
  "success": true,
  "license": {
    "licensed": true,
    "status": "active",
    "customer_name": "Client ABC",
    "expires_at": "2027-01-08T00:00:00Z",
    "days_remaining": 365,
    "features": ["osint", "reports"]
  }
}
```

### Grace Mode

Si le serveur de licence est injoignable, le client entre en "Grace Mode" :
- Durée : 72 heures maximum
- Fonctionnalités : Accès complet maintenu
- Indicateur : Badge "Grace Mode" dans la sidebar

Après expiration du grace mode, l'accès est bloqué jusqu'à reconnexion avec le serveur.

---

## Base de Données

### Emplacement

```
/opt/vigilanceKey/data/licenses.db (SQLite)
```

### Schéma

```sql
CREATE TABLE licenses (
    id TEXT PRIMARY KEY,
    license_key TEXT UNIQUE NOT NULL,
    customer_name TEXT NOT NULL,
    customer_email TEXT,
    max_firewalls INTEGER DEFAULT 1,
    features TEXT,  -- JSON array
    status TEXT DEFAULT 'active',
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    hardware_ids TEXT  -- JSON array of activated hardware IDs
);

CREATE TABLE activations (
    id TEXT PRIMARY KEY,
    license_id TEXT NOT NULL,
    hardware_id TEXT NOT NULL,
    activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat DATETIME,
    ip_address TEXT,
    FOREIGN KEY (license_id) REFERENCES licenses(id)
);
```

### Backup

```bash
# Backup manuel
cp /opt/vigilanceKey/data/licenses.db /opt/vigilanceKey/data/licenses.db.bak

# Backup automatique (cron)
echo "0 2 * * * cp /opt/vigilanceKey/data/licenses.db /opt/vigilanceKey/data/licenses.db.\$(date +\%Y\%m\%d)" | crontab -
```

---

## Monitoring

### Logs

```bash
# Logs en temps réel
docker compose logs -f vigilancekey

# Filtrer par type
docker compose logs vigilancekey | grep -E "(ERROR|WARN)"
docker compose logs vigilancekey | grep "activate"
docker compose logs vigilancekey | grep "validate"
```

### Métriques

```bash
# Health check
curl http://localhost/health

# Statistiques (si implémenté)
curl http://localhost/api/v1/admin/stats \
  -H "Authorization: Bearer YOUR_ADMIN_API_KEY"
```

### Alertes recommandées

| Métrique | Seuil | Action |
|----------|-------|--------|
| Health check failed | 3 consécutifs | Restart container |
| Disk usage > 80% | - | Nettoyer logs |
| License expiring | 30 jours | Notifier client |

---

## Maintenance

### Mise à jour

```bash
cd /opt/vigilanceKey

# Pull nouvelle image
docker compose pull

# Redémarrer
docker compose up -d

# Vérifier
docker compose logs -f
```

### Nettoyage

```bash
# Nettoyer les images Docker non utilisées
docker system prune -f

# Nettoyer les logs anciens
find /opt/vigilanceKey/data -name "*.log" -mtime +30 -delete
```

### Restauration

```bash
# Arrêter le service
docker compose down

# Restaurer la DB
cp /opt/vigilanceKey/data/licenses.db.bak /opt/vigilanceKey/data/licenses.db

# Redémarrer
docker compose up -d
```

---

## Sécurité

### Checklist

- [ ] Changer les secrets par défaut (JWT_SECRET, ADMIN_API_KEY)
- [ ] Activer HTTPS en production
- [ ] Restreindre l'accès réseau (firewall)
- [ ] Configurer les backups automatiques
- [ ] Monitorer les logs pour activités suspectes

### Firewall (UFW)

```bash
# Autoriser SSH
ufw allow 22/tcp

# Autoriser HTTPS
ufw allow 443/tcp

# Activer
ufw enable
```

### Fail2Ban (optionnel)

```bash
apt install fail2ban -y

# Configuration pour vigilanceKey
cat > /etc/fail2ban/jail.d/vigilancekey.conf << 'EOF'
[vigilancekey]
enabled = true
port = 80,443
filter = vigilancekey
logpath = /var/log/nginx/access.log
maxretry = 5
bantime = 3600
EOF
```

---

## Troubleshooting

### Le serveur ne démarre pas

```bash
# Vérifier les logs
docker compose logs vigilancekey

# Vérifier les permissions
ls -la /opt/vigilanceKey/data/
chown -R 1000:1000 /opt/vigilanceKey/data/
```

### Erreur "database locked"

```bash
# Redémarrer le container
docker compose restart vigilancekey
```

### Erreur d'authentification admin

```bash
# Vérifier ADMIN_API_KEY dans .env
grep ADMIN_API_KEY .env

# Tester
curl -H "Authorization: Bearer YOUR_KEY" http://localhost/api/v1/admin/licenses
```

### Certificat SSL expiré

```bash
# Renouveler avec Certbot
certbot renew

# Redémarrer Nginx
systemctl restart nginx
```

---

## Variables d'Environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `SERVER_HOST` | Adresse d'écoute | `0.0.0.0` |
| `SERVER_PORT` | Port d'écoute | `8080` |
| `DB_PATH` | Chemin base de données | `/app/data/licenses.db` |
| `JWT_SECRET` | Secret pour tokens JWT | **Requis** |
| `ADMIN_API_KEY` | Clé API admin | **Requis** |
| `ABUSEIPDB_API_KEY` | Clé AbuseIPDB | Optionnel |
| `VIRUSTOTAL_API_KEY` | Clé VirusTotal | Optionnel |
| `ALIENVAULT_API_KEY` | Clé AlienVault OTX | Optionnel |
| `GREYNOISE_API_KEY` | Clé GreyNoise | Optionnel |
| `CRIMINALIP_API_KEY` | Clé CriminalIP | Optionnel |
| `PULSEDIVE_API_KEY` | Clé Pulsedive | Optionnel |
| `RATE_LIMIT_PER_LICENSE` | Requêtes/minute par licence | `60` |
| `RATE_LIMIT_BURST` | Burst autorisé | `10` |
| `CORS_ORIGINS` | Origines CORS autorisées | `*` |

---

## Support

- **Documentation** : https://docs.vigilancex.io
- **Issues** : https://github.com/kr1s57/vigilanceX/issues
- **Email** : support@vigilancex.io

---

*Documentation vigilanceKey v1.2 - Janvier 2026*
