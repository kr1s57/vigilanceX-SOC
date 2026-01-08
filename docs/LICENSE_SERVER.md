# VIGILANCE X - License Server Documentation

## Vue d'ensemble

Le système de licence VIGILANCE X est composé de deux parties :
1. **vigilanceKey** - Serveur de licence centralisé
2. **Client License** - Module intégré dans chaque déploiement VIGILANCE X

Ce document décrit l'architecture, l'installation, la configuration et le fonctionnement du système complet.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        VIGILANCE X LICENSING SYSTEM                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌────────────────────┐         HTTPS          ┌────────────────────┐   │
│  │   VIGILANCE X      │◄──────────────────────►│   vigilanceKey     │   │
│  │   (Client)         │                        │   (License Server) │   │
│  │                    │                        │                    │   │
│  │  ┌──────────────┐  │   1. Activation        │  ┌──────────────┐  │   │
│  │  │ License      │  │   ─────────────►       │  │ License DB   │  │   │
│  │  │ Client       │  │                        │  │ (SQLite)     │  │   │
│  │  └──────────────┘  │   2. Heartbeat (12h)   │  └──────────────┘  │   │
│  │                    │   ─────────────►       │                    │   │
│  │  ┌──────────────┐  │                        │  ┌──────────────┐  │   │
│  │  │ License      │  │   3. OSINT Proxy       │  │ OSINT APIs   │  │   │
│  │  │ Store        │  │   ─────────────►       │  │ (Centralisé) │  │   │
│  │  │ (AES-256)    │  │                        │  └──────────────┘  │   │
│  │  └──────────────┘  │                        │                    │   │
│  │                    │                        │                    │   │
│  │  ┌──────────────┐  │   4. Validation        │  ┌──────────────┐  │   │
│  │  │ HardwareID   │  │   ◄─────────────       │  │ HardwareID   │  │   │
│  │  │ Generator    │  │                        │  │ Validator    │  │   │
│  │  └──────────────┘  │                        │  └──────────────┘  │   │
│  │                    │                        │                    │   │
│  └────────────────────┘                        └────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Composants du Système

### 1. HardwareID (Identification Unique)

Le HardwareID est un identifiant unique généré pour chaque VM/serveur, empêchant la copie de licences entre machines.

#### Sources d'identification (par ordre de priorité)

| Source | Chemin | Description |
|--------|--------|-------------|
| **Product UUID** | `/sys/class/dmi/id/product_uuid` | UUID VM (Hyper-V, VMware, KVM) |
| **Machine ID** | `/etc/machine-id` | ID systemd unique |
| **Container ID** | Docker inspect | ID conteneur Docker si applicable |

#### Génération du Hash

```go
// Algorithme de génération
HardwareID = SHA256(ProductUUID + MachineID)

// Exemple de sortie
// a1b2c3d4e5f6...789 (64 caractères hex)
```

#### Fichiers concernés

| Fichier | Description |
|---------|-------------|
| `backend/internal/license/hwid.go` | Génération et validation HardwareID |

---

### 2. License Store (Stockage Local)

La licence validée est stockée localement de manière chiffrée pour permettre le fonctionnement hors-ligne.

#### Emplacement

```
/app/data/license.json (dans le conteneur)
./data/license.json (volume monté sur l'hôte)
```

#### Structure du fichier (chiffré AES-256)

```json
{
  "license_key": "XXXX-XXXX-XXXX-XXXX",
  "customer_name": "Client ABC",
  "expires_at": "2027-01-01T00:00:00Z",
  "max_firewalls": 5,
  "features": ["osint", "reports", "geoblocking", "threat_intel"],
  "hardware_id": "a1b2c3d4...",
  "activated_at": "2026-01-08T00:00:00Z",
  "last_validated": "2026-01-08T12:00:00Z"
}
```

#### Chiffrement

| Paramètre | Valeur |
|-----------|--------|
| **Algorithme** | AES-256-GCM |
| **Clé** | Dérivée du HardwareID via PBKDF2 |
| **Salt** | Généré aléatoirement, stocké avec les données |

#### Fichiers concernés

| Fichier | Description |
|---------|-------------|
| `backend/internal/license/store.go` | Persistance et chiffrement |

---

### 3. License Client (Service Principal)

Le client gère toutes les opérations de licence : activation, validation, heartbeat.

#### États de licence

```
┌─────────────┐     Activation     ┌─────────────┐
│  UNLICENSED │ ─────────────────► │   ACTIVE    │
└─────────────┘                    └─────────────┘
                                         │
                    Heartbeat OK         │ Heartbeat Failed
                    ◄───────────         ▼
                                   ┌─────────────┐
                                   │ GRACE_MODE  │
                                   │   (72h)     │
                                   └─────────────┘
                                         │
                    Reconnexion OK       │ Grace expirée
                    ◄───────────         ▼
                                   ┌─────────────┐
                                   │  EXPIRED    │
                                   └─────────────┘
```

#### Méthodes principales

| Méthode | Description |
|---------|-------------|
| `Activate(licenseKey)` | Active une nouvelle licence |
| `Validate()` | Valide la licence avec le serveur |
| `Heartbeat()` | Envoi périodique de validation |
| `IsLicensed()` | Vérifie si la licence est valide |
| `GetStatus()` | Retourne le status détaillé |
| `HasFeature(feature)` | Vérifie accès à une fonctionnalité |

#### Fichiers concernés

| Fichier | Description |
|---------|-------------|
| `backend/internal/license/client.go` | Service client principal |

---

### 4. Heartbeat Service (Validation Périodique)

Service en arrière-plan qui maintient la validité de la licence.

#### Paramètres

| Paramètre | Défaut | Description |
|-----------|--------|-------------|
| **Intervalle** | 12h | Fréquence des heartbeats |
| **Grace Period** | 72h | Durée de fonctionnement si serveur injoignable |
| **Retry Backoff** | Exponentiel | 1min, 2min, 4min, 8min... max 1h |

#### Comportement

```
┌─────────────────────────────────────────────────────────────────┐
│                     HEARTBEAT FLOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Timer (12h)                                                     │
│      │                                                           │
│      ▼                                                           │
│  ┌──────────────────┐                                           │
│  │ Send Heartbeat   │                                           │
│  │ to License Server│                                           │
│  └────────┬─────────┘                                           │
│           │                                                      │
│     ┌─────┴─────┐                                               │
│     ▼           ▼                                               │
│  Success     Failure                                            │
│     │           │                                               │
│     ▼           ▼                                               │
│  Update     Enter Grace Mode                                    │
│  last_validated   │                                             │
│     │           ▼                                               │
│     │     Retry with backoff                                    │
│     │           │                                               │
│     │     ┌─────┴─────┐                                        │
│     │     ▼           ▼                                        │
│     │  Success     Grace Expired (72h)                         │
│     │     │           │                                        │
│     │     ▼           ▼                                        │
│     └──► Normal    KILL SWITCH                                 │
│          Operation  (API blocked)                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Fichiers concernés

| Fichier | Description |
|---------|-------------|
| `backend/internal/license/heartbeat.go` | Service heartbeat |

---

### 5. License Middleware (Kill Switch)

Middleware HTTP qui bloque l'accès API si la licence est invalide.

#### Routes protégées vs publiques

| Type | Routes | Description |
|------|--------|-------------|
| **Public** | `/health`, `/api/v1/auth/login`, `/api/v1/license/status`, `/api/v1/license/activate` | Toujours accessibles |
| **Protected** | Toutes les autres `/api/v1/*` | Nécessitent licence valide |

#### Réponse si licence invalide

```json
{
  "error": "license_required",
  "message": "Valid license required. Please activate your license.",
  "status": "expired",
  "activate_url": "/license"
}
```

#### Fichiers concernés

| Fichier | Description |
|---------|-------------|
| `backend/internal/adapter/controller/http/middleware/license.go` | Middleware kill switch |

---

### 6. OSINT Proxy (Protection des Clés API)

Proxy centralisé pour les requêtes de threat intelligence.

#### Avantages

| Aspect | Bénéfice |
|--------|----------|
| **Sécurité** | Clés API jamais exposées aux clients |
| **Gestion** | Mise à jour centralisée des clés |
| **Contrôle** | Rate limiting par licence |
| **Audit** | Logs centralisés des requêtes |
| **Économie** | Mutualisation des quotas API |

#### Flux de requête

```
Client VIGILANCE X          vigilanceKey Server           OSINT APIs
       │                           │                          │
       │  POST /osint/check        │                          │
       │  {ip, license, hwid}      │                          │
       │ ─────────────────────────►│                          │
       │                           │                          │
       │                           │  Validate License        │
       │                           │  Check Rate Limit        │
       │                           │                          │
       │                           │  GET /api/check?ip=X     │
       │                           │ ─────────────────────────►│
       │                           │                          │
       │                           │  Response                │
       │                           │◄─────────────────────────│
       │                           │                          │
       │  Aggregated Response      │                          │
       │◄─────────────────────────│                          │
       │                           │                          │
```

#### Configuration

```bash
# Activer le mode proxy (désactive les clés locales)
OSINT_PROXY_ENABLED=true
OSINT_PROXY_URL=https://vigilancexkey.cloudcomputing.lu
OSINT_PROXY_TIMEOUT=30s
OSINT_PROXY_RATE_LIMIT=60  # requêtes/minute
```

#### Fichiers concernés

| Fichier | Description |
|---------|-------------|
| `backend/internal/adapter/external/threatintel/proxy_client.go` | Client proxy OSINT |
| `backend/internal/adapter/external/threatintel/aggregator.go` | Intégration mode proxy |

---

## Installation du Client (VIGILANCE X)

### Prérequis

- Docker & Docker Compose
- Accès réseau au serveur de licence
- Clé de licence valide

### Configuration

#### 1. Variables d'environnement

Ajouter dans `.env` :

```bash
# ============================================
# LICENSE CONFIGURATION
# ============================================

# URL du serveur de licence
LICENSE_SERVER_URL=https://vigilancexkey.cloudcomputing.lu

# Clé de licence (optionnel - peut être saisie via UI)
LICENSE_KEY=XXXX-XXXX-XXXX-XXXX

# Activer le système de licence
LICENSE_ENABLED=true

# Intervalle de heartbeat (défaut: 12h)
LICENSE_HEARTBEAT_INTERVAL=12h

# Période de grâce si serveur injoignable (défaut: 72h)
LICENSE_GRACE_PERIOD=72h

# Chemin de stockage de la licence
LICENSE_STORE_PATH=/app/data/license.json

# ============================================
# OSINT PROXY (optionnel)
# ============================================

# Activer le proxy OSINT centralisé
OSINT_PROXY_ENABLED=false

# URL du proxy (même que LICENSE_SERVER_URL)
OSINT_PROXY_URL=https://vigilancexkey.cloudcomputing.lu

# Timeout des requêtes proxy
OSINT_PROXY_TIMEOUT=30s

# Rate limit (requêtes par minute)
OSINT_PROXY_RATE_LIMIT=60
```

#### 2. Docker Compose

Le volume pour la persistance de la licence :

```yaml
services:
  backend:
    volumes:
      - ./data:/app/data  # Persistance licence
```

#### 3. Première activation

1. Démarrer VIGILANCE X : `docker compose up -d`
2. Accéder à l'interface web
3. Vous serez redirigé vers `/license`
4. Saisir votre clé de licence : `XXXX-XXXX-XXXX-XXXX`
5. Cliquer sur "Activate License"

### Vérification

```bash
# Vérifier le status de licence via API
curl http://localhost:8080/api/v1/license/status

# Réponse attendue
{
  "licensed": true,
  "status": "active",
  "customer_name": "Client ABC",
  "expires_at": "2027-01-01T00:00:00Z",
  "days_remaining": 358,
  "features": ["osint", "reports", "geoblocking"]
}
```

---

## Installation du Serveur (vigilanceKey)

### Prérequis

- Serveur Linux (Ubuntu 22.04+ recommandé)
- Docker & Docker Compose
- Domaine avec certificat SSL (production)
- Port 443 (HTTPS) ou 80 (développement)

### Structure du projet

```
vigilanceKey/
├── docker-compose.yml
├── .env
├── Dockerfile
├── main.go
├── internal/
│   ├── config/
│   ├── handlers/
│   ├── middleware/
│   ├── models/
│   └── store/
├── data/
│   └── licenses.db (SQLite)
└── certs/
    ├── server.crt
    └── server.key
```

### Configuration serveur

#### .env

```bash
# Server
SERVER_PORT=8080
SERVER_HOST=0.0.0.0

# Database
DB_PATH=/app/data/licenses.db

# Security
API_SECRET=your-secure-api-secret-key
ADMIN_TOKEN=your-admin-token

# OSINT API Keys (pour le proxy)
ABUSEIPDB_API_KEY=your-key
VIRUSTOTAL_API_KEY=your-key
OTX_API_KEY=your-key
GREYNOISE_API_KEY=your-key
CRIMINALIP_API_KEY=your-key
PULSEDIVE_API_KEY=your-key

# Rate Limiting
RATE_LIMIT_PER_LICENSE=60  # requêtes/minute
RATE_LIMIT_BURST=10
```

#### docker-compose.yml

```yaml
version: '3.8'

services:
  vigilancekey:
    build: .
    container_name: vigilancekey
    restart: unless-stopped
    ports:
      - "443:8080"
    volumes:
      - ./data:/app/data
      - ./certs:/app/certs:ro
    environment:
      - SERVER_PORT=8080
      - DB_PATH=/app/data/licenses.db
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Démarrage

```bash
# Build et démarrage
docker compose up -d --build

# Vérifier les logs
docker compose logs -f vigilancekey

# Vérifier le health
curl https://vigilancexkey.cloudcomputing.lu/health
```

---

## API du Serveur de Licence

### Endpoints Publics

#### GET /health

Health check du serveur.

```bash
curl https://vigilancexkey.cloudcomputing.lu/health
```

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-01-08T12:00:00Z"
}
```

#### POST /api/v1/license/activate

Activer une licence pour un HardwareID.

```bash
curl -X POST https://vigilancexkey.cloudcomputing.lu/api/v1/license/activate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "hardware_id": "a1b2c3d4e5f6..."
  }'
```

**Réponse succès (200):**
```json
{
  "success": true,
  "license": {
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "customer_name": "Client ABC",
    "expires_at": "2027-01-01T00:00:00Z",
    "max_firewalls": 5,
    "features": ["osint", "reports", "geoblocking"],
    "is_valid": true,
    "status": "active"
  }
}
```

**Réponse erreur (400/401):**
```json
{
  "success": false,
  "error": "invalid_license",
  "message": "License key not found or expired"
}
```

#### POST /api/v1/license/validate

Valider une licence (heartbeat).

```bash
curl -X POST https://vigilancexkey.cloudcomputing.lu/api/v1/license/validate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "hardware_id": "a1b2c3d4e5f6..."
  }'
```

**Réponse (200):**
```json
{
  "valid": true,
  "status": "active",
  "expires_at": "2027-01-01T00:00:00Z",
  "features": ["osint", "reports", "geoblocking"]
}
```

### Endpoints Admin (requiert ADMIN_TOKEN)

#### GET /api/v1/admin/licenses

Lister toutes les licences.

```bash
curl https://vigilancexkey.cloudcomputing.lu/api/v1/admin/licenses \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### POST /api/v1/admin/licenses

Créer une nouvelle licence.

```bash
curl -X POST https://vigilancexkey.cloudcomputing.lu/api/v1/admin/licenses \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_name": "New Client",
    "max_firewalls": 5,
    "expires_at": "2027-12-31T23:59:59Z",
    "features": ["osint", "reports", "geoblocking", "threat_intel"]
  }'
```

**Réponse (201):**
```json
{
  "license_key": "ABCD-EFGH-IJKL-MNOP",
  "customer_name": "New Client",
  "expires_at": "2027-12-31T23:59:59Z",
  "max_firewalls": 5,
  "features": ["osint", "reports", "geoblocking", "threat_intel"],
  "created_at": "2026-01-08T12:00:00Z"
}
```

#### DELETE /api/v1/admin/licenses/{license_key}

Révoquer une licence.

```bash
curl -X DELETE https://vigilancexkey.cloudcomputing.lu/api/v1/admin/licenses/ABCD-EFGH-IJKL-MNOP \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### Endpoint OSINT Proxy

#### POST /api/v1/osint/check

Vérifier une IP via le proxy OSINT.

```bash
curl -X POST https://vigilancexkey.cloudcomputing.lu/api/v1/osint/check \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "hardware_id": "a1b2c3d4e5f6..."
  }'
```

**Réponse (200):**
```json
{
  "ip": "1.2.3.4",
  "aggregated_score": 75,
  "threat_level": "high",
  "confidence": 0.85,
  "sources": [
    {"provider": "AbuseIPDB", "score": 80, "available": true},
    {"provider": "VirusTotal", "score": 70, "available": true},
    {"provider": "GreyNoise", "score": 0, "available": true, "classification": "benign"}
  ],
  "country": "RU",
  "is_tor": false,
  "is_vpn": true,
  "tags": ["vpn", "scanner"],
  "cached": false,
  "checked_at": "2026-01-08T12:00:00Z"
}
```

---

## Gestion des Licences

### Format des clés

```
XXXX-XXXX-XXXX-XXXX
│    │    │    │
│    │    │    └── Checksum (4 chars)
│    │    └─────── Random (4 chars)
│    └──────────── Random (4 chars)
└───────────────── Prefix client (4 chars)
```

### Features disponibles

| Feature | Description |
|---------|-------------|
| `osint` | Accès aux threat intelligence providers |
| `reports` | Génération de rapports PDF/XML |
| `geoblocking` | Règles de blocage géographique |
| `threat_intel` | Dashboard Advanced Threat |
| `vpn_detection` | Détection VPN/Proxy |
| `api_access` | Accès API externe |

### Cycle de vie d'une licence

```
┌──────────────┐
│   CREATED    │  Licence générée, non activée
└──────┬───────┘
       │ Activation (premier hardware_id)
       ▼
┌──────────────┐
│   ACTIVE     │  Licence en cours de validité
└──────┬───────┘
       │
       ├──────────────────────────────────┐
       │                                  │
       │ Expiration date atteinte         │ Révocation admin
       ▼                                  ▼
┌──────────────┐                   ┌──────────────┐
│   EXPIRED    │                   │   REVOKED    │
└──────────────┘                   └──────────────┘
```

---

## Troubleshooting

### Problèmes courants

#### "License activation failed"

| Cause | Solution |
|-------|----------|
| Clé invalide | Vérifier le format XXXX-XXXX-XXXX-XXXX |
| Clé expirée | Contacter le support pour renouvellement |
| Serveur injoignable | Vérifier la connectivité réseau |
| HardwareID différent | La licence est liée à une autre VM |

#### "Grace mode" persistant

```bash
# Vérifier la connectivité au serveur
curl -I https://vigilancexkey.cloudcomputing.lu/health

# Vérifier les logs backend
docker compose logs backend | grep -i license

# Forcer une revalidation
curl -X POST http://localhost:8080/api/v1/license/validate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### "Kill switch activated"

1. Vérifier que le serveur de licence est accessible
2. Vérifier que la licence n'est pas expirée
3. Ré-activer la licence si nécessaire via `/license`

### Logs utiles

```bash
# Logs licence côté client
docker compose logs backend | grep -E "(license|License|HWID|heartbeat)"

# Logs serveur de licence
docker compose logs vigilancekey | grep -E "(activate|validate|revoke)"
```

### Récupération après panne

Si le fichier de licence est corrompu :

```bash
# Supprimer le fichier de licence
rm ./data/license.json

# Redémarrer le backend
docker compose restart backend

# Ré-activer via l'interface /license
```

---

## Sécurité

### Recommandations

| Aspect | Recommandation |
|--------|----------------|
| **Transport** | TLS 1.3 obligatoire en production |
| **Stockage** | Volume Docker avec permissions 600 |
| **Secrets** | Variables d'environnement, pas de hardcoding |
| **Monitoring** | Alertes sur échecs heartbeat |
| **Backup** | Sauvegarder `/app/data/licenses.db` |

### Audit

Le serveur de licence log tous les événements :

```
2026-01-08T12:00:00Z INFO  license activated customer="Client ABC" hwid="a1b2..."
2026-01-08T12:00:00Z INFO  heartbeat received license="XXXX-..." status=active
2026-01-08T12:00:00Z WARN  heartbeat failed license="YYYY-..." error="network timeout"
2026-01-08T12:00:00Z ERROR license revoked license="ZZZZ-..." reason="admin action"
```

---

## Support

Pour toute question ou problème :

- **Email**: support@vigilancex.io
- **Documentation**: https://docs.vigilancex.io
- **Issues**: https://github.com/vigilancex/vigilancex/issues

---

*Documentation v2.9.0 - Dernière mise à jour : Janvier 2026*
