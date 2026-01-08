# VIGILANCE X - Live Active Response

> **Version 2.6.0** | Security Operations Center pour Sophos XGS

Solution de supervision de sécurité et de réponse active automatisée pour **Sophos XGS**.

## Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind + Shadcn UI |
| Base de données | ClickHouse (analytique temps réel) |
| Cache | Redis |
| Ingestion | Vector.dev (Syslog) |
| Déploiement | Docker Compose |

## Fonctionnalités

- **Dashboard temps réel** : Vue d'ensemble de la posture de sécurité
- **WAF Explorer** : Analyse détaillée du trafic Web protégé
- **Attacks Analyzer** : Focus sur l'IPS et les tentatives d'intrusion
- **Advanced Threat** : Suivi des alertes ATP et APT
- **VPN & Network** : Audit des accès distants
- **Active Bans** : Gestion des blocages en temps réel
- **Blocklist Ingester** : Synchronisation dynamique de 11 blocklists publiques
- **Soft Whitelist** : Système de whitelist graduée (hard/soft/monitor) *(v2.0)*
- **Geoblocking** : Blocage par pays/ASN avec GeoIP lookup *(v2.0)*
- **Freshness Score** : Scoring temporel avec décroissance exponentielle *(v2.0)*
- **Risk Scoring UI** : Interface de visualisation des scores de risque *(v2.3)*
- **System Protected IPs** : IPs système protégées (DNS, CDN, Monitoring) *(v2.5)*
- **Icon Style** : Personnalisation des icônes sidebar (Monochrome/Color) *(v2.5)*
- **Authentication** : Portail de connexion JWT avec RBAC (admin/audit) *(v2.6)*
- **User Management** : Gestion des utilisateurs et rôles (admin) *(v2.6)*
- **Reports** : Génération de rapports PDF/XML (journalier, hebdomadaire, mensuel)
- **Settings** : Configuration complète (thème, langue, notifications, intégrations)

### Intégrations Sophos XGS

| Méthode | Port | Usage |
|---------|------|-------|
| **Syslog** | UDP 514 / TCP 1514 | Réception des logs firewall en temps réel |
| **SSH** | 22 | Synchronisation des règles ModSecurity |
| **API XML** | 4444 | Gestion des bans (ajout/suppression IP blocklist) |

### Threat Intelligence (v1.6)

7 providers intégrés pour une analyse complète des menaces :

| Provider | Description |
|----------|-------------|
| AbuseIPDB | Réputation IP basée sur les reports |
| VirusTotal | Consensus multi-AV |
| AlienVault OTX | Contexte de menace et IOCs |
| GreyNoise | Réduction des faux positifs (scanners bénins) |
| IPSum | Agrégation de 30+ blocklists |
| CriminalIP | Détection C2/VPN/Proxy |
| Pulsedive | Corrélation IOC et acteurs de menace |

### Blocklist Feed Ingester

Ingestion automatique de blocklists publiques avec sync dynamique :

| Feed | Catégorie | ~IPs |
|------|-----------|------|
| Firehol Level 1 & 2 | mixed | 590k |
| Spamhaus DROP/EDROP | malware | 166k |
| Blocklist.de | attacker | 24k |
| CI Army | attacker | 15k |
| Binary Defense | attacker | 4k |
| Emerging Threats | attacker | 1.5k |
| Feodo Tracker | botnet | active C2 |
| DShield | scanner | top 20 |

**Total : ~800k IPs uniques**

### Soft Whitelist (v2.0)

Système de whitelist graduée remplaçant le binaire on/off :

| Type | Comportement |
|------|--------------|
| `hard` | Bypass total - jamais banni, score ignoré |
| `soft` | Score réduit (configurable), alerte uniquement |
| `monitor` | Logging uniquement, pas d'impact |

- Support TTL avec expiration automatique
- Modificateurs de score (0-100%)
- Tags pour catégorisation

### Geoblocking (v2.0)

Blocage géographique par pays et ASN :

| Type | Description |
|------|-------------|
| `country_block` | Bloquer toutes les IPs d'un pays |
| `country_watch` | Surveiller un pays (boost score) |
| `asn_block` | Bloquer un ASN spécifique |
| `asn_watch` | Surveiller un ASN (boost score) |

- GeoIP lookup via ip-api.com avec cache local
- Détection VPN/Proxy/Tor/Datacenter
- 10 pays haute-risque préconfigurés

### Freshness Score (v2.0)

Scoring temporel avec décroissance exponentielle :

| Âge des données | Multiplicateur |
|-----------------|----------------|
| < 3 jours | 1.25x (boost) |
| 7 jours | ~0.75x |
| 14 jours | ~0.37x |
| > 30 jours | 0.1x (minimal) |

### System Protected IPs (v2.5)

IPs système protégées automatiquement contre tout blocage :

| Catégorie | Fournisseurs |
|-----------|-------------|
| **DNS** | Cloudflare (1.1.1.1, 1.0.0.1), Google (8.8.8.8, 8.8.4.4), Quad9, OpenDNS |
| **Cloud** | AWS Health Checks, Google Cloud Health |
| **Monitoring** | UptimeRobot, Pingdom, StatusCake |
| **NTP** | NIST Time Servers |

Ces IPs sont visibles dans la page Whitelist avec toggle affichage.

### Icon Style (v2.5)

Personnalisation du style des icônes de navigation :

| Style | Description |
|-------|-------------|
| **Monochrome** | Icônes monochromes classiques |
| **Color** | Icônes colorées par catégorie |

### Authentication & RBAC (v2.6)

Système d'authentification complet avec contrôle d'accès basé sur les rôles.

#### Rôles

| Rôle | Description | Accès |
|------|-------------|-------|
| **admin** | Administrateur | Accès complet + Settings + Gestion utilisateurs |
| **audit** | Audit/Lecture seule | Visualisation uniquement, pas de ban/unban |

#### Restrictions Audit

| Page | Accès |
|------|-------|
| Dashboard, WAF, Attacks, Threats, VPN, Bans, Geoblocking, Whitelist, Scoring | ✅ Lecture |
| Reports, Settings, Users | ❌ Admin uniquement |
| Actions ban/unban | ❌ Désactivé |

#### Fonctionnalités

- **JWT Authentication** : Tokens avec validité 24h
- **Login Portal** : Interface de connexion sécurisée
- **User Management** : CRUD utilisateurs (admin)
- **Password Reset CLI** : Outil de récupération d'urgence
- **WebSocket Auth** : Connexions temps réel authentifiées

### Moteur Detect2Ban

- Scénarios YAML configurables
- Récidivisme automatique (4 bans = permanent)
- Synchronisation avec groupes Sophos XGS
- Combined Risk Assessment (Threat Intel + Blocklists)

## Démarrage Rapide

### Prérequis

- Docker & Docker Compose
- Accès API XML au Sophos XGS (port 4444)
- Clés API Threat Intel (optionnel)

### Installation

```bash
# Cloner le projet
cd /opt/vigilanceX

# Copier et configurer l'environnement
cp .env.example .env
# Éditer .env avec vos paramètres

# Démarrer les services
cd docker
docker-compose up -d

# Vérifier les logs
docker-compose logs -f
```

### Configuration Sophos XGS

1. Activer l'API XML : `System > Administration > API`
2. Autoriser l'IP du serveur VIGILANCE X
3. Créer le groupe IP : `VIGILANCE_X_BLOCKLIST`
4. Créer une règle Firewall DROP utilisant ce groupe

### Accès

- **Dashboard** : http://localhost:3000
- **API** : http://localhost:8080
- **ClickHouse** : http://localhost:8123
- **Vector** : http://localhost:8686

## Architecture

```
Sophos XGS
    │
    ├── Syslog (UDP 514) ──► Vector.dev ──► ClickHouse
    │
    └── API XML (4444) ◄──► Backend Go
                              │
                              ├── API REST
                              ├── WebSocket
                              └── Detect2Ban Engine
                                    │
                                    ▼
                              Frontend React
```

## Structure du Projet

```
vigilance-x/
├── docker/           # Docker Compose et configs
├── backend/          # API Go + Detect2Ban
│   ├── cmd/          # Points d'entrée
│   ├── internal/     # Code applicatif
│   └── scenarios/    # Scénarios YAML
├── frontend/         # React SPA
├── docs/             # Documentation
└── scripts/          # Scripts utilitaires
```

## Développement

### Backend

```bash
cd backend
make tidy        # Télécharger les dépendances
make build       # Compiler
make run-api     # Lancer l'API
make test        # Tests
```

### Frontend

```bash
cd frontend
npm install
npm run dev      # Dev server
npm run build    # Build production
```

## API Endpoints

### Core
| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/v1/events` | Liste des événements |
| `GET /api/v1/stats/overview` | Statistiques globales |

### Bans
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/bans` | Bans actifs |
| `POST /api/v1/bans` | Créer un ban |
| `DELETE /api/v1/bans/{ip}` | Supprimer un ban |

### Threats (v1.6)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/threats/check/{ip}` | Analyse threat intel complète |
| `GET /api/v1/threats/risk/{ip}` | Évaluation combinée threat+blocklist |
| `GET /api/v1/threats/should-ban/{ip}` | Recommandation de ban |
| `GET /api/v1/threats/providers` | Status des 7 providers |

### Blocklists
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/blocklists/stats` | Statistiques (total IPs, feeds) |
| `GET /api/v1/blocklists/feeds` | Status de tous les feeds |
| `POST /api/v1/blocklists/sync` | Synchronisation manuelle |
| `GET /api/v1/blocklists/check/{ip}` | Vérifier une IP |
| `GET /api/v1/blocklists/high-risk` | IPs multi-sources |

### Geoblocking (v2.0)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/geoblocking/rules` | Liste des règles |
| `POST /api/v1/geoblocking/rules` | Créer une règle |
| `PUT /api/v1/geoblocking/rules/{id}` | Modifier une règle |
| `DELETE /api/v1/geoblocking/rules/{id}` | Supprimer une règle |
| `GET /api/v1/geoblocking/check/{ip}` | Vérifier une IP |
| `GET /api/v1/geoblocking/lookup/{ip}` | Lookup géolocalisation |
| `GET /api/v1/geoblocking/countries/blocked` | Pays bloqués |
| `GET /api/v1/geoblocking/countries/high-risk` | Pays haute-risque |

### Whitelist (v2.0)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/whitelist` | Liste des entrées |
| `POST /api/v1/whitelist` | Ajouter (type, TTL, score_modifier) |
| `DELETE /api/v1/whitelist/{ip}` | Supprimer |

### Config (v2.5)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/config/system-whitelist` | IPs système protégées |
| `GET /api/v1/config/settings` | Paramètres application |
| `PUT /api/v1/config/settings` | Modifier paramètres |

### Authentication (v2.6)
| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/login` | Authentification (retourne JWT) |
| `POST /api/v1/auth/logout` | Déconnexion |
| `GET /api/v1/auth/me` | Infos utilisateur courant |
| `POST /api/v1/auth/change-password` | Changer son mot de passe |

### Users (v2.6 - Admin)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/users` | Liste des utilisateurs |
| `POST /api/v1/users` | Créer un utilisateur |
| `GET /api/v1/users/{id}` | Détails utilisateur |
| `PUT /api/v1/users/{id}` | Modifier utilisateur |
| `DELETE /api/v1/users/{id}` | Supprimer utilisateur |
| `POST /api/v1/users/{id}/reset-password` | Reset mot de passe |

## Configuration Authentification

### Variables d'environnement

```bash
# JWT
JWT_SECRET=your-secure-jwt-secret-min-32-chars
JWT_EXPIRY=24h

# Admin par défaut (premier démarrage)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!
```

### Utilisateur Admin par défaut

Au premier démarrage, si aucun utilisateur n'existe, un compte admin est créé automatiquement avec les credentials définis dans les variables d'environnement.

### Reset mot de passe (urgence)

En cas de perte du mot de passe admin :

```bash
docker exec vigilance_backend /app/reset-password <username> <new_password>
```

**Mot de passe par défaut pour les resets** : `Admin12345`

Exemple :
```bash
docker exec vigilance_backend /app/reset-password admin Admin12345
```

## Licence

MIT

## Auteur

Développé par l'équipe VIGILANCE X
