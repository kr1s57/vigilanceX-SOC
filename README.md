# VIGILANCE X - Live Active Response

> **Version 1.5.0** | Security Operations Center pour Sophos XGS

Solution de supervision de sécurité et de réponse active automatisée pour **Sophos XGS**.

## Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go (Chi router, Clean Architecture) |
| Frontend | React + TypeScript + Tailwind + Shadcn UI |
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
- **Reports** : Génération de rapports PDF/XML (journalier, hebdomadaire, mensuel)
- **Settings** : Configuration complète (thème, langue, notifications, intégrations)

### Intégrations Sophos XGS

| Méthode | Port | Usage |
|---------|------|-------|
| **Syslog** | UDP 514 / TCP 1514 | Réception des logs firewall en temps réel |
| **SSH** | 22 | Synchronisation des règles ModSecurity |
| **API XML** | 4444 | Gestion des bans (ajout/suppression IP blocklist) |

### Moteur Detect2Ban

- Scénarios YAML configurables
- Récidivisme automatique (4 bans = permanent)
- Synchronisation avec groupes Sophos XGS
- Threat Intelligence intégrée (AbuseIPDB, VirusTotal, AlienVault)

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

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/v1/events` | Liste des événements |
| `GET /api/v1/stats/overview` | Statistiques globales |
| `GET /api/v1/bans` | Bans actifs |
| `POST /api/v1/bans` | Créer un ban |
| `GET /api/v1/threats/score/{ip}` | Score de menace |

## Licence

MIT

## Auteur

Développé par l'équipe VIGILANCE X
