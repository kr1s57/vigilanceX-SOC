# VIGILANCE X - Documentation Technique

> **Version**: 3.58.108 | **Dernière mise à jour**: 2026-01-28
> **Type**: Multi-part (Backend Go + Frontend React)
> **Architecture**: Client-Server avec Docker Compose

---

## Vue d'Ensemble

**VIGILANCE X** est une plateforme SOC (Security Operations Center) temps réel conçue pour:
- Collecter et analyser les logs Sophos XGS via Syslog
- Enrichir les événements avec 11 providers Threat Intelligence
- Détecter et bannir automatiquement les IPs malveillantes (Detect2Ban)
- Synchroniser les bans avec le firewall Sophos XGS via API XML
- Visualiser les attaques en temps réel sur une carte mondiale

---

## Référence Rapide

| Attribut | Valeur |
|----------|--------|
| **Backend** | Go 1.22, Chi Router, Clean Architecture |
| **Frontend** | React 19, TypeScript 5.7, Vite 6, Tailwind CSS 4 |
| **Database** | ClickHouse 25.12 (analytique temps réel) |
| **Cache** | Redis 7.4 (sessions, TI cache) |
| **Ingestion** | Vector 0.52 (Syslog UDP/TCP) |
| **Déploiement** | Docker Compose |

---

## Documentation Générée

### Architecture & Structure

- [Vue d'ensemble du projet](./project-overview.md)
- [Architecture Backend](./architecture-backend.md)
- [Architecture Frontend](./architecture-frontend.md)
- [Arborescence Source](./source-tree-analysis.md)
- [Architecture d'Intégration](./integration-architecture.md)

### Références Techniques

- [Contrats API](./api-contracts.md) - 100+ endpoints REST
- [Modèles de Données](./data-models.md) - Entités Go + Schéma ClickHouse
- [Inventaire Composants UI](./component-inventory.md)
- [Gestion d'État](./state-management.md)

### Guides

- [Guide de Développement](./development-guide.md)
- [Guide de Déploiement](./deployment-guide.md)

---

## Documentation Existante

### Racine du Projet

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Documentation principale |
| [TECHNICAL_REFERENCE.md](../TECHNICAL_REFERENCE.md) | Référence technique complète |
| [CHANGELOG.md](../CHANGELOG.md) | Historique des versions |
| [CLAUDE.md](../CLAUDE.md) | Fichier mémoire Claude Code |

### Wiki Utilisateur (`client-dist/wiki/`)

| Document | Description |
|----------|-------------|
| [Home](../client-dist/wiki/Home.md) | Page d'accueil wiki |
| [Architecture](../client-dist/wiki/Architecture.md) | Architecture système |
| [Installation Guide](../client-dist/wiki/Installation-Guide.md) | Guide d'installation |
| [Configuration](../client-dist/wiki/Configuration.md) | Configuration |
| [Administration](../client-dist/wiki/Administration.md) | Administration |
| [Security Hardening](../client-dist/wiki/Security-Hardening.md) | Durcissement sécurité |
| [Risk Scoring](../client-dist/wiki/Risk-Scoring.md) | Système de scoring |
| [Troubleshooting](../client-dist/wiki/Troubleshooting.md) | Dépannage |

### Base de Connaissances

| Document | Description |
|----------|-------------|
| [BUGFIX-KB.md](./BUGFIX-KB.md) | Base de connaissances bugs corrigés |

---

## Démarrage Rapide

### Prérequis

- Docker & Docker Compose
- Go 1.22+ (développement backend)
- Node.js 20+ (développement frontend)
- Sophos XGS Firewall (intégration)

### Développement Local

```bash
# Backend
cd backend && go build ./cmd/api && go test ./...

# Frontend
cd frontend && npm install && npm run dev

# Docker (stack complète)
cd docker && docker compose up -d
```

### URLs

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | Interface web |
| API | http://localhost:8080 | REST API |
| ClickHouse | http://localhost:8123 | Base de données |
| Syslog | UDP/514, TCP/1514 | Ingestion logs |

---

## Stack Technologique

### Backend (Go 1.22)

| Catégorie | Technologie | Version |
|-----------|-------------|---------|
| HTTP Router | Chi | v5.0.12 |
| Database | ClickHouse | v25.12 |
| Cache | Redis | 7.4 |
| Auth | JWT | v5.2.1 |
| WebSocket | Gorilla | v1.5.1 |
| Config | Viper | v1.18.2 |

### Frontend (React 19)

| Catégorie | Technologie | Version |
|-----------|-------------|---------|
| Build | Vite | 6.0.7 |
| Language | TypeScript | 5.7.2 |
| Routing | React Router | 7.1.1 |
| State | Zustand | 5.0.2 |
| Styling | Tailwind CSS | 4.0.0 |
| UI | Radix UI | 2.x |
| Charts | Recharts | 2.15.0 |
| Maps | Leaflet | 1.9.4 |

---

## Fonctionnalités Principales

### En Production

- ✅ Dashboard temps réel avec WebSocket
- ✅ WAF Explorer (analyse ModSecurity)
- ✅ Attacks Analyzer (événements IPS/WAF/ATP)
- ✅ Advanced Threat (11 providers TI avec cascade)
- ✅ Detect2Ban v2 (tiers progressifs, GeoZone)
- ✅ Active Bans (gestion des bannissements)
- ✅ Soft Whitelist (3 types: hard, soft, monitor)
- ✅ Geoblocking (blocage par pays/ASN)
- ✅ Attack Map (carte mondiale interactive)
- ✅ Track IP (recherche forensique)
- ✅ Neural-Sync (CrowdSec Blocklist via VigilanceKey)
- ✅ Vigimail Checker (détection fuites emails)
- ✅ Reports (PDF/XML avec envoi email)
- ✅ User Management (RBAC admin/audit)
- ✅ Système de licence VX3

---

*Documentation générée automatiquement par le workflow document-project - 2026-01-28*
