# VIGILANCE X - Claude Code Memory File

> **Version**: 3.57.124 | **Derniere mise a jour**: 2026-01-20

Ce fichier sert de memoire persistante pour Claude Code. Il contient les **regles, conventions et workflows** du projet VIGILANCE X.

**Pour les details techniques complets, consulter:**
- `TECHNICAL_REFERENCE.md` - API reference, DB schemas, entities, variables env
- `CHANGELOG.md` - Historique detaille des versions
- `docs/BUGFIX-KB.md` - Knowledge base bugs corriges

---

## REGLES CRITIQUES - LIRE EN PREMIER

### PROTECTION REPO PUBLIC

**AVANT CHAQUE PUSH VERS `public` (vigilanceX-SOC) ou `forgejo-soc`:**

Le repo PUBLIC ne doit contenir **QUE**:
- `README.md` - Documentation client uniquement
- Code source (backend/, frontend/, docker/)

**FICHIERS INTERDITS SUR REPO PUBLIC:**

| Fichier/Dossier | Raison |
|-----------------|--------|
| `CLAUDE.md` | Process internes, architecture |
| `TECHNICAL_REFERENCE.md` | Reference technique complete |
| `CHANGELOG.md` | Details implementation |
| `docs/` | Documentation interne |
| `BUGFIXSESSION/`, `FEATURESPROMPT/` | Sessions de debug/features |
| `.github/` | Workflows CI/CD, secrets |
| `.claude/` | Configuration Claude Code (skills, settings) |
| `backups/` | Donnees sensibles |

**INFORMATIONS SENSIBLES A NE JAMAIS REVELER:**
- Seuils de detection WAF (nombre d'events)
- Durees de ban (4h, 24h, 7j, permanent)
- Logique de decision D2B
- Scores TI et leurs seuils
- Noms des groupes XGS internes

**WORKFLOW GITGO:**
1. `origin` (private) - OK avec tous les fichiers
2. `public` - UNIQUEMENT README.md + code source
3. `forgejo` (private) - OK avec tous les fichiers
4. `forgejo-soc` (public) - UNIQUEMENT README.md + code source

---

## Vue d'Ensemble

**VIGILANCE X** est une plateforme SOC temps reel:
- Collecte les logs Sophos XGS via Syslog
- Analyse les menaces avec 11 providers TI
- Bannit automatiquement les IPs via API XML Sophos
- Interface web React moderne

### Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind + Shadcn UI |
| Database | ClickHouse 24.1 |
| Cache | Redis 7 |
| Ingestion | Vector.dev (Syslog) |
| Deploy | Docker Compose |

### Structure Projet

```
/opt/vigilanceX/
├── backend/
│   ├── cmd/api/          # API server
│   ├── cmd/detect2ban/   # D2B engine
│   └── internal/         # Clean Architecture
│       ├── entity/       # Data models
│       ├── usecase/      # Business logic
│       └── adapter/      # External adapters
├── frontend/src/
│   ├── pages/           # React pages
│   ├── components/      # UI components
│   ├── contexts/        # Auth, License, Settings
│   ├── stores/          # Zustand stores
│   └── lib/api.ts       # API client
├── docker/              # Docker Compose configs
└── docs/                # Documentation interne
```

---

## Statut des Fonctionnalites

### En Production
- Dashboard temps reel, WAF Explorer, Attacks Analyzer
- Advanced Threat (11 providers TI)
- VPN & Network, Soft Whitelist, Geoblocking
- Authentication & User Management (RBAC)
- Systeme de licence VX3
- XGS Parser (104 champs, 74 regles, 23 techniques MITRE)
- Log Retention (cleanup configurable)
- Attack Map (carte mondiale interactive)
- Track IP (recherche forensique)
- Vigimail Checker (verification emails/DNS)

### Features Avancees
- **Detect2Ban v1**: Auto-ban WAF (5 events/5min), brute-force (10/10min)
- **Detect2Ban v2**: Tiers progressifs, GeoZone, Pending Approval
- **Neural-Sync**: CrowdSec Blocklist via VigilanceKey ProxyAPI
- **Storage SMB**: Archivage externe (wired, non teste)

---

## Conventions de Code

### Backend Go

```go
// Clean Architecture
internal/
├── entity/      # Modeles (pas de logique)
├── usecase/     # Services metier
└── adapter/     # Implementations concretes

// Nommage
- Fichiers: snake_case.go
- Interfaces/Structs: PascalCase
- Variables: camelCase
```

### Frontend TypeScript

```typescript
// Structure
src/
├── pages/       # PascalCase.tsx
├── components/  # Composants reutilisables
├── contexts/    # React Context
├── stores/      # Zustand (camelCase.ts)
├── lib/         # Utilitaires
└── types/       # TypeScript types

// State Management
- Context API: Global (auth, settings, license)
- Zustand: Domain state (bans, events)
- useState: Local component state
```

### Base de Donnees ClickHouse

```sql
-- Conventions
- Tables: snake_case (vigilance_x.events)
- Colonnes: snake_case
- Engine: MergeTree ou ReplacingMergeTree
```

---

## Regles de Versioning (X.YY.Z)

**Format**: `X.YY.Z` (exemple: `3.55.112`)

| Digit | Nom | Description |
|-------|-----|-------------|
| **X** | MAJOR | Sur demande explicite uniquement |
| **YY** | FEATURE | Nouvelles features (+1) |
| **Z** | BUGFIX | Corrections (commence a 100) |

**Exemples:**
- Bug fix: `3.55.111` -> `3.55.112`
- Nouvelle feature: `3.55.112` -> `3.56.100`
- Major (rare): `3.59.115` -> `4.0.100`

**A chaque release, mettre a jour:**
- `CHANGELOG.md` - Ajouter entree pour la nouvelle version
- `CLAUDE.md` header - Version + date de mise a jour
- Tags git sur les 4 repos

**FICHIERS VERSION FRONTEND (CRITIQUE - tous a mettre a jour):**

| Fichier | Ligne | Variable/Texte |
|---------|-------|----------------|
| `frontend/src/pages/Dashboard.tsx` | ~24 | `INSTALLED_VERSION = 'X.YY.Z'` |
| `frontend/src/pages/Settings.tsx` | ~2381 | `VIGILANCE X vX.YY.Z` |
| `frontend/src/pages/Login.tsx` | ~192 | `VIGILANCE X vX.YY.Z` |
| `frontend/src/pages/LicenseActivation.tsx` | ~450 | `VIGILANCE X vX.YY.Z` |

> **IMPORTANT**: Le badge version du Dashboard utilise `INSTALLED_VERSION` dans Dashboard.tsx.
> Ne pas oublier de mettre a jour TOUS ces fichiers sinon le badge affichera une mauvaise version!

---

## Workflow Git (gitgo)

Quand l'utilisateur dit "gitgo":

**Etape 0 - Version (OBLIGATOIRE):**
1. Chercher TOUS les fichiers avec la version: `grep -rn "X.YY.Z" frontend/src/pages/`
2. Incrementer selon regles X.YY.Z dans TOUS les fichiers listes ci-dessus
3. Mettre a jour header CLAUDE.md (version + date)

**Etape 1 - Commit et Push Private:**
```bash
git status
git add .
git commit -m "feat(vX.YY.Z): description"
git push origin main
```

**Etape 2 - Repo Public (vigilanceX-SOC):**
```bash
git checkout -b public-sync
git rm --cached CLAUDE.md TECHNICAL_REFERENCE.md CHANGELOG.md
rm -rf docs/ BUGFIXSESSION/ FEATURESPROMPT/
git commit -m "chore: Remove internal docs"
git push public public-sync:main --force
git checkout main && git branch -D public-sync
```

**Etape 3 - Forgejo:**
```bash
git push forgejo main
# Repeter etape 2 pour forgejo-soc
```

**Etape 4 - GitHub Releases:**
```bash
git tag vX.YY.Z && git push origin vX.YY.Z && git push public vX.YY.Z
gh release create vX.YY.Z --repo kr1s57/vigilanceX --title "VIGILANCE X vX.YY.Z"
gh release create vX.YY.Z --repo kr1s57/vigilanceX-SOC --title "VIGILANCE X vX.YY.Z"
```

---

## Architecture de Deploiement

### Modele de Securite

| Couche | Protection |
|--------|------------|
| Reseau | Interne uniquement, pas d'Internet |
| Acces | VPN obligatoire |
| Auth | JWT + RBAC (admin/audit) |

Cette architecture elimine les vecteurs d'attaque externes (brute-force, DDoS, injection).

### Environnements

| Env | Machine | Usage |
|-----|---------|-------|
| DEV | 10.25.72.28 | Code source, builds |
| VPS-TEST | OVH vps-b3a1bf23 | Simulation client |
| vigilanceKey | 10.56.126.126 | Serveur licences |

### Deploiement VPS (GHCR)

```bash
# Sur DEV - Build et push
docker build -t ghcr.io/kr1s57/vigilancex-api:VERSION -f backend/Dockerfile backend/
docker push ghcr.io/kr1s57/vigilancex-api:VERSION

# Sur VPS - Pull et restart
docker compose pull && docker compose up -d --force-recreate
```

---

## Detect2Ban Engine

### Scenarios

| Scenario | Seuil | Fenetre | Action |
|----------|-------|---------|--------|
| `waf_attacks` | 5 events | 5 min | Ban auto |
| `brute_force` | 10 auth fail | 10 min | Ban + TI check |

### Tiers de Ban (D2B v2)

| Tier | Duree | Groupe XGS |
|------|-------|------------|
| 0 | 4h | grp_VGX-BannedIP |
| 1 | 24h | grp_VGX-BannedIP |
| 2 | 7j | grp_VGX-BannedIP |
| 3+ | Permanent | grp_VGX-BannedPerm |

### GeoZone Classification

| Zone | Comportement |
|------|--------------|
| **Authorized** | TI check avant ban, pending si score < seuil |
| **Hostile** | Ban immediat (1 event WAF) |
| **Neutral** | Ban auto apres seuil standard |

---

## Threat Intelligence

### Tiers de Cascade

| Tier | Providers | Activation |
|------|-----------|------------|
| **1** (Free) | IPsum, OTX, ThreatFox, URLhaus, Shodan | Toujours |
| **2** | AbuseIPDB, GreyNoise, CrowdSec CTI | Score > 30 |
| **3** | VirusTotal, CriminalIP, Pulsedive | Score > 60 |

---

## Systeme de Licence VX3

### Binding Hardware

```
Hardware ID = SHA256("VX3:" + machine_id + ":" + firewall_serial)
```

### Statuts

| Status | Description |
|--------|-------------|
| `FDEPLOY` | Fresh deploy, attente XGS (15j) |
| `TRIAL` | XGS connecte, trial valide (15j) |
| `ASKED` | Demande Pro soumise |
| `ACTIVE` | Licence Pro active |

Grace Period: 7 jours si serveur licence injoignable.

---

## CrowdSec Neural-Sync

Architecture ProxyAPI: VGX clients recuperent les blocklists via VigilanceKey (pas directement CrowdSec).

```
CrowdSec API -> VigilanceKey (cache 2h) -> VGX Clients (license auth)
                                                    |
                                              Sync to XGS
                                        (grp_VGX-CrowdSBlockL)
```

---

## Commandes Frequentes

```bash
# Backend
cd backend && go build ./cmd/api
go test ./...

# Frontend
cd frontend && npm run build
npm run dev

# Docker
cd docker
docker compose up -d
docker compose logs -f api
docker compose restart api

# Reset password
docker exec vigilance-api /app/reset-password -u admin -p newpass
```

---

## Hooks de Securite

### Commandes Bloquees

```bash
rm -rf /
DROP DATABASE
git push --force origin main
shutdown, reboot
```

### Fichiers Proteges

```
.env, .env.local, .env.production
credentials.json, secrets.json
*.pem, *.key, id_rsa
```

### Auto-Formatage

| Extension | Formateur |
|-----------|-----------|
| `.go` | gofmt -w |
| `.ts`, `.tsx` | prettier --write |

---

## Backup Git - Forgejo

### Remotes

```bash
origin      -> GitHub (kr1s57/vigilanceX) - private
public      -> GitHub (kr1s57/vigilanceX-SOC) - public
forgejo     -> Forgejo (itsadm/vigilanceX) - private
forgejo-soc -> Forgejo (itsadm/vigilanceX-SOC) - public
```

### Script

```bash
/opt/vigilanceX/scripts/backup-to-forgejo.sh --all
```

---

## Regles de Developpement

1. **Ne jamais modifier** les fichiers .env production
2. **Toujours tester** avec `go build` et `npm run build`
3. **Respecter** Clean Architecture existante
4. **Documenter** les bugs dans `docs/BUGFIX-KB.md`
5. **Ne pas ajouter** de features non demandees
6. **Eviter** over-engineering et abstractions prematurees

---

## Audit Notes (v3.57.106)

**Points a traiter lors du prochain audit:**

| # | Issue | Priorite | Description |
|---|-------|----------|-------------|
| 1 | **TLS InsecureSkipVerify** | Medium | Rendre configurable via env `SOPHOS_TLS_SKIP_VERIFY`. Actuellement requis pour certificats auto-signes XGS. Fichier: `backend/cmd/api/main.go:216` |
| 2 | **ClickHouse ORDER BY** | Medium | Optimiser avec timestamp en premier pour time-range queries. Fichier: `docker/clickhouse/init-db.sql` |
| 3 | **32 Endpoints NotImplemented** | Low | Implementer ou supprimer les routes stub retournant 501. Fichiers: `backend/cmd/api/main.go` handlers |
| 4 | **Framer Motion** | Low | Installer pour animations fluides GlassModal: `npm i framer-motion` |

**Corrections effectuees (v3.57.106):**
- CORS securise (wildcard supprime)
- Security headers OWASP ajoutes
- React lazy loading implemente
- Console.logs debug supprimes
- Composants Glassmorphism crees

---

## Sous-Agents Claude

Tous les sous-agents DOIVENT utiliser le modele **Opus** pour coherence.

```yaml
# Agents recommandes
- code-reviewer (security, maintainability)
- test-writer (coverage, edge-cases)
```

---

## Claude Code Skills

Les Skills sont des fichiers Markdown qui enseignent a Claude comment effectuer des taches specifiques. Ils sont automatiquement detectes et actives selon le contexte de la conversation.

**Total: 36 Skills** repartis en 9 categories.

### Skills par Categorie

#### 1. Development Workflow (9 skills)

| Skill | Description |
|-------|-------------|
| `gitgo` | Workflow complet de release (version, commit, sync repos, tags, releases) |
| `version-bump` | Mise a jour version dans tous les fichiers requis |
| `backend-build` | Build et tests Go (API, D2B, utilitaires) |
| `frontend-build` | Build React/TypeScript (Vite, npm) |
| `docker-deploy` | Gestion conteneurs Docker Compose |
| `db-migration` | Migrations ClickHouse (creation tables, colonnes) |
| `code-review` | Review securite (OWASP, Clean Architecture) |
| `bugfix` | Investigation et correction de bugs |
| `feature` | Implementation nouvelle fonctionnalite full-stack |

#### 2. Security Modules (4 skills)

| Skill | Description |
|-------|-------------|
| `waf-security` | Analyse WAF, regles ModSecurity, faux positifs |
| `ips-analyzer` | Analyse IPS, signatures, mapping MITRE ATT&CK |
| `vpn-security` | Securite VPN, brute force, anomalies geo |
| `atp-analysis` | ATP, malware, sandboxing, C2 detection |

#### 3. CyberSec / Threat Hunting (3 skills)

| Skill | Description |
|-------|-------------|
| `threat-hunting` | Chasse proactive, beaconing, exfiltration, lateral movement |
| `incident-response` | Playbooks IR, containment, eradication |
| `forensics` | Investigation forensique, Track IP, attribution |

#### 4. DevOps / Infrastructure (3 skills)

| Skill | Description |
|-------|-------------|
| `cicd-pipeline` | GitHub Actions, builds, releases, deployments |
| `monitoring` | Health checks, metriques, Docker/ClickHouse/Redis |
| `infrastructure` | (utiliser docker-deploy) |

#### 5. SecOps / SOC (2 skills)

| Skill | Description |
|-------|-------------|
| `soc-operations` | Operations SOC, triage, shift handoff, KPIs |
| `alerting` | Configuration alertes, WebSocket, email, suppression |

#### 6. UI / Frontend (1 skill)

| Skill | Description |
|-------|-------------|
| `react-ui-modern` | React 18, Tailwind, Shadcn, performance, accessibility |

#### 7. Data Analysis (2 skills)

| Skill | Description |
|-------|-------------|
| `xgs-log-analysis` | Analyse logs Sophos XGS, 104 champs, Vector parser |
| `anomaly-detection` | Baselines, deviations, ML-ready queries |

#### 8. API Development (2 skills)

| Skill | Description |
|-------|-------------|
| `api-design` | Design REST API, Chi router, Clean Architecture |
| `api-security` | OWASP API Top 10, JWT, RBAC, rate limiting |

#### 9. Detect2Ban (2 skills)

| Skill | Description |
|-------|-------------|
| `detect2ban-tuning` | Tuning seuils, tiers, GeoZone, scenarios |
| `false-positive-analysis` | Detection/prediction FP, whitelist recommandations |

#### 10. Geographic / Maps (3 skills)

| Skill | Description |
|-------|-------------|
| `attack-map-viz` | Carte mondiale, Leaflet, animations, clustering |
| `geoip-enrichment` | MaxMind GeoIP2, enrichissement, caching |
| `geoblocking-rules` | GeoZones, politiques pays, integration D2B |

#### 11. Threat Intelligence (2 skills)

| Skill | Description |
|-------|-------------|
| `threat-intel` | 11 providers TI, cascade scoring, caching |
| `crowdsec-sync` | Neural-Sync, blocklists, sync XGS |

#### 12. Performance (2 skills)

| Skill | Description |
|-------|-------------|
| `performance-backend` | Profiling Go, pools, concurrence |
| `clickhouse-optimization` | Schemas, partitions, materialized views |

### Structure Complete Skills

```
.claude/skills/
├── # Development Workflow
├── gitgo/
├── version-bump/
├── backend-build/
├── frontend-build/
├── docker-deploy/
├── db-migration/
├── code-review/
├── bugfix/
├── feature/
│
├── # Security Modules
├── waf-security/
├── ips-analyzer/
├── vpn-security/
├── atp-analysis/
│
├── # CyberSec
├── threat-hunting/
├── incident-response/
├── forensics/
│
├── # DevOps
├── cicd-pipeline/
├── monitoring/
│
├── # SecOps
├── soc-operations/
├── alerting/
│
├── # UI
├── react-ui-modern/
│
├── # Data Analysis
├── xgs-log-analysis/
├── anomaly-detection/
│
├── # API
├── api-design/
├── api-security/
│
├── # D2B
├── detect2ban-tuning/
├── false-positive-analysis/
│
├── # Geographic
├── attack-map-viz/
├── geoip-enrichment/
├── geoblocking-rules/
│
├── # TI
├── threat-intel/
├── crowdsec-sync/
│
└── # Performance
    ├── performance-backend/
    └── clickhouse-optimization/
```

### Utilisation

Les Skills s'activent automatiquement selon le contexte:

```
# Exemples d'activation automatique
"analyse les logs WAF de la semaine"          -> waf-security
"optimise les requetes ClickHouse"            -> clickhouse-optimization
"investigate cette IP suspecte"               -> forensics, threat-hunting
"configure l'alerting email"                  -> alerting
"reduis les faux positifs D2B"                -> false-positive-analysis
"ameliore la carte des attaques"              -> attack-map-viz
```

### Creation de Nouveaux Skills

```yaml
---
name: skill-name
description: Description claire pour detection automatique (max 1024 chars)
allowed-tools: Read, Bash, Edit, Glob, Grep
---

# Instructions detaillees en Markdown
```

---

*Fichier de memoire Claude Code - Pour details techniques voir TECHNICAL_REFERENCE.md*
