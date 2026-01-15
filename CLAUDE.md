# VIGILANCE X - Claude Code Memory File

> **Version**: 3.55.113 | **Derniere mise a jour**: 2026-01-16

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
- `CHANGELOG.md`
- `frontend/src/pages/Settings.tsx` (ligne ~2129)
- `CLAUDE.md` header (version + date)
- Tags git sur les 4 repos

---

## Workflow Git (gitgo)

Quand l'utilisateur dit "gitgo":

**Etape 0 - Version (OBLIGATOIRE):**
1. Verifier version dans Settings.tsx (ligne ~2129)
2. Incrementer selon regles X.YY.Z
3. Mettre a jour header CLAUDE.md

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

## Sous-Agents Claude

Tous les sous-agents DOIVENT utiliser le modele **Opus** pour coherence.

```yaml
# Agents recommandes
- code-reviewer (security, maintainability)
- test-writer (coverage, edge-cases)
```

---

*Fichier de memoire Claude Code - Pour details techniques voir TECHNICAL_REFERENCE.md*
