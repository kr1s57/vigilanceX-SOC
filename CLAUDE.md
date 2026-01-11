# VIGILANCE X - Claude Code Memory File

> **Version**: 3.4.100 | **Derniere mise a jour**: 2026-01-11

Ce fichier sert de memoire persistante pour Claude Code. Il documente l'architecture, les conventions et les regles du projet VIGILANCE X.

---

## Architecture de Deploiement Securise

### Modele de Securite

VIGILANCE X est deploye dans un environnement **securise par design**:

| Couche | Protection |
|--------|------------|
| **Reseau** | Pas d'exposition Internet, interne uniquement |
| **Acces** | VPN obligatoire pour acces distant |
| **Firewall** | Regles restrictives, uniquement PC admin autorises |
| **Authentification** | JWT + RBAC (admin/audit) |

### Implications sur la Securite

Cette architecture elimine les vecteurs d'attaque externes:

| Menace | Statut | Raison |
|--------|--------|--------|
| Brute-force login | **Non applicable** | Seuls admins de confiance ont acces |
| DDoS | **Non applicable** | Pas d'exposition Internet |
| Injection depuis Internet | **Non applicable** | Reseau isole |
| Man-in-the-middle externe | **Non applicable** | Trafic interne uniquement |

### Securite Implementee

Les mesures suivantes sont en place et suffisantes pour l'environnement:

- **Hashage bcrypt** (cout 12) pour mots de passe
- **JWT avec validation HMAC** pour sessions
- **RBAC** avec roles admin/audit
- **Rate limiting global** (100 req/min)
- **Placeholders SQL** contre injections
- **Password hash jamais expose** en JSON

### Mesures NON necessaires (environnement controle)

Ces mesures seraient requises uniquement si exposition Internet:

- Lockout apres N tentatives login
- Rate limiting agressif sur /auth/login
- Protection anti-brute-force
- WAF applicatif

---

## Statut des Fonctionnalites

### En Production
- Dashboard temps reel
- WAF Explorer
- Attacks Analyzer
- Advanced Threat (11 providers TI)
- VPN & Network
- Soft Whitelist
- Geoblocking
- Authentication & User Management
- Systeme de licence VX3
- XGS Parser (104 champs, 74 regles, 23 techniques MITRE)

### En Developpement (Coquille)
- **Policies de bans**: Logique de decision non finalisee
- **Detect2Ban engine**: Scenarios YAML a completer
- **Recidivisme automatique**: A configurer selon besoins

> **Note**: Ne pas modifier la logique des bans sans consultation prealable.

---

## Vue d'Ensemble du Projet

**VIGILANCE X** est une plateforme SOC (Security Operations Center) temps reel qui:
- Collecte les logs Sophos XGS via Syslog
- Analyse les menaces avec 11 providers de Threat Intelligence
- Bannit automatiquement les IPs malveillantes via l'API XML Sophos
- Offre une interface web moderne pour les operateurs de securite

### Stack Technique

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Backend | Go (Chi router, Clean Architecture) | 1.22 |
| Frontend | React + TypeScript + Tailwind + Shadcn UI | 18.2.0 |
| Database | ClickHouse (analytique temps reel) | 24.1 |
| Cache | Redis | 7-alpine |
| Ingestion | Vector.dev (Syslog) | 0.34.1 |
| Deploiement | Docker Compose | - |

---

## Structure du Projet

```
/opt/vigilanceX/
├── backend/                    # API Go + Detect2Ban Engine
│   ├── cmd/                    # Points d'entree
│   │   ├── api/               # Serveur API (main.go)
│   │   ├── detect2ban/        # Moteur de detection
│   │   └── reset-password/    # CLI reset mot de passe
│   ├── internal/              # Code applicatif (Clean Architecture)
│   │   ├── domain/            # Logique metier (scoring)
│   │   ├── entity/            # Modeles de donnees
│   │   ├── adapter/           # Adaptateurs externes
│   │   │   ├── repository/    # Acces base de donnees
│   │   │   ├── controller/    # Handlers HTTP et WebSocket
│   │   │   └── external/      # Clients externes (Sophos, ThreatIntel)
│   │   ├── usecase/           # Services metier
│   │   ├── config/            # Configuration
│   │   ├── license/           # Systeme de licence VX3
│   │   └── pkg/               # Utilitaires reutilisables
│   ├── scenarios/             # Scenarios YAML Detect2Ban
│   └── migrations/            # Migrations SQL
├── frontend/                   # React SPA
│   ├── src/
│   │   ├── pages/             # 14 pages principales
│   │   ├── components/        # Composants UI reutilisables
│   │   ├── contexts/          # AuthContext, SettingsContext, LicenseContext
│   │   ├── stores/            # Zustand stores (bans, events)
│   │   ├── lib/               # API client, WebSocket, utils
│   │   ├── hooks/             # Custom React hooks
│   │   └── types/             # Definitions TypeScript
│   └── dist/                  # Build de production
├── docker/                     # Configuration Docker Compose
│   ├── docker-compose.yml
│   ├── clickhouse/            # Init SQL ClickHouse
│   ├── vector/                # Configuration Vector.dev
│   ├── nginx/                 # Reverse proxy production
│   └── ssh/                   # Cles SSH pour Sophos XGS
├── docs/                       # Documentation
│   ├── architecture/
│   ├── api/
│   └── deployment/
├── .env.example               # Template variables d'environnement
├── README.md                  # Documentation principale
├── CHANGELOG.md               # Historique des versions
└── CLAUDE.md                  # CE FICHIER - Memoire Claude Code
```

---

## Fichiers Cles par Fonction

### Backend - Points d'Entree
| Fichier | Lignes | Description |
|---------|--------|-------------|
| `backend/cmd/api/main.go` | ~600 | Initialisation API, routes, middleware |
| `backend/cmd/detect2ban/main.go` | ~200 | Daemon de detection |
| `backend/cmd/reset-password/main.go` | ~50 | CLI urgence |

### Backend - Services Metier
| Fichier | Description |
|---------|-------------|
| `internal/usecase/auth/service.go` | Authentification JWT, bcrypt |
| `internal/usecase/bans/service.go` | Gestion des bans progressifs |
| `internal/usecase/threats/service.go` | Aggregation Threat Intel |
| `internal/usecase/events/service.go` | Traitement des evenements |
| `internal/usecase/geoblocking/service.go` | Regles geographiques |
| `internal/usecase/modsec/service.go` | Sync ModSecurity SSH |
| `internal/license/client.go` | Systeme licence VX3 |

### Backend - Adaptateurs Externes
| Fichier | Description |
|---------|-------------|
| `internal/adapter/external/threatintel/` | 11 providers TI |
| `internal/adapter/external/sophos/` | Client API XML Sophos |
| `internal/adapter/external/blocklist/` | Ingestion blocklists |
| `internal/adapter/external/geoip/` | Lookup geolocalisation |

### Frontend - Pages Principales
| Fichier | Lignes | Description |
|---------|--------|-------------|
| `src/pages/Dashboard.tsx` | ~400 | Vue d'ensemble securite |
| `src/pages/AttacksAnalyzer.tsx` | ~1060 | Analyse WAF/ModSec |
| `src/pages/Settings.tsx` | ~1164 | Configuration systeme |
| `src/pages/VpnNetwork.tsx` | ~900 | Monitoring VPN |
| `src/pages/Geoblocking.tsx` | ~570 | Regles geo |
| `src/pages/SoftWhitelist.tsx` | ~630 | Whitelist graduee |
| `src/pages/UserManagement.tsx` | ~600 | Gestion utilisateurs |

### Frontend - Infrastructure
| Fichier | Description |
|---------|-------------|
| `src/lib/api.ts` | Client API Axios (~720 lignes) |
| `src/lib/websocket.ts` | Manager WebSocket temps reel |
| `src/contexts/AuthContext.tsx` | Gestion authentification |
| `src/contexts/LicenseContext.tsx` | Gestion licence |
| `src/stores/bansStore.ts` | State management bans |

---

## Conventions de Code

### Backend Go

```go
// Structure Clean Architecture
internal/
├── entity/      // Modeles de donnees (pas de logique)
├── usecase/     // Services metier (logique pure)
├── adapter/     // Implementations concretes
│   ├── repository/   // Acces DB
│   └── controller/   // HTTP handlers
└── domain/      // Regles metier complexes

// Nommage
- Fichiers: snake_case.go
- Packages: lowercase
- Interfaces: PascalCase (ex: BansRepository)
- Structs: PascalCase (ex: BanStatus)
- Variables: camelCase
- Constantes: PascalCase ou ALL_CAPS

// Error handling
- Toujours retourner error en dernier
- Logger les erreurs avec contexte
- Ne pas panic sauf cas critiques
```

### Frontend TypeScript/React

```typescript
// Structure fichiers
src/
├── pages/       // Composants de page (PascalCase.tsx)
├── components/  // Composants reutilisables
├── contexts/    // React Context providers
├── stores/      // Zustand stores (camelCase.ts)
├── lib/         // Utilitaires (camelCase.ts)
├── hooks/       // Custom hooks (useXxx.ts)
└── types/       // Types TypeScript (index.ts)

// Conventions
- Composants: PascalCase
- Hooks: useXxx
- Fichiers utilitaires: camelCase
- Types/Interfaces: PascalCase
- Variables: camelCase

// State Management
- Context API: Global (auth, settings, license)
- Zustand: Domain state (bans, events)
- useState: Local component state
```

### Base de Donnees ClickHouse

```sql
-- Tables principales
vigilance.events           -- Logs Sophos XGS
vigilance.threat_scores    -- Scores Threat Intel
vigilance.ban_status       -- Statut des bans
vigilance.ban_history      -- Historique bans
vigilance.whitelist        -- Soft whitelist
vigilance.geo_block_rules  -- Regles geoblocking
vigilance.users            -- Utilisateurs
vigilance.modsec_logs      -- Logs ModSecurity

-- Conventions
- Tables: snake_case
- Colonnes: snake_case
- Index: idx_table_column
```

---

## API Endpoints Principaux

### Authentication
```
POST   /api/v1/auth/login              # Login (public)
POST   /api/v1/auth/logout             # Logout
GET    /api/v1/auth/me                 # User info
POST   /api/v1/auth/change-password    # Change password
```

### Events & Stats (Free)
```
GET    /api/v1/events                  # Liste events
GET    /api/v1/events/timeline         # Timeline
GET    /api/v1/stats/overview          # Stats globales
GET    /api/v1/stats/top-attackers     # Top IPs
```

### Threats (Licensed)
```
GET    /api/v1/threats/check/{ip}      # Check IP
GET    /api/v1/threats/risk/{ip}       # Risk combine
GET    /api/v1/threats/providers       # Status providers
POST   /api/v1/threats/batch           # Batch check
```

### Bans (Licensed)
```
GET    /api/v1/bans                    # Liste bans
POST   /api/v1/bans                    # Creer ban
DELETE /api/v1/bans/{ip}               # Supprimer ban
POST   /api/v1/bans/sync               # Sync Sophos XGS
```

### Geoblocking (Licensed)
```
GET    /api/v1/geoblocking/rules       # Liste regles
POST   /api/v1/geoblocking/rules       # Creer regle
GET    /api/v1/geoblocking/check/{ip}  # Check IP
GET    /api/v1/geoblocking/lookup/{ip} # Lookup geo
```

### WebSocket
```
GET    /ws                             # Real-time updates
GET    /api/v1/ws?token=xxx            # With auth token
```

---

## Variables d'Environnement Critiques

```bash
# Sophos XGS
SOPHOS_HOST=10.x.x.x
SOPHOS_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASSWORD=xxx

# Database
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_DATABASE=vigilance_x
CLICKHOUSE_USER=vigilance
CLICKHOUSE_PASSWORD=xxx

# Authentication
JWT_SECRET=min-32-chars-secret
JWT_EXPIRY=24h
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!

# License (v3.0)
LICENSE_ENABLED=true
LICENSE_SERVER_URL=https://vigilancexkey.cloudcomputing.lu
LICENSE_KEY=xxx
LICENSE_GRACE_PERIOD=168h  # 7 jours

# Threat Intelligence (optionnel)
ABUSEIPDB_API_KEY=xxx
VIRUSTOTAL_API_KEY=xxx
GREYNOISE_API_KEY=xxx
```

---

## Regles de Developpement

### OBLIGATOIRE - A Respecter

1. **Ne jamais modifier** les fichiers de configuration production (.env)
2. **Toujours tester** les modifications backend avec `go build` avant commit
3. **Toujours tester** les modifications frontend avec `npm run build`
4. **Respecter** l'architecture Clean Architecture existante
5. **Ne pas ajouter** de nouvelles dependances sans justification
6. **Documenter** les nouveaux endpoints dans README.md
7. **Mettre a jour** CHANGELOG.md pour chaque version
8. **Documenter** les bugs dans `docs/BUGFIX-KB.md` pour la KB

### Gestion des Bugs (BUGFIX-KB)

Apres chaque session de debug, documenter les corrections dans `docs/BUGFIX-KB.md`:

**Structure d'une entree bug:**
```markdown
### [BUG-XXXX] Titre court

**Date**: YYYY-MM-DD
**Version**: vX.Y.Z
**Severite**: Critical | High | Medium | Low
**Composant**: Frontend | Backend | Infrastructure
**Fichiers affectes**: Liste des fichiers

#### Symptome
Description du comportement observe.

#### Cause Racine
Explication technique du pourquoi.

#### Solution
Description de la correction avec code avant/apres.

#### Lecons Apprises
- Points cles pour eviter ce bug a l'avenir

#### Tags
`#composant` `#type-bug` `#technologie`
```

**Patterns recurrents documentes:**
1. Persistance filtres → `sessionStorage`
2. Null safety API → `data || []`
3. Filtrage centralise → `shouldShowIP()` dans Context
4. Conversion period → `getStartTimeFromPeriod()`

### Regles de Versioning (X.Y.Z)

Les projets **VigilanceX** et **VigilanceKey** suivent une numerotation stricte des versions.

**Format**: `X.Y.Z` (exemple: `3.10.109`)

| Digit | Nom | Description | Reset |
|-------|-----|-------------|-------|
| **X** | MAJOR | Montee de version majeure (sur demande explicite) | - |
| **Y** | FEATURE | Ajout de fonctionnalites, nouvelles features | → 0 lors d'un bump MAJOR |
| **Z** | BUGFIX | Corrections de bugs, hotfixes (commence a 100) | → 100 lors d'un bump FEATURE |

**Montee BUGFIX** (X.Y.Z → X.Y.Z+1):
- Corrections de bugs et crashs
- Hotfixes necessitant un rebuild
- Exemple: `3.2.105` → `3.2.106`

**Montee FEATURE** (X.Y.Z → X.Y+1.100):
- Ajout de nouvelles fonctionnalites
- Ameliorations significatives
- Le digit BUGFIX revient a 100
- Exemple: `3.2.106` → `3.3.100`

**Montee MAJOR** (X.Y.Z → X+1.0.100):
- Uniquement sur demande explicite de l'utilisateur
- Changements majeurs d'architecture
- Les digits FEATURE et BUGFIX reviennent a 0 et 100
- Exemple: `3.10.115` → `4.0.100`

> **Important**: A chaque release, mettre a jour:
> - `CHANGELOG.md` - Historique des versions
> - `frontend/src/pages/Settings.tsx` - Version affichee dans l'interface (ligne ~966)
> - `CLAUDE.md` - Header du fichier (version et date)
> - Tags git: `vX.Y.Z` sur les deux repos (private et public)

### Commandes Frequentes

```bash
# Backend
cd backend
go mod tidy          # Deps
go build ./cmd/api   # Build API
go test ./...        # Tests

# Frontend
cd frontend
npm install          # Deps
npm run dev          # Dev server
npm run build        # Production
npm run lint         # Linting

# Docker
cd docker
docker compose up -d           # Start
docker compose logs -f         # Logs
docker compose restart api     # Restart service
```

### Workflow Git (gitgo)

Quand l'utilisateur dit "gitgo":
1. `git status` - Verifier les changements
2. `git add .` - Ajouter les fichiers
3. `git commit` - Commit avec message descriptif
4. `git push` - Pousser vers origin
5. Mettre a jour CHANGELOG.md si nouvelle version
6. Mettre a jour README.md si nouvelles fonctionnalites

### Workflow Deploiement (3 environnements)

| Environnement | Machine | Description |
|---------------|---------|-------------|
| **DEV** | 10.25.72.28 (/opt/vigilanceX) | Code source, builds locaux |
| **VPS-TEST** | vps-b3a1bf23 (OVH) | Simulation client distant |
| **vigilanceKey** | 10.56.126.126 | Serveur de licences |

**Deploiement vers VPS-TEST (via GHCR):**
```bash
# 1. Sur DEV - Build et push images
cd /opt/vigilanceX
echo "TOKEN" | docker login ghcr.io -u kr1s57 --password-stdin
docker build -t ghcr.io/kr1s57/vigilancex-api:VERSION -f backend/Dockerfile backend/
docker build -t ghcr.io/kr1s57/vigilancex-frontend:VERSION -f frontend/Dockerfile frontend/
docker push ghcr.io/kr1s57/vigilancex-api:VERSION
docker push ghcr.io/kr1s57/vigilancex-frontend:VERSION

# 2. Sur VPS-TEST - Pull et restart
cd ~/vigilanceX-SOC/deploy
docker compose pull backend frontend
docker compose up -d backend frontend --force-recreate
```

**Synchronisation des 3 repos Git:**
1. vigilanceX (private): Code source complet
2. vigilanceX-SOC (public): Deploiement et documentation
3. vigilanceKey (private): Serveur de licences

A chaque release, creer les GitHub Releases via API pour afficher "Latest".

---

## Threat Intelligence Providers

### Tiers de Cascade (v2.9.5)

| Tier | Providers | Quota | Seuil |
|------|-----------|-------|-------|
| **Tier 1** (Free) | IPSum, OTX, ThreatFox, URLhaus, Shodan InternetDB | Illimite | Toujours |
| **Tier 2** | AbuseIPDB, GreyNoise, CrowdSec | Modere | Score > 30 |
| **Tier 3** | VirusTotal, CriminalIP, Pulsedive | Limite | Score > 60 |

### Format Score Agrege

```go
type ThreatScore struct {
    IP               string
    AggregatedScore  float64  // 0-100
    ThreatLevel      string   // critical/high/medium/low/minimal
    IsMalicious      bool
    Sources          []string
    Categories       []string
}
```

---

## Systeme de Licence VX3

### Binding Hardware

```
VX3 Hardware ID = SHA256("VX3:" + machine_id + ":" + firewall_serial)
```

- **machine_id**: UUID de la VM (/etc/machine-id)
- **firewall_serial**: Extrait des logs Sophos XGS

### Workflow Fresh Deploy (v3.2)

Flux semi-automatise "Request & Sync" pour l'onboarding client:

```
Installation -> Login -> Email + Generate Trial (15j) -> FDEPLOY
                                    |
                    [Sync auto 12h ou manuel]
                                    |
                    XGS detecte -> FWID envoye -> TRIAL valide
                                    |
                    "Ask Pro License" -> ASKED -> Admin approuve -> ACTIVE
```

### Statuts Licence

| Status | Description | Duree |
|--------|-------------|-------|
| `FDEPLOY` | Fresh deploy, attente XGS | 15 jours |
| `TRIAL` | XGS connecte, trial valide | 15 jours |
| `ASKED` | Demande Pro soumise | Jusqu'a action admin |
| `ACTIVE` | Pro licence active | Config admin |
| `EXPIRED` | Licence expiree | - |
| `REVOKED` | Revoquee par admin | - |

### Grace Period

- Duree: 7 jours (168h)
- Active si serveur de licence injoignable
- Fonctionnalites completes maintenues

### Endpoints Licence

```
GET  /api/v1/license/status        # Status (public)
POST /api/v1/license/activate      # Activation manuelle (public)
POST /api/v1/license/fresh-deploy  # Trial automatique (public, rate limit 5/h)
POST /api/v1/license/ask-pro       # Demande upgrade Pro (auth)
POST /api/v1/license/sync-firewall # Sync firewall binding (auth)
GET  /api/v1/license/info          # Details (admin)
POST /api/v1/license/validate      # Force validation (admin)
```

---

## Integrations Sophos XGS

### Ports et Protocoles

| Service | Port | Protocole | Usage |
|---------|------|-----------|-------|
| Syslog | 514/UDP, 1514/TCP | Syslog | Reception logs |
| API XML | 4444 | HTTPS | Ban/Unban IPs |
| SSH | 22 | SSH | Sync ModSecurity |

### Groupes IP Sophos

- `VIGILANCE_X_BLOCKLIST` - Bans temporaires
- `VIGILANCE_X_PERMANENT` - Bans permanents

---

## Sous-Agents Claude (Regles)

### Configuration Requise

Tous les sous-agents DOIVENT utiliser le modele **Opus** pour garantir la coherence.

### Agents Recommandes

```yaml
# ~/.claude/agents/code-reviewer.yaml
name: code-reviewer
model: opus
focus:
  - security
  - maintainability
  - clean-architecture

# ~/.claude/agents/test-writer.yaml
name: test-writer
model: opus
focus:
  - test-coverage
  - edge-cases
  - error-handling
```

---

## Hooks de Securite

Configuration dans `~/.claude/settings.json` et scripts dans `~/.claude/hooks/`.

### Scripts de Hooks

| Script | Type | Description |
|--------|------|-------------|
| `block-dangerous-commands.sh` | PreToolUse | Bloque rm -rf, DROP DATABASE, etc. |
| `validate-git-operations.sh` | PreToolUse | Bloque force push sur main/master |
| `protect-env-files.sh` | PreToolUse | Protege .env, credentials, cles SSH |
| `post-write-linter.sh` | PostToolUse | gofmt pour .go, prettier pour .ts/.tsx |

### Commandes Bloquees

```bash
# Suppression systeme
rm -rf /
rm -rf /*
rm -rf /etc /var /usr /root /opt

# Base de donnees
DROP DATABASE
TRUNCATE TABLE
DELETE FROM ... WHERE 1

# Git destructif (sur main/master/develop)
git push --force origin main
git reset --hard
git clean -fd

# Systeme
shutdown, reboot, halt
dd if=/dev/zero of=/dev/sd*
chmod -R 777 /
```

### Fichiers Proteges

```
.env, .env.local, .env.production
credentials.json, secrets.json
*.pem, *.key, id_rsa, id_ed25519
license.json, .credentials.json
```

### Auto-Formatage (PostToolUse)

| Extension | Formateur |
|-----------|-----------|
| `.go` | gofmt -w |
| `.ts`, `.tsx`, `.js`, `.jsx` | prettier --write |
| `.json` | jq '.' |

### Logs des Hooks

```bash
# Voir les logs des hooks
tail -f /tmp/claude-hooks.log
```

---

## References Documentation Anthropic

- [Claude Code Memory Files](https://docs.anthropic.com/en/docs/claude-code/memory)
- [Claude Code Hooks](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [Claude Code Agents](https://docs.anthropic.com/en/docs/claude-code/agents)

---

## Notes de Version Recentes

### v3.4.100 (2026-01-11)
- **Debug Session**: 8 corrections UX et ameliorations
- Attack Analyzer: Fix tooltip graphique (Triggers/Unique IPs)
- Attack Analyzer: Loupe sur Top Attack pour voir IPs associees
- Attack Analyzer: Unique Attackers avec compteur total + tabs filtres
- Reports: Bouton "Send by Mail" avec piece jointe PDF/XML
- Reports: Fix SMTP hot-reload (utilise notificationService)
- WAF Explorer: Bouton Expand/Collapse All
- WAF Explorer: Stats header (Total Events, Blocked, Detected)
- Nouvelle methode `SendEmailWithAttachment` dans notifications service

### v3.3.100 (2026-01-11)
- **SMTP Email Notifications**: Nouvelle integration (partiellement fonctionnelle)
- Configuration SMTP avec support TLS/STARTTLS/SSL
- **Office365**: AUTH LOGIN prioritaire, STARTTLS port 587
- Rapports programmes: Daily, Weekly, Monthly avec choix horaire
- Alertes temps-reel: WAF Detection/Blocked, New Bans, Critical Events
- Seuil de severite configurable (Critical/High/Medium/Low)
- Templates HTML professionnels pour tous les emails
- Nouvelle section "Email Notifications" dans Settings
- Nouveaux endpoints: /notifications/settings, /test-email, /status
- Hot-reload SMTP client (pas de redemarrage necessaire)
- **Bug connu**: Notification settings multi-toggle ne persist pas (race condition)
- **Voir**: `docs/bugfix/SMTP_IMPLEMENTATION_NOTES.md` pour details debug

### v3.2.102 (2026-01-10)
- WAF Explorer: Selecteur periode (7d/14d/30d) et date picker
- Auto-expansion de tous les jours par defaut
- Fix Zone Traffic API 500 (check colonne existence)

### v3.2.101 (2026-01-10)
- **Bug Fix Session**: 6 corrections UX et stabilite
- Dashboard: Persistance filtre temps via sessionStorage
- Attack Analyzer: Filtrage IPs systeme (0.0.0.0, 127.0.0.1)
- WAF Explorer: Limite augmentee (500) + bouton "Load More"
- VPN Page: start_time passe a eventsApi pour filtrage correct
- Settings: Nouveau plugin Syslog avec bouton edition IP
- Pages vides: Gestion defensive null sur APIs (serveur test)
- **Documentation**: Nouveau fichier `docs/BUGFIX-KB.md` pour KB

### v3.2.100 (2026-01-10)
- **Fresh Deploy System**: Workflow semi-automatise "Request & Sync"
- Nouveaux statuts licence: FDEPLOY, TRIAL, ASKED
- Trial automatique 15 jours (format VX3-TRIAL-XXXX-XXXX)
- Detection et binding XGS automatique
- Bouton "Ask Pro License" pour demande upgrade
- Interface LicenseActivation refaite completement
- Section Fresh Deploy dans dashboard admin VigilanceKey
- Nouveaux endpoints: /fresh-deploy, /ask-pro, /sync-firewall
- **Fix**: NeedsFreshDeploy retourne true pour licences invalid/expired

### v3.1.6 (2026-01-10)
- Fix dashboard page blanche (APIs retournaient null au lieu de [])
- Erreur corrigee: `Cannot read properties of null (reading 'slice')`
- Initialisation des slices avec `[]Type{}` au lieu de `var []Type`

### v3.1.5 (2026-01-10)
- Fix nginx proxy_pass: preserve /api prefix for correct routing
- Ajout `LICENSE_INSECURE_SKIP_VERIFY` pour certificats self-signed
- Fix: `/api/v1/license/status` retournait 404 (trailing slash dans proxy_pass)
- Support certificats SSL sans SANs sur serveur de licence interne
- Fix WebSocket routing `/api/v1/ws`

### v3.1.4 (2026-01-10)
- Fix frontend React build (Terser property mangling cassait React internals)
- Erreur corrigee: `Cannot read properties of undefined (reading 'ReactCurrentOwner')`
- Suppression du property mangling `/^_/` dans vite.config.ts

### v3.1.3 (2026-01-10)
- Fix backend signal handler crash (Garble `-tiny` flag)
- Suppression du flag `-tiny` de Garble dans release.yml
- Erreur corrigee: `fatal: bad g in signal handler` (SIGSEGV)

### v3.1.1 (2026-01-09)
- Fix backend signal handler crash (UPX compression)
- Suppression de la compression UPX dans release.yml

### v3.1.0 (2026-01-09)
- XGS Decoders & Rules Engine (Sophos Log Parser)
- 104 champs dans 17 groupes (vigilanceX_XGS_decoders.xml)
- 74 regles dans 10 categories (vigilanceX_XGS_rules.xml)
- 23 techniques MITRE ATT&CK mappees
- Parser Go natif avec API endpoints (/parser/stats, /fields, /rules, /mitre, /test)
- 27 nouveaux champs dans Vector.toml et ClickHouse

### v3.0.1 (2026-01-09)
- Script de maintenance Docker (nettoyage build cache)
- VPN Sessions: Groupement par jour avec accordeon
- Geoblocking: Top 10 pays attaquants avec modal details

### v3.0.0 (2026-01-08)
- VX3 Secure Firewall Binding (VM + Firewall serial)
- Grace Period etendu a 7 jours
- Migration automatique VX2 → VX3

### v2.9.7 (2026-01-06)
- License Sync & Grace Mode
- Heartbeat monitoring

### v2.6.0 (2025-12-xx)
- Authentication JWT
- User Management
- RBAC (admin/audit)

---

*Fichier de memoire genere par Claude Code - Maintenir a jour lors des evolutions majeures du projet.*
