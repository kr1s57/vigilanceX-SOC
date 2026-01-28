# Guide de Développement

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Prérequis

### Outils Requis

| Outil | Version | Usage |
|-------|---------|-------|
| **Go** | 1.22+ | Backend |
| **Node.js** | 20+ | Frontend |
| **Docker** | 24+ | Infrastructure |
| **Git** | 2.40+ | Version control |

### Extensions Recommandées (VS Code)

- Go (golang.go)
- ESLint
- Prettier
- Tailwind CSS IntelliSense
- Docker

---

## Démarrage Rapide

### 1. Cloner le Projet

```bash
git clone https://github.com/kr1s57/vigilanceX.git
cd vigilanceX
```

### 2. Démarrer l'Infrastructure

```bash
cd docker
cp .env.example .env
# Éditer .env avec vos valeurs
docker compose up -d clickhouse redis vector
```

### 3. Backend

```bash
cd backend

# Installer les dépendances
go mod download

# Build
go build -o api ./cmd/api

# Lancer (dev)
go run ./cmd/api
```

### 4. Frontend

```bash
cd frontend

# Installer les dépendances
npm install

# Lancer (dev)
npm run dev
```

### 5. Accéder à l'Application

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| API | http://localhost:8080 |
| ClickHouse | http://localhost:8123 |

---

## Structure du Code

### Backend (Clean Architecture)

```
backend/
├── cmd/api/          # Point d'entrée → Configure tout
├── internal/
│   ├── entity/       # Modèles de données (CORE)
│   ├── usecase/      # Logique métier (CORE)
│   ├── adapter/      # Implémentations (EXTERNAL)
│   │   ├── controller/  # HTTP handlers
│   │   ├── repository/  # DB access
│   │   └── external/    # Clients externes
│   └── config/       # Configuration
```

**Règle d'Or**: Les couches internes (entity, usecase) ne dépendent JAMAIS des couches externes (adapter).

### Frontend (Component-Based)

```
frontend/src/
├── pages/         # Une page = une route
├── components/    # Réutilisables
│   └── ui/        # Primitives (Radix-based)
├── contexts/      # État global (auth, settings)
├── stores/        # État domain (Zustand)
├── hooks/         # Logique réutilisable
├── lib/           # Utilitaires
└── types/         # TypeScript types
```

---

## Conventions de Code

### Go

```go
// Fichiers: snake_case.go
// Interfaces/Structs: PascalCase
// Variables: camelCase
// Constantes: SCREAMING_SNAKE_CASE ou PascalCase

// Clean Architecture layers
type EventService struct {
    repo EventRepository  // Dependency injection
}

func (s *EventService) GetEvents(ctx context.Context) ([]Event, error) {
    return s.repo.FindAll(ctx)
}
```

### TypeScript/React

```tsx
// Fichiers pages: PascalCase.tsx
// Fichiers stores: camelCase.ts
// Composants: PascalCase
// Hooks: useCamelCase

// Functional components only
const Dashboard: React.FC = () => {
  const { events } = useEventsStore();
  return <div>{/* ... */}</div>;
};
```

### Tailwind CSS

```tsx
// Utiliser les classes utilitaires
<div className="flex items-center gap-4 p-4 bg-slate-900 rounded-lg">
  <Button variant="default">Action</Button>
</div>

// Couleurs sémantiques
className="text-severity-critical"  // #dc2626
className="text-status-active"      // #22c55e
className="shadow-neon-cyan"        // Glow effect
```

---

## Ajouter une Feature

### Backend

1. **Créer l'entité** (`internal/entity/`)
```go
type NewFeature struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}
```

2. **Créer le use case** (`internal/usecase/newfeature/`)
```go
type Service struct {
    repo Repository
}

func NewService(repo Repository) *Service {
    return &Service{repo: repo}
}

func (s *Service) Create(ctx context.Context, f *entity.NewFeature) error {
    return s.repo.Insert(ctx, f)
}
```

3. **Créer le repository** (`internal/adapter/repository/clickhouse/`)
```go
type NewFeatureRepository struct {
    conn *Connection
}

func (r *NewFeatureRepository) Insert(ctx context.Context, f *entity.NewFeature) error {
    // SQL INSERT
}
```

4. **Créer le handler** (`internal/adapter/controller/http/handlers/`)
```go
type NewFeatureHandler struct {
    service *newfeature.Service
}

func (h *NewFeatureHandler) Create(w http.ResponseWriter, r *http.Request) {
    // Parse request, call service, return response
}
```

5. **Enregistrer la route** (`cmd/api/main.go`)
```go
r.Route("/newfeature", func(r chi.Router) {
    r.Post("/", newFeatureHandler.Create)
})
```

### Frontend

1. **Créer la page** (`src/pages/NewFeature.tsx`)
```tsx
const NewFeature: React.FC = () => {
  const [data, setData] = useState<Feature[]>([]);

  useEffect(() => {
    api.get('/newfeature').then(res => setData(res.data));
  }, []);

  return (
    <div className="p-6">
      <h1>New Feature</h1>
      {/* Content */}
    </div>
  );
};
```

2. **Ajouter la route** (`src/App.tsx`)
```tsx
<Route path="/newfeature" element={<NewFeature />} />
```

3. **Ajouter au menu** (`src/components/layout/Sidebar.tsx`)

---

## Tests

### Backend

```bash
# Tous les tests
go test ./...

# Avec couverture
go test -cover ./...

# Test spécifique
go test ./internal/usecase/auth/...
```

### Frontend

```bash
# Linting
npm run lint

# Type checking
npm run build
```

---

## Debugging

### Backend Logs

```bash
# Docker logs
docker compose logs -f backend

# Log levels (via APP_ENV)
APP_ENV=development  # Debug logs
APP_ENV=production   # Info+ only
```

### Frontend DevTools

- React DevTools
- Redux DevTools (pour Zustand)
- Network tab pour API calls

### ClickHouse Queries

```bash
# Accès CLI
docker exec -it vigilance_clickhouse clickhouse-client

# Requêtes utiles
SELECT count() FROM vigilance_x.events WHERE timestamp > now() - INTERVAL 1 HOUR;
SELECT * FROM vigilance_x.bans WHERE status = 'active' LIMIT 10;
```

---

## Versioning

### Format: X.YY.Z

| Digit | Description | Exemple |
|-------|-------------|---------|
| **X** | MAJOR (sur demande) | 3 → 4 |
| **YY** | FEATURE (nouvelle) | 58 → 59 |
| **Z** | BUGFIX (correction) | 107 → 108 |

### Fichiers à Mettre à Jour

```bash
# 1. Frontend
frontend/src/pages/Dashboard.tsx      # INSTALLED_VERSION
frontend/src/pages/Settings.tsx       # Footer
frontend/src/pages/Login.tsx          # Footer
frontend/src/pages/LicenseActivation.tsx

# 2. Backend
backend/internal/adapter/controller/http/handlers/update.go

# 3. Documentation
CLAUDE.md  # Header
```

---

## Git Workflow

### Branches

```
main         # Production stable
develop      # Développement actif (optionnel)
feature/*    # Nouvelles features
bugfix/*     # Corrections
```

### Commit Messages

```
feat(vX.YY.Z): description courte

- Détail 1
- Détail 2

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

### Remotes

| Remote | Repo | Accès |
|--------|------|-------|
| origin | kr1s57/vigilanceX | Private |
| public | kr1s57/vigilanceX-SOC | Public |
| forgejo | itsadm/vigilanceX | Private |
| forgejo-soc | itsadm/vigilanceX-SOC | Public |

---

## Commandes Fréquentes

```bash
# Build backend
cd backend && go build ./cmd/api

# Build frontend
cd frontend && npm run build

# Docker restart
cd docker && docker compose restart api

# Logs
docker compose logs -f api

# Reset password admin
docker exec vigilance-api /app/reset-password -u admin -p newpass

# ClickHouse CLI
docker exec -it vigilance_clickhouse clickhouse-client
```

---

## Règles de Sécurité

### À Ne Jamais Faire

- Commiter `.env`, `credentials.json`, clés SSH
- Push `--force` sur main/master
- Exposer les seuils D2B ou durées de ban
- Utiliser `InsecureSkipVerify` en production

### Headers OWASP (déjà implémentés)

```go
// middleware/security.go
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("X-XSS-Protection", "1; mode=block")
w.Header().Set("Content-Security-Policy", "default-src 'self'")
```

---

*Documentation générée par le workflow document-project*
