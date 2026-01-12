# Storage SMB - Session de Travail

> **Date**: 2026-01-12 | **Status**: Preparation terminee, pret pour tests
> **Reprise**: Dire "reprenons le storage SMB" pour continuer

---

## Etat Actuel

### Code Pret (Non Deploye)

| Composant | Fichier | Status |
|-----------|---------|--------|
| Provider Interface | `backend/internal/adapter/external/storage/provider.go` | Done |
| SMB Client | `backend/internal/adapter/external/storage/smb.go` | Done |
| Storage Manager | `backend/internal/adapter/external/storage/manager.go` | Done |
| HTTP Handlers | `backend/internal/adapter/controller/http/handlers/storage.go` | Done |
| Frontend API | `frontend/src/lib/api.ts` (storageApi) | Done |
| Settings UI | `frontend/src/pages/Settings.tsx` (section Storage) | Done |
| Risk Analysis | `docs/STORAGE-SMB-RISK.md` | Done |

### Risque Evalue

- **Score Global**: 4.1/10 (Risque Modere - Acceptable)
- **Strategie**: SMB en archivage supplementaire, ClickHouse reste pour temps reel

---

## Tests a Realiser Demain

### 1. Prerequisites Infrastructure

```bash
# Verifier acces SMB depuis le serveur VGX
smbclient //IP_NAS/vigilancex_logs -U vigilancex_svc

# Infos requises:
# - SMB_HOST: IP du NAS/serveur SMB
# - SMB_SHARE: Nom du partage (ex: vigilancex_logs)
# - SMB_USER: Compte service
# - SMB_PASSWORD: Mot de passe
# - SMB_DOMAIN: WORKGROUP ou domaine AD
```

### 2. Ajouter Dependance Go

```bash
cd /opt/vigilanceX/backend
go get github.com/hirochachacha/go-smb2
go mod tidy
```

### 3. Wirer Routes dans main.go

Ajouter dans `backend/cmd/api/main.go`:

```go
import "vigilancex/internal/adapter/external/storage"

// Apres initialisation des autres services
storageManager := storage.NewManager("/app/config/storage.json")
if err := storageManager.LoadConfig(); err != nil {
    slog.Warn("Storage config not found, using defaults")
}
storageHandler := handlers.NewStorageHandler(storageManager)

// Dans la section routes protegees
r.Route("/storage", func(r chi.Router) {
    r.Get("/config", storageHandler.GetConfig)
    r.Put("/config", storageHandler.UpdateConfig)
    r.Put("/smb", storageHandler.UpdateSMBConfig)
    r.Get("/status", storageHandler.GetStatus)
    r.Post("/test", storageHandler.TestConnection)
    r.Post("/connect", storageHandler.Connect)
    r.Post("/disconnect", storageHandler.Disconnect)
    r.Post("/enable", storageHandler.Enable)
    r.Post("/disable", storageHandler.Disable)
})
```

### 4. Rebuild et Test

```bash
# Build backend
cd /opt/vigilanceX/docker
docker compose build backend --no-cache

# Restart
docker compose up -d backend --force-recreate

# Verifier logs
docker compose logs backend -f
```

### 5. Test via UI

1. Aller dans Settings > Storage & Archiving
2. Remplir les champs SMB (Host, Share, User, Password)
3. Cliquer "Test Connection"
4. Si OK, cliquer "Save & Enable"

### 6. Validation Archivage

```bash
# Sur le NAS/SMB, verifier creation des fichiers
ls -la /chemin/share/vigilancex/logs/

# Format attendu:
# vigilancex/logs/2026-01-13/vigilancex_2026-01-13.jsonl.gz
```

---

## Configuration SMB Recommandee

```json
{
  "enabled": true,
  "type": "smb",
  "smb": {
    "host": "10.x.x.x",
    "port": 445,
    "share": "vigilancex_logs",
    "username": "vigilancex_svc",
    "password": "***",
    "domain": "WORKGROUP",
    "base_path": "vigilancex"
  },
  "archive": {
    "enabled": true,
    "compression": true,
    "rotation_pattern": "daily",
    "retention_days": 90,
    "max_file_size": 104857600
  }
}
```

---

## Fichiers Modifies Cette Session

- `backend/internal/adapter/external/storage/` (nouveau package)
- `backend/internal/adapter/controller/http/handlers/storage.go`
- `frontend/src/lib/api.ts` (+storageApi)
- `frontend/src/pages/Settings.tsx` (+section Storage)
- `docs/STORAGE-SMB-RISK.md` (nouveau)
- `CLAUDE.md` (section Storage External ajoutee)

---

## Rollback si Probleme

Le storage SMB est **optionnel et supplementaire**:
- Desactiver dans Settings suffit
- Les logs continuent vers ClickHouse
- Aucun impact sur le fonctionnement normal

---

*Session preparee par Claude Code - 2026-01-12 04:15*
