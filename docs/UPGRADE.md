# Guide de Mise à Jour VIGILANCE X (Internal)

Ce document décrit les procédures de mise à jour pour le développement interne.

## Versioning

| Type | Changement | Exemple |
|------|------------|---------|
| PATCH | Bugfixes, corrections mineures | 3.0.0 → 3.0.1 |
| MAJOR | Nouveau module, fonctionnalité majeure | 3.0.1 → 3.1.0 |

## Release Process

### 1. Préparer la Release

```bash
# Vérifier les modifications
git status
git diff

# S'assurer que les tests passent
cd backend && go test ./...
cd ../frontend && npm run build
```

### 2. Mettre à Jour les Fichiers de Version

| Fichier | Modification |
|---------|--------------|
| `CHANGELOG.md` | Ajouter la nouvelle version |
| `CLAUDE.md` | Header version + Notes de version |
| `frontend/src/pages/Settings.tsx` | Ligne ~966 : `v{VERSION}` |
| `README.md` | Header version |

### 3. Commit et Tag

```bash
# Commit les changements
git add -A
git commit -m "feat(vX.Y.Z): Description de la release"

# Créer le tag
git tag vX.Y.Z -m "vX.Y.Z - Description courte"

# Pousser
git push origin main
git push origin vX.Y.Z
```

### 4. Synchroniser le Repo Client

```bash
cd /opt/vigilanceX-SOC

# Mettre à jour README.md avec la nouvelle version
# Mettre à jour VERSION
# Mettre à jour wiki/Home.md

git add -A
git commit -m "feat(vX.Y.Z): Description"
git tag vX.Y.Z -m "vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

---

## Migrations v3.1.0

### ClickHouse Schema

Migration 006 : Extended XGS Fields

```sql
-- 27 nouvelles colonnes
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_serial_id String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_model String DEFAULT '';
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_name String DEFAULT '';
-- ... (voir docker/clickhouse/migrations/006_extended_xgs_fields.sql)
```

### Vector.toml

Nouveaux champs dans `prepare_events` :
- device_serial_id, device_model, device_name
- log_id, con_id, log_component, log_subtype
- tls_version, cipher_suite, sni
- threatfeed, malware, classification
- connection_name, remote_network, local_network, local_ip
- ep_uuid, ep_name, ep_ip, ep_health, hb_status
- sender, recipient, subject
- src_zone, dst_zone

### API Endpoints

Nouveaux endpoints Parser :
- GET `/api/v1/parser/stats`
- GET `/api/v1/parser/fields`
- GET `/api/v1/parser/rules`
- GET `/api/v1/parser/mitre`
- POST `/api/v1/parser/test`

---

## Checklist Release

- [ ] Tests backend passent (`go test ./...`)
- [ ] Build frontend OK (`npm run build`)
- [ ] CHANGELOG.md mis à jour
- [ ] CLAUDE.md mis à jour
- [ ] Settings.tsx version mise à jour
- [ ] README.md version mise à jour
- [ ] Commit effectué
- [ ] Tag créé sur vigilanceX
- [ ] vigilanceX-SOC synchronisé
- [ ] Tag créé sur vigilanceX-SOC
- [ ] GitHub shows latest tag correctly

---

## Historique des Versions

### v3.1.0 (2026-01-09)
- XGS Parser Engine
- 104 champs, 74 règles, 23 techniques MITRE
- Migration ClickHouse 006

### v3.0.1 (2026-01-09)
- UI improvements
- VPN sessions grouping
- Geoblocking top attackers

### v3.0.0 (2026-01-08)
- VX3 Secure Firewall Binding
- Grace Period 7 jours
