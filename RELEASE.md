# Guide de Release VIGILANCE X

> **Version**: 3.0.0 | **Derniere mise a jour**: 2026-01-08

Ce document decrit le processus de release pour VIGILANCE X.

---

## Architecture de Distribution

```
/opt/vigilanceX/                    Code source complet (prive)
    │
    ├── backend/                    API Go
    ├── frontend/                   React SPA
    ├── client-dist/                Template structure client
    └── .github/workflows/          Pipeline CI/CD
            │
            │ git push tag v*.*.*
            ▼
    ┌───────────────────────────────────────────────────┐
    │              GitHub Actions Pipeline               │
    │                                                    │
    │  1. Build Backend (Garble + UPX)                  │
    │  2. Build Frontend (Terser)                       │
    │  3. Push Docker Images (ghcr.io)                  │
    │  4. Sign Images (Cosign)                          │
    │  5. Update vigilanceX-SOC                         │
    │  6. Create GitHub Release                         │
    └───────────────────────────────────────────────────┘
            │
            ▼
    vigilanceX-SOC/                 Repository client (prive)
    ├── deploy/docker-compose.yml   Images versionnees
    ├── vigilance.sh                Script de gestion
    ├── config/                     Configuration
    └── wiki/                       Documentation
```

---

## Creer une Nouvelle Release

### Etape 1: Developper et Tester

```bash
cd /opt/vigilanceX

# Faire vos modifications
# ... editer les fichiers ...

# Tester localement
cd backend && go build ./cmd/api && cd ..
cd frontend && npm run build && cd ..
```

### Etape 2: Commit et Push

```bash
git add .
git commit -m "feat: description des changements"
git push origin main
```

### Etape 3: Creer le Tag de Release

```bash
# Format: vMAJOR.MINOR.PATCH
git tag -a v3.1.0 -m "Release v3.1.0 - Description courte"
git push origin v3.1.0
```

### Etape 4: Surveiller le Pipeline

```bash
# Voir le statut du pipeline
gh run list --repo kr1s57/vigilanceX --limit 1

# Suivre en temps reel
gh run watch --repo kr1s57/vigilanceX
```

Le pipeline prend environ **7-10 minutes**.

---

## Ce que le Pipeline Fait Automatiquement

| Etape | Action | Resultat |
|-------|--------|----------|
| **build-backend** | Compile avec Garble v0.12.1 + UPX | Binaires obfusques (~5MB) |
| **build-frontend** | Build avec Terser | JS minifie sans console.log |
| **docker-build** | Cree les images Docker | Push vers ghcr.io |
| **sign-images** | Signe avec Cosign (OIDC) | Images verifiables |
| **update-client-repo** | Met a jour docker-compose.yml | vigilanceX-SOC synchronise |
| **create-release** | Cree la GitHub Release | Binaires + checksums |

---

## Versioning (Semantic Versioning)

| Changement | Increment | Exemple |
|------------|-----------|---------|
| Bugfix, correction mineure | PATCH | 3.0.0 → 3.0.1 |
| Nouvelle fonctionnalite | MINOR | 3.0.1 → 3.1.0 |
| Breaking change, refonte majeure | MAJOR | 3.1.0 → 4.0.0 |

---

## Donner Acces a un Client

### 1. Acces au Repository vigilanceX-SOC

```bash
# Via GitHub CLI
gh repo add-collaborator kr1s57/vigilanceX-SOC CLIENT_USERNAME --permission read

# Ou via l'interface GitHub:
# Settings > Collaborators > Add people
```

### 2. Acces aux Images Docker (ghcr.io)

Les images sont privees. Le client a besoin d'un token pour les pull.

**Option A: Token personnel du client**
```bash
# Le client cree son propre token avec scope "read:packages"
# Puis se connecte:
echo "TOKEN" | docker login ghcr.io -u USERNAME --password-stdin
```

**Option B: Token de service (recommande)**
```bash
# Creer un token avec scope "read:packages" uniquement
# Le fournir au client de maniere securisee
```

### 3. Instructions pour le Client

Envoyer au client:
1. Invitation au repo vigilanceX-SOC
2. Token Docker pour ghcr.io
3. Lien vers la documentation: `https://github.com/kr1s57/vigilanceX-SOC/wiki`

---

## Mettre a Jour client-dist

Le dossier `client-dist/` contient le template initial. Pour mettre a jour:

### Modifier la Documentation (wiki/)

```bash
# Editer les fichiers wiki
nano client-dist/wiki/Configuration.md

# Commit
git add client-dist/
git commit -m "docs: mise a jour documentation client"
git push origin main
```

**Note**: Les changements dans `client-dist/` ne sont PAS automatiquement synchronises vers `vigilanceX-SOC`. Il faut les pousser manuellement:

```bash
# Copier vers le repo client
cp -r client-dist/* /tmp/vigilanceX-SOC/
cd /tmp/vigilanceX-SOC
git add . && git commit -m "docs: mise a jour" && git push
```

### Modifier docker-compose.yml

Le fichier `client-dist/deploy/docker-compose.yml` est le template. Le pipeline met a jour **uniquement les versions d'images** dans `vigilanceX-SOC`.

Pour des changements de structure (nouveaux services, volumes, etc.):
1. Modifier `client-dist/deploy/docker-compose.yml`
2. Pousser manuellement vers `vigilanceX-SOC`

---

## Troubleshooting

### Pipeline Echoue: "Garble version incompatible"

```bash
# Verifier la version de Garble dans le workflow
grep "garble@" .github/workflows/release.yml
# Doit etre: mvdan.cc/garble@v0.12.1 (compatible Go 1.22)
```

### Pipeline Echoue: "Terser not found"

```bash
# Verifier que terser est installe
cd frontend
npm list terser
# Si absent:
npm install --save-dev terser
git add package.json package-lock.json
git commit -m "fix: add terser dependency"
```

### Pipeline Echoue: "update-client-repo failed"

```bash
# Verifier le secret CLIENT_REPO_TOKEN
gh secret list --repo kr1s57/vigilanceX

# Regenerer si necessaire:
# 1. Creer un nouveau token sur GitHub (scope: repo)
# 2. Mettre a jour le secret:
gh secret set CLIENT_REPO_TOKEN --repo kr1s57/vigilanceX --body "NEW_TOKEN"
```

### Images Docker Non Accessibles

```bash
# Verifier l'authentification
docker login ghcr.io -u kr1s57

# Verifier que les images existent
gh api /user/packages/container/vigilancex-api/versions --jq '.[0].metadata.container.tags'
```

### Rollback d'une Version

```bash
# 1. Identifier la version precedente
gh release list --repo kr1s57/vigilanceX

# 2. Mettre a jour vigilanceX-SOC manuellement
cd /tmp/vigilanceX-SOC
sed -i 's/:3.1.0/:3.0.0/g' deploy/docker-compose.yml
git commit -am "rollback: v3.1.0 -> v3.0.0"
git push

# 3. Supprimer le tag problematique (optionnel)
git tag -d v3.1.0
git push origin :refs/tags/v3.1.0
```

---

## Checklist Pre-Release

- [ ] Code teste localement (`go build`, `npm run build`)
- [ ] Tests passes (`go test ./...`, `npm run test`)
- [ ] CHANGELOG.md mis a jour
- [ ] Version incrementee selon semantic versioning
- [ ] Commit message descriptif
- [ ] Tag annote avec description

---

## Checklist Post-Release

- [ ] Pipeline termine avec succes
- [ ] GitHub Release creee avec binaires
- [ ] Images Docker disponibles sur ghcr.io
- [ ] vigilanceX-SOC mis a jour
- [ ] Test de pull des images:
  ```bash
  docker pull ghcr.io/kr1s57/vigilancex-api:NEW_VERSION
  ```

---

## Contacts

- **Repository source**: https://github.com/kr1s57/vigilanceX
- **Repository client**: https://github.com/kr1s57/vigilanceX-SOC
- **Registry Docker**: ghcr.io/kr1s57/vigilancex-*

---

*Document maintenu par l'equipe VIGILANCE X*
