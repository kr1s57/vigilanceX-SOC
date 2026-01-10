# DEBUG SESSION - 2026-01-10

> **Status**: EN COURS
> **VPS**: vps-b3a1bf23 (51.210.4.99)
> **Version**: 3.1.5

---

## PROBLEMES CORRIGES

### 1. License API 404 (FIXE)
- **Symptome**: `/api/v1/license/status` retournait 404
- **Cause**: `proxy_pass http://backend/;` avec trailing slash strippait `/api`
- **Solution**: `docker/nginx/nginx.conf` ligne 102 - enlever le trailing slash
- **Fichier**: `docker/nginx/nginx.conf`
```nginx
# AVANT (bug)
proxy_pass http://backend/;
# APRES (fix)
proxy_pass http://backend;
```

### 2. Certificat TLS VigilanceKey (FIXE)
- **Symptome**: `x509: certificate relies on legacy Common Name field, use SANs instead`
- **Solution**: Regenere certificat avec SANs sur vigilancexkey (10.56.126.126)
```bash
# Certificat regenere dans /etc/nginx/ssl/vigilancekey.crt
# SANs: DNS:vigilancexkey.cloudcomputing.lu, DNS:localhost, IP:10.56.126.126, IP:127.0.0.1
```

### 3. Certificat auto-signe non reconnu (FIXE)
- **Symptome**: `x509: certificate signed by unknown authority`
- **Solution**: Ajout `LICENSE_INSECURE_SKIP_VERIFY=true` dans backend
- **Fichiers modifies**:
  - `backend/internal/license/client.go` - support de la variable
  - `docker-compose.yml` - ajout variable environnement
  - `.env` - `LICENSE_INSECURE_SKIP_VERIFY=true`

### 4. Prefixe VX3- manquant (FIXE)
- **Symptome**: `Invalid license key` sur activation
- **Solution**: Mise a jour des cles dans PostgreSQL VigilanceKey
```sql
ALTER TABLE licenses ALTER COLUMN license_key TYPE character varying(24);
UPDATE licenses SET license_key = 'VX3-' || license_key WHERE license_key NOT LIKE 'VX3-%';
```

### 5. WebSocket 400 Error (FIXE)
- **Symptome**: `'upgrade' token not found in 'Connection' header`
- **Cause**: Frontend appelle `/api/v1/ws` mais nginx n'avait que `/ws`
- **Solution**: Ajout bloc nginx pour `/api/v1/ws`
- **Fichier**: `config/nginx/nginx.conf` sur VPS
```nginx
# WebSocket endpoint via API path
location /api/v1/ws {
    proxy_pass http://backend/api/v1/ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 7d;
    proxy_send_timeout 7d;
    proxy_read_timeout 7d;
}
```

### 6. License activee (FIXE)
- **Cle**: `VX3-CBED-92BA-EBD6-121C`
- **Customer**: vpstest
- **Expires**: 2027-01-10
- **Status**: Active, 364 jours restants

---

## PROBLEME CORRIGE (v3.1.6)

### Dashboard page blanche / flash (FIXE)

**Symptomes**:
- Le dashboard apparait brievement (~0.5s) puis disparait
- Page de fond blanche reste affichee
- A chaque refresh, redemande authentification
- WebSocket se connecte puis se deconnecte immediatement
- Pas d'erreur JavaScript visible dans F12 Console
- "Provisional headers are shown" sur plusieurs requetes

**Ce qui fonctionne**:
- APIs backend repondent 200 OK
- WebSocket upgrade reussit (status 0, connexion etablie)
- CORS headers presents et corrects
- License active et reconnue
- Authentification reussit (token recu)

**Ce qui ne fonctionne pas**:
- React render persiste pas
- Session/token ne persiste pas entre refreshes
- WebSocket se deconnecte immediatement apres connexion

**Tests effectues**:
- [x] Hard refresh (Ctrl+Shift+R)
- [x] Navigation privee/incognito
- [x] Rollback frontend 3.1.4 -> meme probleme
- [x] Verification CORS -> OK
- [x] Verification logs backend -> pas d'erreur

**Hypotheses restantes**:
1. Probleme dans AuthContext qui logout automatiquement
2. Probleme de localStorage/sessionStorage
3. Erreur JavaScript silencieuse (try/catch qui avale l'erreur)
4. Probleme de routing React
5. Probleme avec une extension navigateur

**SOLUTION TROUVEE**:
- Erreur JS: `Cannot read properties of null (reading 'slice')`
- Cause: APIs retournaient `"data": null` au lieu de `"data": []`
- Fix: `backend/internal/adapter/repository/clickhouse/events_repo.go`
- Changement: `var slice []Type` → `slice := []Type{}`
- Version: v3.1.6

---

## VERSIONS ACTUELLES SUR VPS

```yaml
backend: ghcr.io/kr1s57/vigilancex-api:3.1.5
frontend: ghcr.io/kr1s57/vigilancex-frontend:3.1.4  # rollback
detect2ban: ghcr.io/kr1s57/vigilancex-detect2ban:3.1.5
```

---

## FICHIERS MODIFIES SUR VPS

```
~/vigilanceX-SOC/config/nginx/nginx.conf:
  - ligne 102: proxy_pass http://backend; (sans trailing slash)
  - Ajout bloc location /api/v1/ws

~/vigilanceX-SOC/deploy/.env:
  - LICENSE_KEY=VX3-CBED-92BA-EBD6-121C
  - LICENSE_INSECURE_SKIP_VERIFY=true

~/vigilanceX-SOC/deploy/docker-compose.yml:
  - Ajout LICENSE_INSECURE_SKIP_VERIFY dans backend environment
```

---

## COMMANDES UTILES POUR REPRENDRE

```bash
# Logs backend
docker logs vigilance_backend 2>&1 | tail -50

# Logs frontend
docker logs vigilance_frontend 2>&1 | tail -20

# Status services
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"

# Test API
curl -sk https://localhost/api/v1/license/status | jq .

# Test WebSocket
docker logs vigilance_backend 2>&1 | grep -i "ws"

# Restart all
docker compose -f ~/vigilanceX-SOC/deploy/docker-compose.yml down && docker compose -f ~/vigilanceX-SOC/deploy/docker-compose.yml up -d
```

---

## SERVEUR VIGILANCEKEY (10.56.126.126)

- Acces SSH: `ssh -i ~/.ssh/id_rsa_vgxtest root@10.56.126.126`
- Certificat SSL regenere avec SANs
- Cles licence mises a jour avec prefixe VX3-

---

*Derniere mise a jour: 2026-01-10 15:05 UTC*
