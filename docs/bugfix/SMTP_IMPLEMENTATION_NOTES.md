# SMTP Email Notifications - Implementation Notes

> **Date**: 2026-01-11
> **Version**: 3.3.100
> **Status**: Partiellement fonctionnel

---

## Ce qui fonctionne

### Configuration SMTP
- Configuration via Settings > Email Notifications > Edit SMTP Server
- Support STARTTLS (port 587) pour Office365
- Test de connexion SMTP fonctionnel
- Envoi d'email test reussi

### Authentification Office365
- AUTH LOGIN (requis par Office365) implementee
- L'ordre d'authentification: LOGIN d'abord, puis PLAIN en fallback
- STARTTLS negocie automatiquement

### Hot-reload SMTP
- Apres sauvegarde config SMTP, le client est recharge sans redemarrage
- Callback `SetSMTPReloadCallback` dans `config.go`
- Mise a jour via `notificationService.UpdateSMTPClient()`

---

## Problemes non resolus

### 1. Notification Settings ne persistent pas correctement

**Symptome**: Quand on active plusieurs toggles (daily + weekly + monthly), seul le dernier est conserve apres refresh.

**Cause identifiee**: Race condition - les requetes PUT concurrentes s'ecrasent mutuellement.

**Tentative de fix**:
- Ajout de `MergeAndUpdateSettings()` dans `service.go` avec mutex atomique
- Modification du handler pour utiliser cette fonction atomique
- **Mais**: Le code compile dans Docker semble ne pas inclure les modifications (le log montre toujours "Notification settings updated" au lieu de "[ATOMIC] Notification settings merged")

**Investigation necessaire**:
- Verifier le cache de build Go dans Docker
- Verifier si le context Docker utilise bien `/opt/vigilanceX/backend`
- Tester avec `go build` direct hors Docker

### 2. Champs SMTP vides lors de l'edition

**Symptome**: Quand on clique Edit sur SMTP apres avoir sauvegarde, les champs sont vides.

**Tentative de fix**:
- Modification de `handleEditPlugin` pour fetch les configs fraiches avant affichage
- Ajout de `configApi.get()` asynchrone dans la fonction

**Statut**: A verifier apres rebuild correct

---

## Configuration SMTP Office365 testee

```
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_FROM_EMAIL=<email_expediteur>
SMTP_USERNAME=<email_compte_office365>
SMTP_PASSWORD=<mot_de_passe>
SMTP_RECIPIENTS=<destinataires_separes_par_virgule>
```

### Points importants pour Office365:
1. **Utiliser STARTTLS** (pas SSL/TLS direct)
2. **Port 587** (pas 465)
3. **AUTH LOGIN** obligatoire (pas PLAIN)
4. Le FROM_EMAIL peut etre different du USERNAME

---

## Fichiers modifies

### Backend

| Fichier | Modification |
|---------|--------------|
| `smtp/client.go` | Support STARTTLS, AUTH LOGIN prioritaire |
| `notifications/service.go` | Ajout `MergeAndUpdateSettings()`, `UpdateSMTPClient()` |
| `handlers/notifications.go` | Handler utilise merge atomique |
| `handlers/config.go` | Callback hot-reload SMTP, merge configs |

### Frontend

| Fichier | Modification |
|---------|--------------|
| `Settings.tsx` | `handleEditPlugin` async avec fetch frais |
| `api.ts` | Types NotificationSettings |

### Docker

| Fichier | Modification |
|---------|--------------|
| `docker-compose.yml` | Variables SMTP, volume `backend_config` |

---

## Commandes de debug

```bash
# Verifier les logs SMTP
sudo docker compose logs -f backend | grep -i smtp

# Verifier le fichier de config
sudo docker compose exec backend cat /app/config/integrations.json

# Verifier les notification settings
sudo docker compose exec backend cat /app/config/notification_settings.json

# Tester la connexion SMTP manuellement
openssl s_client -starttls smtp -connect smtp.office365.com:587

# Verifier les methodes d'auth supportees
# Dans la sortie openssl, chercher "250-AUTH LOGIN XOAUTH2"
```

---

## Prochaines etapes

1. **Resoudre le probleme de build Docker** - Le code modifie n'est pas compile
2. **Tester la persistence des settings** apres fix du build
3. **Verifier le chargement des configs SMTP** dans le modal Edit
4. **Tester les rapports schedules** (daily, weekly, monthly)
5. **Tester les alertes temps-reel** (WAF, bans, critical)

---

## Notes techniques

### Structure du client SMTP

```go
// Dans smtp/client.go - Ordre d'authentification
1. Verifier les methodes supportees via EHLO
2. Si LOGIN disponible, essayer LOGIN d'abord
3. Si LOGIN echoue ou non dispo, essayer PLAIN
4. Si aucune methode ne fonctionne, retourner erreur
```

### Race condition dans les settings

```
Requete A: GET settings -> {daily:false, weekly:false}
Requete A: Merge {daily:true} -> {daily:true, weekly:false}
Requete B: GET settings -> {daily:false, weekly:false} (avant save A)
Requete B: Merge {weekly:true} -> {daily:false, weekly:true}
Requete A: SAVE -> {daily:true, weekly:false}
Requete B: SAVE -> {daily:false, weekly:true} (ecrase daily!)
```

**Solution implementee** (mais pas encore fonctionnelle dans Docker):
```go
func MergeAndUpdateSettings(updates map[string]interface{}) error {
    s.mu.Lock() // Mutex pour atomicite
    defer s.mu.Unlock()
    // Merge directement dans s.settings (pas de GET externe)
    // Save
}
```
