# Contrats API - REST Endpoints

> **Généré**: 2026-01-28 | **Version**: 3.58.108

---

## Vue d'Ensemble

L'API VIGILANCE X expose **100+ endpoints REST** organisés par domaine.

**Base URL**: `/api/v1`

**Authentification**: JWT Bearer Token (sauf routes publiques)

**Rate Limiting**: 10000 req/min par IP

---

## Routes Publiques

### Authentification

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/auth/login` | Connexion utilisateur |
| `POST` | `/auth/logout` | Déconnexion |
| `GET` | `/health` | Health check |

### Licence

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/license/status` | Statut licence |
| `POST` | `/license/activate` | Activation (rate limited: 5/h) |
| `POST` | `/license/fresh-deploy` | Premier déploiement (rate limited: 5/h) |

---

## Routes Authentifiées (Free)

### Événements

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/events` | Liste événements (paginé, filtrable) |
| `GET` | `/events/{id}` | Détail événement |
| `GET` | `/events/timeline` | Timeline agrégée |
| `GET` | `/events/hostnames` | Liste hostnames |

**Paramètres de requête `/events`:**
```
?limit=50
&offset=0
&log_type=WAF|IPS|ATP
&severity=critical|high|medium|low
&src_ip=x.x.x.x
&hostname=example.com
&start_time=2026-01-01T00:00:00Z
&end_time=2026-01-28T23:59:59Z
&search=keyword
```

### Statistiques

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/stats/overview` | Stats globales |
| `GET` | `/stats/top-attackers` | Top IPs attaquantes |
| `GET` | `/stats/top-targets` | Cibles les plus visées |
| `GET` | `/stats/zone-traffic` | Trafic inter-zones XGS |

### Statut

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/status/syslog` | Statut ingestion Syslog |
| `GET` | `/alerts/critical` | Alertes critiques |
| `GET` | `/modsec/test` | Test connexion ModSec |
| `GET` | `/detect2ban/status` | Statut moteur D2B |

### WebSocket

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/ws` | Connexion WebSocket temps réel |

---

## Routes Licenciées

### Menaces (Threat Intelligence)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/threats` | Top menaces |
| `GET` | `/threats/stats` | Statistiques TI |
| `GET` | `/threats/providers` | Providers configurés |
| `GET` | `/threats/check/{ip}` | Check IP live (cascade TI) |
| `GET` | `/threats/score/{ip}` | Score stocké |
| `GET` | `/threats/risk/{ip}` | Évaluation risque combinée |
| `GET` | `/threats/level/{level}` | Menaces par niveau |
| `POST` | `/threats/batch` | Check multiple IPs |
| `POST` | `/threats/cache/clear` | Vider cache TI |

### Bans

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/bans` | Liste bans actifs |
| `GET` | `/bans/stats` | Statistiques bans |
| `GET` | `/bans/xgs-status` | Statut sync XGS |
| `POST` | `/bans` | Créer ban |
| `POST` | `/bans/sync` | Sync vers XGS |
| `GET` | `/bans/{ip}` | Détail ban |
| `DELETE` | `/bans/{ip}` | Unban |
| `POST` | `/bans/{ip}/extend` | Prolonger ban |
| `POST` | `/bans/{ip}/permanent` | Rendre permanent |
| `GET` | `/bans/{ip}/history` | Historique IP |

**Body POST `/bans`:**
```json
{
  "ip": "192.168.1.100",
  "reason": "Manual ban - suspicious activity",
  "duration_days": 7,
  "permanent": false
}
```

### Whitelist

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/whitelist` | Liste whitelist |
| `GET` | `/whitelist/stats` | Statistiques |
| `GET` | `/whitelist/check/{ip}` | Vérifier IP |
| `POST` | `/whitelist` | Ajouter entrée |
| `PUT` | `/whitelist/{ip}` | Modifier entrée |
| `DELETE` | `/whitelist/{ip}` | Supprimer entrée |

**Body POST `/whitelist`:**
```json
{
  "ip": "10.0.0.0",
  "cidr_mask": 24,
  "type": "hard|soft|monitor",
  "reason": "Internal network",
  "score_modifier": 50,
  "alert_only": true,
  "duration_days": null,
  "tags": ["internal", "trusted"]
}
```

### Detect2Ban

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/detect2ban/status` | Statut moteur |
| `POST` | `/detect2ban/enable` | Activer |
| `POST` | `/detect2ban/disable` | Désactiver |
| `POST` | `/detect2ban/toggle` | Basculer |
| `GET` | `/detect2ban/scenarios` | Scénarios chargés |

### Pending Bans (D2B v2)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/pending-bans` | Liste pending |
| `GET` | `/pending-bans/stats` | Statistiques |
| `GET` | `/pending-bans/ip/{ip}` | Détail par IP |
| `POST` | `/pending-bans/{id}/approve` | Approuver ban |
| `POST` | `/pending-bans/{id}/reject` | Rejeter |

### GeoZone (D2B v2)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/geozone/config` | Configuration |
| `PUT` | `/geozone/config` | Mettre à jour |
| `GET` | `/geozone/classify` | Classifier pays |
| `GET` | `/geozone/countries` | Liste pays |
| `POST` | `/geozone/countries/authorized` | Ajouter autorisé |
| `DELETE` | `/geozone/countries/authorized` | Retirer autorisé |
| `POST` | `/geozone/countries/hostile` | Ajouter hostile |

### Geoblocking

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/geoblocking/rules` | Liste règles |
| `POST` | `/geoblocking/rules` | Créer règle |
| `PUT` | `/geoblocking/rules/{id}` | Modifier règle |
| `DELETE` | `/geoblocking/rules/{id}` | Supprimer règle |
| `GET` | `/geoblocking/stats` | Statistiques |
| `GET` | `/geoblocking/check/{ip}` | Vérifier IP |
| `GET` | `/geoblocking/lookup/{ip}` | Lookup GeoIP |
| `GET` | `/geoblocking/countries/blocked` | Pays bloqués |
| `GET` | `/geoblocking/countries/watched` | Pays surveillés |

### ModSec

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/modsec/stats` | Statistiques |
| `POST` | `/modsec/sync` | Forcer sync SSH |
| `GET` | `/modsec/test` | Test connexion |
| `GET` | `/modsec/logs` | Logs bruts |
| `GET` | `/modsec/logs/grouped` | Logs groupés par unique_id |
| `GET` | `/modsec/hostnames` | Hostnames ciblés |
| `GET` | `/modsec/rules/stats` | Stats par rule_id |
| `GET` | `/modsec/attacks/stats` | Stats par type attaque |
| `GET` | `/modsec/watcher` | Statut WAF Watcher |

### Blocklists

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/blocklists/stats` | Statistiques |
| `GET` | `/blocklists/feeds` | Feeds disponibles |
| `GET` | `/blocklists/feeds/configured` | Feeds configurés |
| `POST` | `/blocklists/sync` | Sync tous feeds |
| `POST` | `/blocklists/feeds/{name}/sync` | Sync feed spécifique |
| `GET` | `/blocklists/check/{ip}` | Vérifier IP |
| `GET` | `/blocklists/high-risk` | IPs haut risque |

### CrowdSec Blocklist

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/crowdsec/blocklist/config` | Configuration |
| `PUT` | `/crowdsec/blocklist/config` | Mettre à jour |
| `POST` | `/crowdsec/blocklist/test` | Test connexion |
| `GET` | `/crowdsec/blocklist/lists` | Blocklists disponibles |
| `GET` | `/crowdsec/blocklist/status` | Statut sync |
| `GET` | `/crowdsec/blocklist/history` | Historique sync |
| `GET` | `/crowdsec/blocklist/ips` | IPs stockées |
| `GET` | `/crowdsec/blocklist/ips/list` | IPs paginées |
| `GET` | `/crowdsec/blocklist/summary` | Résumé blocklists |
| `GET` | `/crowdsec/blocklist/countries` | Pays uniques |
| `POST` | `/crowdsec/blocklist/enrich` | Enrichir GeoIP |
| `POST` | `/crowdsec/blocklist/sync` | Sync toutes |

### Neural-Sync (VigilanceKey Proxy)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/neural-sync/config` | Configuration |
| `PUT` | `/neural-sync/config` | Mettre à jour |
| `POST` | `/neural-sync/test` | Test connexion |
| `GET` | `/neural-sync/status` | Statut |
| `GET` | `/neural-sync/blocklists` | Blocklists via proxy |
| `GET` | `/neural-sync/ips` | IPs via proxy |

### Vigimail

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/vigimail/config` | Configuration |
| `PUT` | `/vigimail/config` | Mettre à jour |
| `GET` | `/vigimail/status` | Statut |
| `GET` | `/vigimail/stats` | Statistiques |
| `GET` | `/vigimail/domains` | Liste domaines |
| `POST` | `/vigimail/domains` | Ajouter domaine |
| `DELETE` | `/vigimail/domains/{domain}` | Supprimer |
| `GET` | `/vigimail/domains/{domain}/dns` | DNS checks |
| `POST` | `/vigimail/domains/{domain}/check` | Vérifier domaine |
| `GET` | `/vigimail/emails` | Liste emails |
| `POST` | `/vigimail/emails` | Ajouter email |
| `DELETE` | `/vigimail/emails/{email}` | Supprimer |
| `GET` | `/vigimail/emails/{email}/leaks` | Fuites détectées |
| `POST` | `/vigimail/emails/{email}/check` | Vérifier email |
| `POST` | `/vigimail/test-hibp` | Test API HIBP |
| `POST` | `/vigimail/check-all` | Vérifier tout |

### Track IP

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/track-ip` | Recherche forensique |

**Paramètres:**
```
?query=192.168.1.100
&type=ip|hostname
&days=30
```

### WAF Servers

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/waf-servers` | Liste serveurs |
| `GET` | `/waf-servers/hostnames` | Hostnames |
| `POST` | `/waf-servers` | Créer serveur |
| `GET` | `/waf-servers/{hostname}` | Détail |
| `PUT` | `/waf-servers/{hostname}` | Modifier |
| `DELETE` | `/waf-servers/{hostname}` | Supprimer |
| `GET` | `/waf-servers/{hostname}/check-policy` | Vérifier politique |

### Reports

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/reports/stats` | Stats DB |
| `GET` | `/reports/generate` | Générer rapport |
| `POST` | `/reports/generate` | Générer avec options |
| `GET` | `/reports/preview` | Prévisualiser |
| `POST` | `/reports/send-email` | Envoyer par email |

### Notifications

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/notifications/settings` | Paramètres |
| `PUT` | `/notifications/settings` | Modifier |
| `POST` | `/notifications/test-email` | Envoyer test |
| `GET` | `/notifications/status` | Statut SMTP |
| `GET` | `/notifications/smtp-config` | Config SMTP |
| `PUT` | `/notifications/smtp-config` | Modifier SMTP |

### Retention

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/retention/settings` | Paramètres |
| `PUT` | `/retention/settings` | Modifier |
| `GET` | `/retention/status` | Statut |
| `GET` | `/retention/storage` | Stats stockage |
| `POST` | `/retention/cleanup` | Forcer nettoyage |

### Integrations

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/integrations/providers` | Tous providers |
| `GET` | `/integrations/providers/{id}` | Détail provider |
| `PUT` | `/integrations/providers/{id}` | Modifier |

### Config

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/config` | Configuration globale |
| `POST` | `/config/test` | Tester config |
| `POST` | `/config/save` | Sauvegarder |
| `DELETE` | `/config/{plugin_id}` | Réinitialiser plugin |
| `GET` | `/config/system-whitelist` | Whitelist système |
| `POST` | `/config/system-whitelist` | Ajouter |
| `PUT` | `/config/system-whitelist/{id}` | Modifier |
| `DELETE` | `/config/system-whitelist/{id}` | Supprimer |

### Parser

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/parser/stats` | Statistiques XGS Parser |
| `GET` | `/parser/fields` | Champs supportés |
| `GET` | `/parser/rules` | Règles chargées |
| `GET` | `/parser/mitre` | Couverture MITRE |
| `POST` | `/parser/test` | Tester parsing |

---

## Routes Admin Only

### Users

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/users` | Liste utilisateurs |
| `POST` | `/users` | Créer utilisateur |
| `GET` | `/users/{id}` | Détail |
| `PUT` | `/users/{id}` | Modifier |
| `DELETE` | `/users/{id}` | Supprimer |
| `POST` | `/users/{id}/reset-password` | Reset password |

### Console

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/console/execute` | Exécuter commande |
| `GET` | `/console/logs` | Logs Docker |
| `GET` | `/console/logs/stream` | Stream logs |
| `GET` | `/console/services` | Services Docker |

### System

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/system/version` | Version actuelle |
| `GET` | `/system/stats` | Stats système |
| `POST` | `/system/update` | Déclencher update (admin) |
| `GET` | `/system/update/status` | Statut update (admin) |

---

## Codes de Réponse

| Code | Signification |
|------|---------------|
| `200` | Succès |
| `201` | Créé |
| `204` | Supprimé (no content) |
| `400` | Bad Request |
| `401` | Non authentifié |
| `403` | Non autorisé (licence/rôle) |
| `404` | Non trouvé |
| `429` | Rate limited |
| `500` | Erreur serveur |
| `501` | Not implemented |

---

## Format de Réponse

### Succès

```json
{
  "data": { ... },
  "meta": {
    "total": 100,
    "limit": 50,
    "offset": 0
  }
}
```

### Erreur

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "IP address is invalid",
    "details": { ... }
  }
}
```

---

*Documentation générée par le workflow document-project*
