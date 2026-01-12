# VIGILANCE X - Policies de Bannissement

> **Version**: 3.50.101 | **Derniere mise a jour**: 2026-01-12
> **Statut**: En developpement - Ce document sert de reference pour l'implementation

---

## Vue d'Ensemble

Ce document decrit la strategie complete de bannissement des IPs malveillantes dans VIGILANCE X, incluant:
- Les sources de detection
- Les regles de bannissement progressif
- La synchronisation avec Sophos XGS
- Les processus d'unban et de reconciliation

---

## 1. Sources de Detection

### 1.1 Detect2Ban Engine

Moteur de detection automatique base sur des scenarios YAML.

| Scenario | Description | Seuil | Action |
|----------|-------------|-------|--------|
| `brute_force` | Tentatives de connexion echouees | 5 en 5min | Ban progressif |
| `waf_attacks` | Attaques WAF detectees | 10 en 1h | Ban progressif |

**Fichiers**: `backend/scenarios/*.yaml`

### 1.2 Threat Intelligence

11 providers de Threat Intel avec scoring agrege.

| Tier | Providers | Seuil Auto-Ban |
|------|-----------|----------------|
| Tier 1 (Free) | IPSum, OTX, ThreatFox, URLhaus, Shodan | Score > 80 |
| Tier 2 | AbuseIPDB, GreyNoise, CrowdSec | Score > 70 |
| Tier 3 | VirusTotal, CriminalIP, Pulsedive | Score > 60 |

### 1.3 Ban Manuel

L'operateur peut bannir manuellement depuis:
- Page Active Bans (bouton "Add Ban")
- IPThreatModal (bouton "Ban IP")
- WAF Explorer (bouton "Ban" sur chaque ligne)
- Attacks Analyzer (bouton "Ban" dans les modals)

---

## 2. Bannissement Progressif

### 2.1 Regles de Duree

Le systeme applique un bannissement progressif base sur le nombre de recidives:

| Ban Count | Duree | Status |
|-----------|-------|--------|
| 1 | 1 heure | `active` |
| 2 | 4 heures | `active` |
| 3 | 24 heures | `active` |
| 4+ | Permanent | `permanent` |

**Code source**: `backend/internal/usecase/bans/service.go` - fonction `calculateBanDuration()`

```go
func calculateBanDuration(banCount int) time.Duration {
    switch banCount {
    case 1:
        return 1 * time.Hour
    case 2:
        return 4 * time.Hour
    case 3:
        return 24 * time.Hour
    default:
        return 0 // Permanent
    }
}
```

### 2.2 Statuts de Ban

| Status | Description |
|--------|-------------|
| `active` | Ban temporaire avec expiration |
| `permanent` | Ban definitif (ban_count >= 4) |
| `expired` | Ban expire ou annule |

### 2.3 Recidivistes

Une IP est consideree "recidiviste" si `ban_count >= 2`.

---

## 3. Synchronisation Sophos XGS

### 3.1 Configuration

| Variable | Description | Defaut |
|----------|-------------|--------|
| `SOPHOS_HOST` | IP du firewall XGS | - |
| `SOPHOS_PORT` | Port API XML | 4444 |
| `SOPHOS_USER` | Utilisateur API | api_service_soc |
| `SOPHOS_PASSWORD` | Mot de passe | - |
| `SOPHOS_BAN_GROUP` | Groupe de blocklist | grp_SOC-BannedIP |

### 3.2 Processus de Ban vers XGS

Quand une IP est bannie dans VIGILANCE X:

1. **Creation du host**: `bannedIP_x.x.x.x` (IPHost)
2. **Ajout au groupe**: Mise a jour de `grp_SOC-BannedIP` (IPHostGroup)
3. **Marquage sync**: `synced_xgs = true` dans la DB

```
[VIGILANCE X] Ban IP 1.2.3.4
       |
       v
[Sophos API] POST Set/IPHost (add) name="bannedIP_1.2.3.4"
       |
       v
[Sophos API] POST Set/IPHostGroup (update) -> add to HostList
       |
       v
[VIGILANCE X] Update synced_xgs = true
```

### 3.3 Processus d'Unban vers XGS

Quand une IP est unbannie dans VIGILANCE X:

1. **Retrait du groupe**: Mise a jour de `grp_SOC-BannedIP` sans le host
2. **Suppression du host**: Remove `bannedIP_x.x.x.x`

```
[VIGILANCE X] Unban IP 1.2.3.4
       |
       v
[Sophos API] GET IPHostGroup -> current hosts
       |
       v
[Sophos API] POST Set/IPHostGroup (update) -> remove from HostList
       |
       v
[Sophos API] POST Remove/IPHost name="bannedIP_1.2.3.4"
```

### 3.4 Sync Bidirectionnel (Reconciliation)

Le bouton "Sync XGS" execute 3 phases:

| Phase | Action | Description |
|-------|--------|-------------|
| 1. Push | VGX → XGS | Envoie les bans actifs non synces vers XGS |
| 2. Import | XGS → VGX | Importe les IPs presentes dans XGS mais pas dans VGX |
| 3. Reconcile | XGS → VGX | Unban les IPs retirees directement de XGS |

**Reconciliation**: Si une IP est marquee `synced_xgs=true` mais n'est plus dans le groupe XGS, elle est automatiquement passee en `expired` avec la raison "Unbanned by XGS".

---

## 4. Protection des Reseaux Locaux

### 4.1 IPs Protegees

Les reseaux suivants ne peuvent PAS etre bannis:

| Reseau | Description |
|--------|-------------|
| 10.0.0.0/8 | Reseau prive classe A |
| 172.16.0.0/12 | Reseau prive classe B |
| 192.168.0.0/16 | Reseau prive classe C |
| 127.0.0.0/8 | Loopback |

**Code source**: `backend/internal/usecase/bans/service.go` - fonction `isProtectedIP()`

### 4.2 Whitelist

Types de whitelist disponibles:

| Type | Comportement |
|------|--------------|
| `hard` | Bypass complet, unban si actuellement banni |
| `soft` | Reduction de score (configurable 0-100%) |
| `monitor` | Logging uniquement, pas d'action |

---

## 5. Interface Utilisateur

### 5.1 Page Active Bans

| Element | Fonction |
|---------|----------|
| Stats Cards | Cliquables, affichent modal avec IPs filtrees |
| Tableau | Liste des bans actifs avec actions |
| Bouton "Add Ban" | Bannissement manuel |
| Bouton "Sync XGS" | Synchronisation bidirectionnelle |
| Bouton D2B | Toggle Detect2Ban engine |

### 5.2 IPThreatModal

| Element | Fonction |
|---------|----------|
| Badge "Banned/Permanent Ban" | Statut de ban visible |
| Bouton "Ban IP" | Bannissement rapide |
| Score agrege | Information Threat Intel |

---

## 6. Base de Donnees

### 6.1 Tables Principales

```sql
-- Statut actuel des bans
ip_ban_status (
    ip IPv4,
    status String,        -- active, permanent, expired
    ban_count UInt32,
    reason String,
    expires_at DateTime,
    synced_xgs UInt8,
    created_at DateTime,
    updated_at DateTime
)

-- Historique des actions
ip_ban_history (
    ip IPv4,
    action String,        -- ban, unban, extend
    reason String,
    source String,        -- manual, detect2ban, threat_intel, xgs_reconcile
    performed_by String,
    synced_xgs UInt8,
    created_at DateTime
)
```

---

## 7. Logs et Monitoring

### 7.1 Tags de Log

| Tag | Description |
|-----|-------------|
| `[BAN]` | Action de bannissement |
| `[SYNC]` | Synchronisation XGS |
| `[DETECT2BAN]` | Detection automatique |
| `[ERROR]` | Erreur de sync/ban |
| `[WARN]` | Avertissement |

### 7.2 Exemples de Logs

```
[BAN] Progressive ban for IP 1.2.3.4: 4h0m0s (ban count: 2)
[BAN] Permanent ban for IP 1.2.3.4 (ban count: 5)
[SYNC] Ban synced to XGS: 1.2.3.4
[SYNC] IP removed from XGS blocklist: 1.2.3.4
[SYNC] Reconciliation: IP 1.2.3.4 removed from XGS, unbanning in VIGILANCE X
```

---

## 8. Points d'Attention (Bugs Connus/Resolus)

### 8.1 API Sophos XGS

| Probleme | Solution |
|----------|----------|
| GET IPHostGroup retourne TOUS les groupes | Filtrer par nom cote code Go |
| UPDATE IPHost ignore HostGroupList | Modifier IPHostGroup.HostList directement |
| Remove IPHost ne retire pas du groupe | Retirer du groupe AVANT de supprimer le host |

### 8.2 References

- `docs/BUGFIX-KB.md` - BUG-007, BUG-008, BUG-009

---

## 9. Roadmap / TODO

- [ ] Configuration des seuils de ban progressif via UI
- [ ] Personnalisation des durees de ban
- [ ] Notifications email sur ban/unban
- [ ] Dashboard de statistiques de ban
- [ ] Export des bans en CSV
- [ ] API webhook pour integration externe
- [ ] Scenarios Detect2Ban additionnels

---

## 10. Fichiers Cles

| Fichier | Description |
|---------|-------------|
| `backend/internal/usecase/bans/service.go` | Logique metier principale |
| `backend/internal/adapter/external/sophos/client.go` | Client API Sophos XGS |
| `backend/internal/usecase/detect2ban/engine.go` | Moteur Detect2Ban |
| `backend/scenarios/*.yaml` | Scenarios de detection |
| `frontend/src/pages/ActiveBans.tsx` | Page Active Bans |
| `frontend/src/components/IPThreatModal.tsx` | Modal Threat Intel |

---

*Document maintenu par Claude Code - Reference pour le module de bannissement*
