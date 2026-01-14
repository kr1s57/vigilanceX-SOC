# Debug Session - 2026-01-14

## Session Info
- **Date**: 2026-01-14
- **Version**: v3.53.104 → v3.53.105
- **Status**: Corrections appliquees - Tests en cours

---

## Issues Identified & Fixed

### 1. Attack Map - Date Picker Non Fonctionnel [FIXED]
**Symptome**: Le champ date est present mais selectionner une date ne change pas les attaques affichees.

**Cause Racine**: Le backend `GetGeoHeatmap` ignorait completement les parametres `start_time` et `end_time`.

**Solution**:
- Handler: Parse `start_time` et `end_time` depuis query params
- Service: Nouvelle methode `GetGeoHeatmapFilteredRange(ctx, startTime, endTime, attackTypes)`
- Repository: Nouvelle query avec `WHERE timestamp >= ? AND timestamp <= ?`

**Fichiers modifies**:
- `backend/internal/adapter/controller/http/handlers/events.go`
- `backend/internal/usecase/events/service.go`
- `backend/internal/adapter/repository/clickhouse/events_repo.go`

**Status**: OK - Teste et fonctionne

---

### 2. Bouton Disconnect API Non Visible [FIXED]
**Symptome**: Dans Settings > Integrations, le bouton "Disconnect" n'apparait pas dans le modal d'edition.

**Cause Racine**: `configApi.get()` ne retournait que les configs de `integrations.json`, pas les variables d'environnement. Les API keys des providers TI sont dans `.env`, pas dans le fichier JSON.

**Solution**: Modifier `GetConfig` pour aussi lire les variables d'environnement:
```go
// v3.53.105: Also check environment variables for plugins not in integrations.json
envPlugins := map[string][]string{
    "abuseipdb":   {"ABUSEIPDB_API_KEY"},
    "virustotal":  {"VIRUSTOTAL_API_KEY"},
    // ... autres providers
}
```

**Fichiers modifies**:
- `backend/internal/adapter/controller/http/handlers/config.go` (lignes 154-200)

**Status**: OK - Rebuild et deploy effectue

---

### 3. Attack History Non Visible dans IP Modal [FIXED]
**Symptome**: La section "Attack History" n'apparait jamais dans le modal IP.

**Cause Racine**: Le modal cherchait les events dans la table `events` avec `src_ip`, mais les attaques WAF sont dans la table `modsec_logs`. Les IPs affichees dans Attack Analyzer viennent de modsec_logs.

**Solution**: Ajouter une requete supplementaire pour `modsec_logs`:
```typescript
// Ajout dans Promise.all
modsecApi.getLogs({ src_ip: ip, limit: 50 })

// Nouveau state
const [wafHistory, setWafHistory] = useState<ModSecLog[]>([])

// Nouvelle section UI "WAF Attack History"
```

**Fichiers modifies**:
- `frontend/src/components/IPThreatModal.tsx`:
  - Import `modsecApi` et `ModSecLog`
  - Ajout state `wafHistory`
  - Ajout appel `modsecApi.getLogs` dans `Promise.all`
  - Nouvelle section "WAF Attack History" dans le rendu

**Status**: OK - Build passe, deploy effectue

---

## Tests a Effectuer

### Test 1: Attack Map Date Picker
- [x] Fonctionne correctement

### Test 2: Disconnect Button
1. [ ] Aller sur Settings > Integrations
2. [ ] Cliquer sur Edit pour une API configuree (ex: AbuseIPDB)
3. [ ] Verifier que le bouton "Disconnect" (rouge) est visible
4. [ ] Cliquer sur Disconnect et confirmer la suppression
5. [ ] Verifier que l'API est deconnectee (indicateur rouge)

### Test 3: WAF Attack History dans IP Modal
1. [ ] Cliquer sur une IP dans Attack Analyzer (ex: 5.48.159.190)
2. [ ] Verifier que la section "WAF Attack History" apparait
3. [ ] Verifier les details: attack_type, rule_msg, rule_id, severity, score
4. [ ] Tester avec une IP de modsec_logs qui a des detections

---

## Resume des Changements v3.53.105

| Composant | Fichier | Description |
|-----------|---------|-------------|
| Backend | config.go | GetConfig lit aussi les variables d'environnement |
| Backend | events.go | Parse start_time/end_time params (deja fait) |
| Frontend | IPThreatModal.tsx | Ajout section WAF Attack History depuis modsec_logs |

---

## Notes Techniques

### Plugins dans ENV vs integrations.json
```
integrations.json: smtp, crowdsec, crowdsec_blocklist
Variables ENV: abuseipdb, virustotal, alienvault, greynoise, criminalip, pulsedive, abusech, sophos_*
```

### Tables de donnees
```
events: Logs Firewall, IPS, ATP (src_ip interne souvent)
modsec_logs: Attaques WAF detectees par ModSecurity (src_ip externe)
```

---

### 4. CrowdSec Blocklist - Retention Logic 30 jours [FIXED]
**Symptome**: Pas de logique de retention - quand l'API est deconnectee, les donnees sont supprimees immediatement.

**Besoin**:
- Garder les IPs 30 jours apres deconnexion API
- Apres 30 jours sans reconnexion: supprimer IPs de la DB et objets CS_* du XGS
- Si reconnexion dans les 30 jours: reprendre cycle sync normal

**Solution**:
- Ajout constante `RetentionDuration = 30 * 24 * time.Hour`
- `UpdateConfig`: Ne plus appeler `Cleanup()` immediatement quand service desactive
- Nouvelle fonction `CheckRetention()`: Verifie si `last_sync` > 30 jours et service desactive → cleanup
- Nouvelle fonction `GetRetentionStatus()`: Retourne status retention pour UI
- `Cleanup()` modifie: Ajoute suppression des IPs dans groupe XGS
- `Initialize()`: Appel `CheckRetention()` au demarrage

**Fichiers modifies**:
- `backend/internal/usecase/crowdsec/blocklist_service.go`

**Status**: OK - Compile et logique implementee

---

### 5. Geoblocking Page - Layout Top 10 Countries [FIXED]
**Symptome**: La section Top 10 Countries prend toute la place, les autres categories sont peu visibles.

**Solution**:
- Section repliee par defaut (`topCountriesExpanded = false`)
- Preview des 3 premiers drapeaux quand repliee
- Layout compact en grille (5 colonnes) au lieu de liste verticale
- Padding et tailles reduits

**Fichiers modifies**:
- `frontend/src/pages/Geoblocking.tsx`

**Status**: OK - Build passe

---

## Resume des Changements v3.53.105 (Suite)

| Composant | Fichier | Description |
|-----------|---------|-------------|
| Backend | blocklist_service.go | Retention 30 jours quand API deconnectee |
| Backend | blocklist_service.go | CheckRetention() au demarrage |
| Backend | blocklist_service.go | Cleanup() supprime aussi les CS_* du XGS |
| Frontend | Geoblocking.tsx | Top 10 replie par defaut, layout grille compact |

---

### 6. CrowdSec Blocklist - Bouton Disconnect Manquant [FIXED]
**Symptome**: Le bouton "Disconnect" n'apparait pas dans le modal d'edition de CrowdSec Blocklist.

**Cause Racine**: La config CrowdSec Blocklist est stockee dans ClickHouse (pas dans `integrations.json` ni variables ENV). `isPluginConfigured()` retournait toujours false.

**Solution**: Modifier 4 fonctions dans `Settings.tsx` pour gerer le cas special `crowdsec_blocklist`:
- `isPluginConfigured()`: Check `crowdsecBlocklistConfig?.api_key`
- `handleEditPlugin()`: Fetch config via `crowdsecBlocklistApi.getConfig()`
- `handleSavePlugin()`: Save via `crowdsecBlocklistApi.updateConfig()` + test
- `handleDisconnectPlugin()`: Clear via `updateConfig({ api_key: '', enabled: false })`

**Fichiers modifies**:
- `frontend/src/pages/Settings.tsx`

**Status**: OK - Teste et fonctionne

---

### 7. Detect2Ban - Ban apres expiration immunité 24h [FIXED]
**Symptome**: Une IP avec immunité 24h est re-bannée immédiatement après l'expiration de l'immunité, car Detect2Ban compte les events qui ont eu lieu PENDANT la période d'immunité.

**Cause Racine**: La query Detect2Ban cherche les events des dernières N minutes (ex: 5min pour WAF). Quand l'immunité expire, les events de la période d'immunité sont comptés, ce qui déclenche un ban incorrect.

**Solution**: Ajouter une vérification post-immunité dans `handleMatch()`:
```go
// v3.53.106: Check if immunity just expired - only count events AFTER immunity ended
if existingBan.ImmuneUntil != nil && !existingBan.IsImmune() {
    immuneEnded := *existingBan.ImmuneUntil
    window, _ := time.ParseDuration(scenario.Aggregation.Window)

    // Si immunité a expiré dans la fenêtre du scenario, recompter
    if time.Since(immuneEnded) < window {
        eventsAfterImmunity, err := e.countEventsAfter(ctx, scenario, match.IP, immuneEnded)
        if eventsAfterImmunity < uint64(scenario.Aggregation.Threshold) {
            log.Printf("[DETECT2BAN] IP %s: only %d events after immunity, skipping", ...)
            return
        }
    }
}
```

**Nouvelle fonction** `countEventsAfter()`: Query ClickHouse pour compter uniquement les events APRÈS une date donnée.

**Fichiers modifies**:
- `backend/internal/usecase/detect2ban/engine.go`

**Status**: OK - Build passe, deploy effectué

---

## Resume des Changements v3.53.106

| Composant | Fichier | Description |
|-----------|---------|-------------|
| Backend | engine.go | D2B: Ne compte que les events APRES expiration immunité |
| Backend | engine.go | Nouvelle fonction `countEventsAfter()` |

---

*Session documentee par Claude Code - 2026-01-14 15:35*
