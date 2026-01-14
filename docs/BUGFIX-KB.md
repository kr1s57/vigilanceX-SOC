# VIGILANCE X - Bug Fix Knowledge Base

> Base de connaissances des bugs corriges et patterns de resolution

---

## Index des Bugs

| ID | Date | Version | Severite | Composant | Description |
|----|------|---------|----------|-----------|-------------|
| BUG-001 | 2026-01-14 | 3.53.105 | Medium | Backend | Attack Map date picker non fonctionnel |
| BUG-002 | 2026-01-14 | 3.53.105 | Low | Frontend | Bouton Disconnect API non visible |
| BUG-003 | 2026-01-14 | 3.53.105 | Medium | Frontend | Attack History non visible dans IP modal |

---

## [BUG-001] Attack Map Date Picker Non Fonctionnel

**Date**: 2026-01-14
**Version**: v3.53.105
**Severite**: Medium
**Composant**: Backend

### Symptome
Le date picker dans Attack Map ne filtre pas les attaques. Selectionner n'importe quelle date affiche toujours les memes flux d'attaques.

### Cause Racine
Le backend `GetGeoHeatmap` handler ignorait les parametres `start_time` et `end_time` envoyes par le frontend. Il ne lisait que `period` pour calculer le time range.

```go
// AVANT - Ignore start_time/end_time
func (h *EventsHandler) GetGeoHeatmap(w http.ResponseWriter, r *http.Request) {
    period := r.URL.Query().Get("period")
    // start_time et end_time non lus!
    heatmap, err := h.service.GetGeoHeatmapFiltered(ctx, period, attackTypes)
}
```

### Solution
Ajouter le parsing des parametres temporels et une nouvelle methode service/repo:

```go
// APRES - Parse et utilise start_time/end_time
var startTime, endTime time.Time
if st := r.URL.Query().Get("start_time"); st != "" {
    startTime, _ = time.Parse(time.RFC3339, st)
}
if et := r.URL.Query().Get("end_time"); et != "" {
    endTime, _ = time.Parse(time.RFC3339, et)
}

if !startTime.IsZero() && !endTime.IsZero() {
    heatmap, err = h.service.GetGeoHeatmapFilteredRange(ctx, startTime, endTime, attackTypes)
} else {
    heatmap, err = h.service.GetGeoHeatmapFiltered(ctx, period, attackTypes)
}
```

### Fichiers Affectes
- `backend/internal/adapter/controller/http/handlers/events.go`
- `backend/internal/usecase/events/service.go`
- `backend/internal/adapter/repository/clickhouse/events_repo.go`

### Lecons Apprises
- Toujours verifier que le backend lit TOUS les parametres que le frontend envoie
- Ajouter des logs de debug pour tracer les params recus

### Tags
`#backend` `#api` `#clickhouse` `#date-filtering`

---

## [BUG-002] Bouton Disconnect API Non Visible

**Date**: 2026-01-14
**Version**: v3.53.105
**Severite**: Low
**Composant**: Frontend

### Symptome
Dans Settings > Integrations, apres avoir configure une API, le bouton "Disconnect" n'apparait pas dans le modal d'edition.

### Cause Racine
Race condition dans `handleEditPlugin`:

```javascript
// AVANT - Modal s'ouvre AVANT le chargement des configs
const handleEditPlugin = async (pluginId: string) => {
    setEditingPlugin(plugin)  // Modal s'ouvre!
    const freshConfigs = await configApi.get()  // Async - trop tard
    setSavedConfigs(freshConfigs)
}
```

Le bouton Disconnect depend de `isPluginConfigured(editingPlugin.id)` qui verifie `savedConfigs`. Au premier rendu du modal, `savedConfigs` n'a pas encore les donnees fraiches.

### Solution
Charger les configs AVANT d'ouvrir le modal:

```javascript
// APRES - Configs chargees PUIS modal ouvert
const handleEditPlugin = async (pluginId: string) => {
    const freshConfigs = await configApi.get()  // D'abord charger
    setSavedConfigs(freshConfigs)
    setPluginFormData(initialData)
    setEditingPlugin(plugin)  // PUIS ouvrir le modal
}
```

### Fichiers Affectes
- `frontend/src/pages/Settings.tsx`

### Lecons Apprises
- Attention aux race conditions avec les modals et le state async
- Pattern: Charger les donnees AVANT d'ouvrir un modal qui en depend

### Tags
`#frontend` `#react` `#state-management` `#race-condition`

---

## [BUG-003] Attack History Non Visible dans IP Modal

**Date**: 2026-01-14
**Version**: v3.53.105
**Severite**: Medium
**Composant**: Frontend

### Symptome
La section "Attack History" n'apparait jamais dans le modal IP Threat, meme pour des IPs avec des events WAF.

### Cause Racine
Mauvaise structure conditionnelle JSX:

```jsx
// AVANT - Attack History DANS le bloc score
{score ? (
    <>
        {/* Score sections */}
        {banHistory.length > 0 && (...)}
        {attackHistory.length > 0 && (...)}  // Ne s'affiche que si score!
    </>
) : (
    // Error view sans Attack History
)}
```

Si l'IP n'a pas de threat score, tout le bloc (incluant Attack/Ban History) ne s'affiche pas.

### Solution
Restructurer pour que Attack/Ban History soient independants du score:

```jsx
// APRES - Attack History HORS du bloc score
{loading ? (
    // Loading
) : (
    <>
        {error && !score && (...)}  // Error avec bouton
        {score && (...)}  // Score sections uniquement
        {banHistory.length > 0 && (...)}  // TOUJOURS si data
        {attackHistory.length > 0 && (...)}  // TOUJOURS si data
        <ExternalLinks />
    </>
)}
```

### Fichiers Affectes
- `frontend/src/components/IPThreatModal.tsx`

### Lecons Apprises
- Verifier que les sections UI independantes ne sont pas imbriquees dans des conditions non liees
- Pattern: Separer les blocs conditionnels pour chaque piece de data

### Tags
`#frontend` `#react` `#jsx` `#conditional-rendering`

---

## Patterns Recurrents

### 1. Race Condition State + Modal
**Probleme**: Ouvrir un modal qui depend de donnees async
**Solution**: Toujours `await` les donnees AVANT `setModalOpen(true)`

### 2. Params API Non Lus
**Probleme**: Frontend envoie des params que le backend ignore
**Solution**: Verifier handler lit tous les params avec `r.URL.Query().Get()`

### 3. Sections UI Imbriquees
**Probleme**: Section A cachee car dans le bloc conditionnel de Section B
**Solution**: Extraire les sections independantes hors des blocs conditionnels

### 4. ClickHouse Time Filtering
**Pattern**: Utiliser `WHERE timestamp >= ? AND timestamp <= ?` avec `time.Time`
**Note**: ClickHouse supporte bien les comparaisons temporelles directes

---

*Derniere mise a jour: 2026-01-14*
