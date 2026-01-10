# VIGILANCE X - Bug Fix Knowledge Base

> **Purpose**: Documentation structurée des bugs rencontrés et leurs solutions pour exploitation future en KB.
> **Format**: Chaque bug suit un template standardisé pour faciliter la recherche et l'apprentissage.

---

## Template Bug Entry

```markdown
### [BUG-XXXX] Titre court du bug

**Date**: YYYY-MM-DD
**Version**: vX.Y.Z
**Sévérité**: Critical | High | Medium | Low
**Composant**: Frontend | Backend | Infrastructure
**Fichiers affectés**: Liste des fichiers modifiés

#### Symptôme
Description du comportement observé par l'utilisateur.

#### Cause Racine
Explication technique de pourquoi le bug se produit.

#### Solution
Description de la correction appliquée.

#### Code Avant/Après
\`\`\`typescript
// Avant
code problématique

// Après
code corrigé
\`\`\`

#### Leçons Apprises
- Point clé 1
- Point clé 2

#### Tags
`#composant` `#type-de-bug` `#technologie`
```

---

## Session: 2026-01-10 21:11

### [BUG-001] Dashboard time filter ne persiste pas après refresh

**Date**: 2026-01-10
**Version**: v3.2.100 → v3.2.101
**Sévérité**: Medium
**Composant**: Frontend
**Fichiers affectés**: `frontend/src/pages/Dashboard.tsx`

#### Symptôme
Sur le Dashboard, le filtre temps (1h, 7d, 24h) se réinitialise à 24h après refresh de page. L'utilisateur doit resélectionner son filtre à chaque actualisation.

#### Cause Racine
Le state du filtre temps est stocké uniquement en mémoire React (useState). Aucune persistance sessionStorage n'est implémentée.

#### Solution
Utiliser `sessionStorage` pour persister le filtre temps pendant la session navigateur. Le filtre se réinitialise à 24h uniquement lors d'une nouvelle connexion (nouveau tab/fenêtre).

#### Code Avant/Après
```typescript
// Avant
const [period, setPeriod] = useState<Period>(settings.defaultPeriod)

// Après
const [period, setPeriod] = useState<Period>(() => {
  const stored = sessionStorage.getItem('dashboard_timeRange')
  return (stored as Period) || settings.defaultPeriod
})

useEffect(() => {
  sessionStorage.setItem('dashboard_timeRange', period)
}, [period])
```

#### Leçons Apprises
- Toujours considérer la persistance UX pour les filtres utilisateur
- `sessionStorage` = persistance par session (fermeture tab = reset)
- `localStorage` = persistance permanente (à éviter pour préférences temporaires)

#### Tags
`#frontend` `#state-management` `#ux` `#sessionStorage`

---

### [BUG-002] Attack Analyzer affiche logs avec IP 0.0.0.0

**Date**: 2026-01-10
**Version**: v3.2.100 → v3.2.101
**Sévérité**: Medium
**Composant**: Frontend
**Fichiers affectés**: `frontend/src/contexts/SettingsContext.tsx`, `frontend/src/pages/AttacksAnalyzer.tsx`

#### Symptôme
Depuis l'ajout des logs firewall XGS au syslog, Attack Analyzer affiche des entrées avec IP source 0.0.0.0.

#### Cause Racine
Les logs firewall XGS incluent parfois des IPs système (0.0.0.0, 127.0.0.1) pour le traffic local ou les services internes. Ces IPs n'étaient pas filtrées par le mécanisme `shouldShowIP` existant.

#### Solution
1. Ajouter le filtrage des IPs système (0.0.0.0, 127.0.0.1, ::1, "") dans `shouldShowIP` du SettingsContext
2. Ajouter `useSettings` et `filteredTopAttackers` dans AttacksAnalyzer pour filtrer les IPs affichées

#### Code Avant/Après
```typescript
// SettingsContext.tsx - Avant
const shouldShowIP = useCallback((ip: string): boolean => {
  if (!settings.hideSystemIPs) return true
  return !systemWhitelistIPs.includes(ip)
}, [settings.hideSystemIPs, systemWhitelistIPs])

// SettingsContext.tsx - Après
const shouldShowIP = useCallback((ip: string): boolean => {
  if (!settings.hideSystemIPs) return true
  // Filter invalid/system IPs (0.0.0.0, localhost, etc.)
  if (ip === '0.0.0.0' || ip === '127.0.0.1' || ip === '::1' || ip === '') return false
  return !systemWhitelistIPs.includes(ip)
}, [settings.hideSystemIPs, systemWhitelistIPs])
```

#### Leçons Apprises
- Les logs firewall peuvent contenir des IPs invalides/système
- Centraliser le filtrage dans SettingsContext permet de l'appliquer partout
- Le setting `hideSystemIPs` permet à l'utilisateur de contrôler ce comportement

#### Tags
`#frontend` `#filtering` `#xgs-logs` `#system-ips`

---

### [BUG-003] WAF Explorer limité à today/yesterday

**Date**: 2026-01-10
**Version**: v3.2.100 → v3.2.101
**Sévérité**: Medium
**Composant**: Frontend + Backend
**Fichiers affectés**: `frontend/src/pages/WafExplorer.tsx`, `backend/internal/adapter/controller/http/handlers/modsec.go`

#### Symptôme
WAF Explorer n'affiche que "today" et "yesterday" dans les accordéons de dates. Impossible de visualiser les jours antérieurs.

#### Cause Racine
1. La limite par défaut du frontend était 100 logs
2. La limite maximale du backend était 100, avec défaut à 25
3. Si tous les 100 premiers logs sont des 2 derniers jours, on ne voit que today/yesterday

#### Solution
1. Augmenter la limite par défaut frontend de 100 à 500
2. Augmenter la limite max backend de 100 à 500 (défaut 100)
3. Ajouter un bouton "Load More" pour charger plus de logs historiques

#### Code Avant/Après
```typescript
// Frontend - Avant
const [pagination, setPagination] = useState({ total: 0, limit: 100, offset: 0, has_more: false })

// Frontend - Après
const [pagination, setPagination] = useState({ total: 0, limit: 500, offset: 0, has_more: false })
const [loadingMore, setLoadingMore] = useState(false)

const loadMore = async () => {
  // Append more data to existing requests
}
```

```go
// Backend - Avant
if limit <= 0 || limit > 100 {
    limit = 25
}

// Backend - Après
if limit <= 0 || limit > 500 {
    limit = 100
}
```

#### Leçons Apprises
- Les limites de pagination doivent être alignées frontend/backend
- Pour les vues groupées par date, la limite doit être assez haute pour couvrir plusieurs jours
- Un bouton "Load More" offre flexibilité sans surcharger la requête initiale

#### Tags
`#frontend` `#backend` `#pagination` `#waf` `#ux`

---

### [BUG-004] VPN page compteurs statiques

**Date**: 2026-01-10
**Version**: v3.2.100 → v3.2.101
**Sévérité**: Medium
**Composant**: Frontend
**Fichiers affectés**: `frontend/src/pages/VpnNetwork.tsx`

#### Symptôme
Sur la page VPN, les blocs compteurs (hits) ne se mettent pas à jour lors du changement de filtre temps (24h, 7d, 30d).

#### Cause Racine
L'API `eventsApi.list()` était appelée sans passer le paramètre `start_time`, donc les données retournées n'étaient pas filtrées par période.

#### Solution
1. Ajouter une fonction helper `getStartTimeFromPeriod()` pour convertir le period en date ISO
2. Passer `start_time` à tous les appels `eventsApi.list()`

#### Code Avant/Après
```typescript
// Avant
const [overviewRes, vpnRes, firewallRes, ipsRes, geoRes] = await Promise.all([
  statsApi.overview(period),
  eventsApi.list({ log_type: 'VPN', limit: 100 }),
  eventsApi.list({ log_type: 'Firewall', limit: 100 }),
  eventsApi.list({ log_type: 'IPS', limit: 50 }),
  geoApi.heatmap(period),
])

// Après
const startTime = getStartTimeFromPeriod(period)
const [overviewRes, vpnRes, firewallRes, ipsRes, geoRes] = await Promise.all([
  statsApi.overview(period),
  eventsApi.list({ log_type: 'VPN', limit: 100, start_time: startTime }),
  eventsApi.list({ log_type: 'Firewall', limit: 100, start_time: startTime }),
  eventsApi.list({ log_type: 'IPS', limit: 50, start_time: startTime }),
  geoApi.heatmap(period),
])
```

#### Leçons Apprises
- Les APIs de stats et de liste d'events utilisent des paramètres différents (period vs start_time)
- Toujours vérifier que les filtres de temps sont passés à toutes les APIs

#### Tags
`#frontend` `#api` `#time-filter` `#vpn`

---

### [BUG-005] Settings - Manque bouton édition IP XGS Syslog

**Date**: 2026-01-10
**Version**: v3.2.100 → v3.2.101
**Sévérité**: Low
**Composant**: Frontend
**Fichiers affectés**: `frontend/src/pages/Settings.tsx`

#### Symptôme
Impossible de modifier l'IP du firewall XGS (syslog source) depuis la WebUI. Nécessite modification manuelle des fichiers de configuration.

#### Cause Racine
Fonctionnalité non implémentée. Les plugins API et SSH existaient mais pas le plugin Syslog.

#### Solution
1. Ajouter un nouveau plugin config `sophos_syslog` avec les champs IP et Port
2. Ajouter le bouton `onEdit` sur la ligne Sophos XGS - Syslog (admin only)

#### Code Avant/Après
```typescript
// Avant - pas de plugin syslog

// Après
{
  id: 'sophos_syslog',
  name: 'Sophos XGS - Syslog',
  type: 'syslog',
  fields: [
    { key: 'SYSLOG_SOURCE_IP', label: 'Firewall IP', type: 'text', value: '', placeholder: '10.56.125.254' },
    { key: 'SYSLOG_PORT', label: 'Syslog Port (TCP)', type: 'number', value: '1514', placeholder: '1514' },
  ],
},

// IntegrationRow avec bouton édition
<IntegrationRow
  name="Sophos XGS - Syslog"
  ...
  onEdit={isAdmin ? () => handleEditPlugin('sophos_syslog') : undefined}
/>
```

#### Leçons Apprises
- Toutes les intégrations configurables doivent avoir un bouton d'édition dans Settings
- Les nouveaux plugins doivent être ajoutés au tableau `defaultPluginConfigs`

#### Tags
`#frontend` `#feature` `#settings` `#xgs` `#admin`

---

### [BUG-006] Pages vides Attack Analyzer/Adv Threat sur serveur test

**Date**: 2026-01-10
**Version**: v3.2.100 → v3.2.101
**Sévérité**: High
**Composant**: Frontend
**Fichiers affectés**: `frontend/src/pages/AttacksAnalyzer.tsx`, `frontend/src/pages/AdvancedThreat.tsx`

#### Symptôme
Sur le serveur de test VPS (sans firewall connecté), les pages Attack Analyzer et Advanced Threat affichent une page complètement vide au lieu d'un état "no data".

#### Cause Racine
Les APIs backend peuvent retourner `null` au lieu de tableaux vides `[]` quand il n'y a pas de données. Le frontend ne gérait pas ce cas et crashait silencieusement.

#### Solution
Ajouter une gestion défensive avec le pattern `data || []` pour garantir que les states sont toujours des tableaux, jamais null.

#### Code Avant/Après
```typescript
// AttacksAnalyzer.tsx - Avant
setRuleStats(rules)
setAttackTypeStats(attacks)
setTopAttackers(attackersData)

// AttacksAnalyzer.tsx - Après
setRuleStats(rules || [])
setAttackTypeStats(attacks || [])
setTopAttackers(attackersData || [])

// AdvancedThreat.tsx - Avant
setStats(statsData)
setProviders(providersData)
setThreats(threatsData)

// AdvancedThreat.tsx - Après
setStats(statsData || null)
setProviders(providersData || [])
setThreats(threatsData || [])
```

#### Leçons Apprises
- Toujours utiliser le pattern `data || []` ou `data || {}` pour les données API
- Les APIs peuvent retourner null même si le type TypeScript dit autrement
- Tester sur un environnement vierge (sans données) révèle ces bugs

#### Tags
`#frontend` `#error-handling` `#null-safety` `#empty-state`

---

## Index des Tags

| Tag | Description | Bugs |
|-----|-------------|------|
| `#frontend` | Bugs côté React/TypeScript | 001, 002, 003, 004, 005, 006 |
| `#backend` | Bugs côté Go API | 003 |
| `#state-management` | Gestion d'état React | 001 |
| `#ux` | Expérience utilisateur | 001, 003 |
| `#sessionStorage` | Persistance session navigateur | 001 |
| `#filtering` | Filtrage de données | 002 |
| `#system-ips` | IPs système (0.0.0.0, localhost) | 002 |
| `#xgs-logs` | Logs Sophos XGS | 002, 005 |
| `#pagination` | Pagination API | 003 |
| `#waf` | ModSecurity/WAF | 003 |
| `#api` | Appels API | 004 |
| `#time-filter` | Filtres temporels | 004 |
| `#vpn` | Page VPN | 004 |
| `#settings` | Page Settings | 005 |
| `#admin` | Fonctionnalités admin | 005 |
| `#error-handling` | Gestion d'erreurs | 006 |
| `#null-safety` | Protection null/undefined | 006 |
| `#empty-state` | États vides/no data | 006 |

---

## Patterns de Correction Récurrents

### Pattern 1: Persistance de filtres utilisateur
```typescript
// Utiliser sessionStorage pour persistance par session
const [filter, setFilter] = useState<T>(() => {
  const stored = sessionStorage.getItem('key')
  return (stored as T) || defaultValue
})

useEffect(() => {
  sessionStorage.setItem('key', filter)
}, [filter])
```

### Pattern 2: Gestion défensive des données API
```typescript
// Toujours fallback sur valeur par défaut
const response = await api.getData()
setData(response || [])  // Pour arrays
setData(response || {})  // Pour objects
setData(response || null)  // Pour optionals
```

### Pattern 3: Filtrage centralisé
```typescript
// Centraliser dans Context pour réutilisation
const shouldShowItem = useCallback((item: Item): boolean => {
  if (!settings.filterEnabled) return true
  return !itemsToHide.includes(item.id)
}, [settings.filterEnabled, itemsToHide])
```

### Pattern 4: Conversion period → timestamp
```typescript
function getStartTimeFromPeriod(period: string): string {
  const now = new Date()
  const offsets: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
  }
  return new Date(now.getTime() - (offsets[period] || offsets['24h'])).toISOString()
}
```

---

## Historique des Sessions

| Date | Version | Bugs Fixés | Fichiers Modifiés |
|------|---------|------------|-------------------|
| 2026-01-10 | v3.2.101 | BUG-001 à BUG-006 | 8 fichiers |

---

*Document maintenu par Claude Code - Mise à jour après chaque session de debug*
