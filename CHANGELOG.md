# Changelog

All notable changes to VIGILANCE X will be documented in this file.

---

## [3.1.4] - 2026-01-10

### Fix: Frontend React Build

Correction du build frontend qui causait une page blanche.

#### Problème
- Terser manglait les propriétés React internes (`__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED`)
- Erreur console: `Cannot read properties of undefined (reading 'ReactCurrentOwner')`

#### Solution
- Suppression du property mangling dans `vite.config.ts`
- Le regex `/^_/` manglait les propriétés commençant par underscore, cassant React

---

## [3.1.3] - 2026-01-10

### Fix: Backend Signal Handler Crash (Garble)

Correction du crash backend avec Garble `-tiny` flag.

#### Problème
- Flag `-tiny` de Garble supprime les infos runtime nécessaires au signal handling Go
- Erreur: `fatal: bad g in signal handler` (exit code 139/SIGSEGV)

#### Solution
- Suppression du flag `-tiny` de toutes les commandes Garble dans `release.yml`

---

## [3.1.2] - 2026-01-10

### Tentative de fix (ineffective)

- Tentative de rebuild sans changement effectif

---

## [3.1.1] - 2026-01-09

### Fix: Backend Signal Handler Crash (UPX)

Première tentative de correction du crash backend.

#### Problème
- Compression UPX incompatible avec le runtime Go
- Causait `fatal: bad g in signal handler`

#### Solution
- Suppression de la compression UPX dans `release.yml`

---

## [3.1.0] - 2026-01-09

### XGS Decoders & Rules Engine (Sophos Log Parser)

Version majeure introduisant un moteur de parsing propriétaire pour les logs Sophos XGS avec décodeurs XML et règles de détection.

---

### 📦 Nouveaux Fichiers XML

Deux fichiers XML propriétaires définissent le parsing et la détection :

| Fichier | Description | Contenu |
|---------|-------------|---------|
| `vigilanceX_XGS_decoders.xml` | Définition des champs | 104 champs, 17 groupes |
| `vigilanceX_XGS_rules.xml` | Règles de détection | 74 règles, 10 catégories |

#### Groupes de Champs (Decoders)

| Groupe | Champs | Description |
|--------|--------|-------------|
| `device_identity` | 3 | Identification firewall (device_serial_id, device_model, device_name) |
| `log_metadata` | 5 | Métadonnées log (log_id, timestamp, log_type, etc.) |
| `network_layer` | 8 | Couche réseau (IPs, ports, protocol, zones) |
| `user_identity` | 5 | Identité utilisateur (user_name, domain, auth_client) |
| `http_request` | 8 | Requêtes HTTP (method, url, status, user_agent) |
| `tls_analysis` | 4 | Analyse TLS (version, cipher_suite, sni) |
| `threat_intel` | 6 | Threat intelligence (threatfeed, malware, classification) |
| `waf_modsec` | 6 | WAF/ModSecurity (reason, rule_id, severity) |
| `vpn_session` | 8 | Sessions VPN (connection_name, tunnel_id, bytes) |
| `endpoint_health` | 5 | Synchronized Security (ep_uuid, ep_health, hb_status) |
| `email_fields` | 6 | Anti-spam (sender, recipient, subject, spam_action) |
| `firewall_action` | 5 | Actions firewall (action, rule_id, rule_name) |
| `atp_sandbox` | 5 | ATP/Sandstorm (file_name, file_hash, sandbox_status) |
| `antivirus` | 4 | Anti-virus (malware_name, malware_type, quarantine_status) |
| `nat_translation` | 4 | NAT (nat_src_ip, nat_dst_ip, nat_rule) |
| `bandwidth` | 4 | Bande passante (bytes_in, bytes_out, duration) |
| `custom` | 2 | Champs personnalisés |

#### Catégories de Règles

| Catégorie | Règles | ID Range | Description |
|-----------|--------|----------|-------------|
| WAF Attack Detection | 15 | 100xxx | Injection SQL, XSS, RCE, LFI, scanners |
| ATP Threats | 8 | 200xxx | C2, malware, zero-day, sandstorm |
| IPS Alerts | 8 | 300xxx | Intrusion, exploit, protocol anomaly |
| VPN Security | 10 | 400xxx | Auth failure, brute force, tunnel attacks |
| Firewall Violations | 8 | 500xxx | Zone violations, port scanning |
| Sandstorm Analysis | 6 | 600xxx | Sandbox results, APT detection |
| Authentication | 8 | 700xxx | Login failures, privilege escalation |
| Endpoint Health | 4 | 800xxx | Heartbeat, health status |
| Email Threats | 4 | 900xxx | Spam, phishing, malware attachment |
| Custom Rules | 3 | 990xxx | Règles personnalisées |

---

### 🔧 Parser Go Natif

Nouveau package Go pour le parsing des logs Sophos XGS.

#### Fichiers Créés

| Fichier | Description |
|---------|-------------|
| `internal/adapter/parser/sophos/types.go` | Structures de données XML |
| `internal/adapter/parser/sophos/decoder_parser.go` | Parsing des décodeurs |
| `internal/adapter/parser/sophos/rules_parser.go` | Évaluation des règles |
| `internal/adapter/parser/sophos/sophos.go` | API unifiée |
| `internal/adapter/parser/sophos/sophos_test.go` | Tests complets |

#### Fonctionnalités Parser

| Méthode | Description |
|---------|-------------|
| `LoadDecodersFromFile()` | Charge les définitions XML des champs |
| `LoadRulesFromFile()` | Charge les règles de détection |
| `ParseLog()` | Extrait les champs d'un log brut |
| `EvaluateLog()` | Évalue les règles sur un log parsé |
| `ParseAndEvaluate()` | Parsing + évaluation combinés |
| `GetMitreCoverage()` | Retourne les techniques MITRE couvertes |

#### MITRE ATT&CK Coverage

23 techniques MITRE ATT&CK mappées :

| Tactique | Techniques |
|----------|------------|
| Initial Access | T1190, T1133 |
| Execution | T1059 |
| Persistence | T1098 |
| Privilege Escalation | T1068 |
| Defense Evasion | T1070, T1562 |
| Credential Access | T1110, T1003 |
| Discovery | T1046, T1018 |
| Lateral Movement | T1021 |
| Collection | T1557 |
| Command & Control | T1071, T1573, T1095 |
| Exfiltration | T1041, T1567 |
| Impact | T1499, T1486 |

---

### 🌐 API Parser Endpoints

5 nouveaux endpoints pour l'API du parser :

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/v1/parser/stats` | GET | Statistiques du parser (champs, règles, MITRE) |
| `/api/v1/parser/fields` | GET | Liste des groupes et champs définis |
| `/api/v1/parser/rules` | GET | Liste des règles par catégorie |
| `/api/v1/parser/mitre` | GET | Couverture MITRE ATT&CK |
| `/api/v1/parser/test` | POST | Test de parsing d'un log brut |

#### Exemple Réponse `/parser/stats`

```json
{
  "loaded": true,
  "version": "1.0",
  "total_fields": 104,
  "total_rules": 74,
  "total_groups": 17,
  "mitre_techniques": 23,
  "decoders_loaded_at": "2026-01-09T10:30:00Z",
  "rules_loaded_at": "2026-01-09T10:30:00Z",
  "total_logs_parsed": 15234,
  "total_rules_triggered": 892
}
```

---

### 📊 Vector.toml Extended Fields (v3.1)

27 nouveaux champs extraits et envoyés à ClickHouse :

| Catégorie | Champs |
|-----------|--------|
| Device Identity | device_serial_id, device_model, device_name |
| Log Metadata | log_id, con_id, log_component, log_subtype |
| TLS Analysis | tls_version, cipher_suite, sni |
| Threat Intel | threatfeed, malware, classification |
| VPN Extended | connection_name, remote_network, local_network, local_ip |
| Endpoint Health | ep_uuid, ep_name, ep_ip, ep_health, hb_status |
| Email | sender, recipient, subject |
| Zones | src_zone, dst_zone |

---

### 🗄️ Migration ClickHouse

Nouvelle migration `006_extended_xgs_fields.sql` :

- 27 nouvelles colonnes sur la table `events`
- 4 nouveaux index (device_serial, tls_version, threatfeed, ep_health)
- Compatible avec les données existantes (valeurs par défaut)

---

### 📝 Fichiers Modifiés

| Fichier | Modification |
|---------|--------------|
| `backend/cmd/api/main.go` | Import parser, initialisation, routes `/parser/*` |
| `backend/internal/adapter/controller/http/handlers/parser.go` | 5 handlers API |
| `docker/vector/vector.toml` | 27 nouveaux champs dans prepare_events |
| `docker/clickhouse/migrations/006_extended_xgs_fields.sql` | Migration schema |

---

### ⚙️ Prérequis

Pour activer le parser XGS :

1. **Fichiers XML** : Présence de `vigilanceX_XGS_decoders.xml` et `vigilanceX_XGS_rules.xml` dans `/backend/scenarios/`
2. **Migration** : Exécuter `006_extended_xgs_fields.sql` sur ClickHouse
3. **Restart** : Redémarrer les services Vector et API

---

## [3.0.1] - 2026-01-09

### Maintenance & UI Improvements

---

### 🔧 Maintenance Automatique Docker

Ajout d'un script de maintenance pour nettoyer automatiquement le build cache Docker qui peut saturer le disque.

#### Script de Maintenance

```bash
# Emplacement
/opt/vigilanceX/scripts/maintenance.sh

# Installation cron (nettoyage hebdomadaire dimanche 3h)
0 3 * * 0 /opt/vigilanceX/scripts/maintenance.sh >> /var/log/vigilancex-maintenance.log 2>&1
```

#### Actions du Script

| Action | Description |
|--------|-------------|
| Build cache cleanup | `docker builder prune -a -f --filter "until=168h"` |
| System cleanup | Suppression des images/conteneurs non utilisés |
| Logs truncation | Troncature des logs conteneurs > 100MB |

---

### 📊 Page VPN & Network - Filtrage par Jour

Refactoring de la section VPN Sessions pour grouper les événements par jour avec un système d'accordéon.

#### Fonctionnalités

| Feature | Description |
|---------|-------------|
| Groupement par jour | Sessions organisées par date |
| Accordéon | Clic sur un jour pour déplier/replier |
| Stats rapides | Compteurs "connected" / "failed" par jour |
| Recherche | Filtre par user, IP ou pays |

---

### 🌍 Page Geoblocking - Top 10 Pays Attaquants

Nouvelle section affichant les 10 pays avec le plus d'événements d'attaque sur le XGS.

#### Interface

| Élément | Description |
|---------|-------------|
| Top 10 Liste | Pays triés par nombre d'attaques |
| Sélecteur période | 24h, 7d, 30d |
| Stats par pays | Nombre d'events + IPs uniques |
| Modal détails | Clic sur un pays affiche la liste des IPs attaquantes |

#### Données Affichées (Modal)

| Colonne | Description |
|---------|-------------|
| IP Address | Adresse IP avec badge "High Risk" si score > 50 |
| Attacks | Nombre total d'attaques |
| Blocked | Nombre d'attaques bloquées |
| Unique Rules | Règles déclenchées |
| Categories | Types d'attaques (sqli, xss, scanner...) |

---

### 📝 Notes de Versioning

Rappel important pour les futures versions :
- **Mettre à jour la version** dans `frontend/src/pages/Settings.tsx` à chaque release
- Suivre le Semantic Versioning : PATCH pour bugfixes, MAJOR pour nouvelles fonctionnalités

---

## [3.0.0] - 2026-01-08

### VX3 Secure Firewall Binding

Version majeure introduisant un nouveau système de liaison matérielle sécurisé combinant l'identité de la VM et du firewall connecté.

---

### 🔐 VX3 Hardware Binding

Nouveau système de binding double couche pour une protection renforcée contre la copie de licence.

#### Architecture Binding

| Version | Format | Éléments |
|---------|--------|----------|
| **VX2** (legacy) | `SHA256("VX2:" + machine_id + ":" + product_uuid)` | VM uniquement |
| **VX3** (nouveau) | `SHA256("VX3:" + machine_id + ":" + firewall_serial)` | VM + Firewall |

#### Sécurité Renforcée

| Menace | VX2 | VX3 |
|--------|-----|-----|
| Copie VM vers autre hyperviseur | ⚠️ Possible si machine-id identique | ✅ Bloqué (firewall différent) |
| Clone VM avec même firewall | ⚠️ Fonctionnel | ✅ Bloqué (machine-id différent) |
| Transfert licence entre clients | ⚠️ Contournable | ✅ Impossible |

#### Extraction Firewall Serial

Le serial du firewall est extrait automatiquement des logs syslog stockés dans ClickHouse :

```sql
SELECT
    extractAll(raw_log, 'device_serial_id="([^"]+)"')[1] as serial,
    extractAll(raw_log, 'device_model="([^"]+)"')[1] as model,
    extractAll(raw_log, 'device_name="([^"]+)"')[1] as name
FROM vigilance.events
WHERE raw_log LIKE '%device_serial_id%'
```

#### Données Firewall Capturées

| Champ | Exemple | Source |
|-------|---------|--------|
| `firewall_serial` | `X21006DP4YWT63A` | Sophos XGS syslog |
| `firewall_model` | `XGS2100` | Sophos XGS syslog |
| `firewall_name` | `xgkrs.cloudcomputing.lu` | Sophos XGS syslog |

---

### ⏰ Grace Period Étendu

| Paramètre | Ancienne valeur | Nouvelle valeur |
|-----------|-----------------|-----------------|
| `LICENSE_GRACE_PERIOD` | 72h (3 jours) | 168h (7 jours) |

Permet un fonctionnement hors-ligne prolongé en cas de panne réseau ou maintenance du serveur de licence.

---

### 🔄 Migration Automatique VX2 → VX3

Le système migre automatiquement les licences existantes lors de la première connexion :

1. Détection licence VX2 existante
2. Extraction du firewall serial depuis ClickHouse
3. Régénération du hash avec binding VX3
4. Re-chiffrement du fichier licence local
5. Mise à jour sur vigilanceKey

#### Compatibilité

- Les nouvelles installations utilisent directement VX3
- Les installations existantes migrent automatiquement
- Fallback vers VX2 si aucun log firewall disponible

---

### 📡 API Response Enrichie

Le endpoint `/api/v1/license/status` retourne maintenant les informations de binding :

```json
{
    "licensed": true,
    "status": "active",
    "customer_name": "VigilanceX Production",
    "expires_at": "2027-01-08T13:50:24Z",
    "days_remaining": 364,
    "grace_mode": false,
    "features": ["osint", "reports", "geoblocking"],
    "hardware_id": "5eed64c4192c28ba...",
    "binding_version": "VX3",
    "firewall_serial": "X21006DP4YWT63A",
    "firewall_model": "XGS2100",
    "firewall_name": "xgkrs.cloudcomputing.lu",
    "secure_binding": true
}
```

---

### 🔧 Fichiers Modifiés

| Fichier | Modification |
|---------|--------------|
| `internal/license/hwid.go` | Interfaces DBQuerier/RowScanner, ClickHouseAdapter, firewall extraction |
| `internal/license/store.go` | Support VX3, migration automatique, firewall fields |
| `internal/license/client.go` | NewClientWithFirewall(), firewall info dans LicenseStatus |
| `internal/config/config.go` | Grace period 168h |
| `cmd/api/main.go` | ClickHouseAdapter, NewClientWithFirewall() |
| `handlers/license.go` | Firewall binding fields dans API response |

---

### ⚙️ Variables d'Environnement

```bash
# Grace Period (défaut: 168h = 7 jours)
LICENSE_GRACE_PERIOD=168h
```

---

### 🛡️ Prérequis VX3

Pour activer le binding VX3, le système nécessite :

1. **Logs syslog** : Au moins un log contenant `device_serial_id` dans ClickHouse
2. **Firewall Sophos XGS** : Les logs doivent provenir d'un firewall Sophos XGS
3. **Connexion ClickHouse** : Accès à la base de données pour extraire le serial

Si ces conditions ne sont pas remplies, le système utilise le binding VX2 en fallback.

---

## [2.9.7] - 2026-01-08

### License Sync & Grace Mode

Amélioration du système de licence avec synchronisation manuelle et mode grace testé.

---

### 🔄 Sync License Status

Nouveau bouton "Sync License Status" sur la page d'activation de licence permettant de forcer la synchronisation avec le serveur vigilanceKey.

#### Fonctionnalités
| Feature | Description |
|---------|-------------|
| **Bouton Sync** | Toujours visible sur `/license` |
| **Feedback visuel** | Animation pendant le sync, badge succès |
| **Mise à jour instantanée** | Status, expiration, jours restants |
| **Gestion erreurs** | Message d'erreur si serveur injoignable |

#### Cas d'usage
- Vérifier manuellement le status de licence après modification sur vigilanceKey
- Forcer la mise à jour après revoke/reactivate/renew/extend
- Débugger les problèmes de licence

---

### 🛡️ Grace Mode (Testé & Validé)

Mode de fonctionnement hors-ligne quand vigilanceKey est injoignable.

#### Comportement validé
| Condition | Status | Grace Mode | Accès |
|-----------|--------|------------|-------|
| Serveur accessible | `active` | `false` | ✅ Normal |
| Serveur injoignable | `grace` | `true` | ✅ Maintenu (72h) |
| Grace expirée | `expired` | `false` | ❌ Bloqué |
| Serveur revient | `active` | `false` | ✅ Restauré |

#### Indicateurs UI
- **Sidebar** : Badge jaune "Grace Mode" avec "Server unreachable"
- **Page License** : Message d'avertissement avec durée restante

---

### 🔗 Intégration vigilanceKey v1.2

Compatibilité complète avec vigilanceKey v1.2 et ses nouvelles fonctionnalités.

#### Endpoints supportés
| Endpoint vigilanceKey | Action vigilanceX |
|-----------------------|-------------------|
| `POST /license/validate` | Sync manuel & heartbeat |
| `POST /admin/licenses/{id}/revoke` | Détection révocation |
| `POST /admin/licenses/{id}/reactivate` | Restauration accès |
| `POST /admin/licenses/{id}/renew` | Mise à jour expiration |
| `POST /admin/licenses/{id}/extend` | Extension personnalisée |

#### Cycle de vie testé
```
vigilanceKey                    vigilanceX
     │                              │
     │◄── Heartbeat (12h) ──────────│
     │                              │
  [revoke]                          │
     │                              │
     │◄── Sync (bouton) ────────────│
     │                              │
     └──────► status: revoked ──────┘
                   │
              Accès bloqué
```

---

### 🔧 Fichiers Modifiés

| Fichier | Modification |
|---------|--------------|
| `frontend/src/pages/LicenseActivation.tsx` | Bouton Sync toujours visible |
| `frontend/src/contexts/LicenseContext.tsx` | Fonction `syncWithServer()` |
| `docs/VIGILANCEKEY_SERVER.md` | Documentation v1.2 complète |

---

## [2.9.6] - 2026-01-08

### CrowdSec CTI Integration

Ajout de CrowdSec CTI comme 11ème provider de threat intelligence.

---

### 🔌 Nouveau Provider (Tier 2)

| Provider | Source | Limite | Description |
|----------|--------|--------|-------------|
| **CrowdSec CTI** | CrowdSec | 50 req/jour | Community-sourced CTI, subnet reputation, MITRE ATT&CK |

#### CrowdSec - Fonctionnalités Uniques

- **Réputation Subnet /24** : Évalue la réputation du sous-réseau entier
- **Background Noise Score** : Score 0-10 quantifiant le bruit de fond internet
- **Multi-Timeframe Scoring** : Scores last_day, last_week, last_month, overall
- **MITRE ATT&CK Mapping** : Association des techniques d'attaque
- **Behaviors** : Classification des comportements observés
- **False Positive Classification** : Identification CDN, VPN, services connus

#### Score Normalisé (0-100)

Le score CrowdSec est calculé en fonction de:
- Réputation de base (malicious=70, suspicious=50, known=30, unknown=10, safe=0)
- Background Noise Score ≥7 (+15pts), ≥4 (+10pts)
- IP Range /24 Reputation (malicious +10, suspicious +5)
- IP Range Score ≥4 (+10), ≥2 (+5)
- Nombre de behaviors (+3 pts/behavior, max 15)
- Bonus pour behaviors agressifs (exploit +10, bruteforce +8, scan +3)
- MITRE Techniques (+2 pts/technique, max 10)
- CVEs associés (+3 pts/CVE, max 10)
- Ajustement confiance (high=100%, medium=90%, low=70%)
- Réduction false positives (x0.6 si FP identifié)

#### Nouveaux Champs de Réponse API

```json
{
  "crowdsec": {
    "found": true,
    "reputation": "malicious",
    "background_noise_score": 8,
    "ip_range_score": 4,
    "behaviors": ["ssh:bruteforce", "http:scan"],
    "mitre_techniques": ["T1110", "T1046"],
    "normalized_score": 85
  },
  "background_noise": 8,
  "subnet_score": 4,
  "mitre_techniques": ["T1110", "T1046"],
  "behaviors": ["ssh:bruteforce", "http:scan"]
}
```

---

### 📊 Rebalancement des Poids (11 Providers)

```
Tier 1 (Unlimited):
  IPSum:         0.11  (blocklists aggregation)
  OTX:           0.09  (threat context)
  ThreatFox:     0.11  (C2/malware IOCs)
  URLhaus:       0.09  (malicious URLs)
  ShodanIDB:     0.07  (passive recon)

Tier 2 (Moderate - Score≥30):
  AbuseIPDB:     0.14  (behavioral reports)
  GreyNoise:     0.11  (FP reduction)
  CrowdSec:      0.10  (community CTI) [NEW]

Tier 3 (Limited - Score≥60):
  VirusTotal:    0.09  (multi-AV consensus)
  CriminalIP:    0.05  (infrastructure detection)
  Pulsedive:     0.04  (IOC correlation)
```

---

### ⚙️ Configuration

```bash
# .env - CrowdSec CTI API Key
# Obtenir sur https://app.crowdsec.net/cti
CROWDSEC_API_KEY=your_api_key_here

# Cache TTL (défaut: 24h) - évite les requêtes répétées
THREAT_INTEL_CACHE_TTL=24h
```

---

### 🛡️ Optimisation des Quotas API

CrowdSec étant limité à **50 requêtes/jour**, plusieurs mécanismes protègent le quota :

#### 1. Cache 24 heures
- Une IP checkée n'est **jamais re-checkée pendant 24h**
- Le cache est partagé entre tous les providers
- Configurable via `THREAT_INTEL_CACHE_TTL`

#### 2. Système de Cascade (Tier 2)
- CrowdSec n'est interrogé que si le **score Tier 1 ≥ 30**
- Les IPs "propres" ne consomment pas de quota CrowdSec
- Seules les IPs suspectes déclenchent Tier 2

#### 3. Cas d'Usage Recommandés
| Contexte | CrowdSec Utilisé | Raison |
|----------|------------------|--------|
| Advanced Threat (OSINT) | ✅ Oui | Analyse approfondie |
| IP bloquée par WAF | ✅ Oui | Score Tier 1 élevé |
| Logs normaux | ⚠️ Si suspect | Seulement si score ≥ 30 |
| IP déjà en cache | ❌ Non | Cache 24h actif |

#### Estimation de Consommation
- ~10-20 IPs suspectes/jour = ~10-20 requêtes CrowdSec
- Marge confortable avec limite de 50/jour
- Le cache évite les doublons même en cas de multiples checks UI

---

### 🖥️ Frontend - IP Threat Modal

Le modal de détail IP affiche maintenant les données CrowdSec :

#### Pastille Score CrowdSec
- **Score normalisé** (0-100) avec code couleur
- **Réputation** (malicious, suspicious, unknown, safe)
- Grille 4 colonnes : AbuseIPDB, VirusTotal, OTX, **CrowdSec**

#### Section Détaillée CrowdSec (si données disponibles)
- **Background Noise** : Score 0-10 du bruit internet
- **Subnet /24** : Score 0-5 de réputation du sous-réseau
- **Behaviors** : Tags des comportements détectés (bruteforce, scan, exploit...)
- **MITRE ATT&CK** : Techniques avec liens cliquables vers attack.mitre.org
- **Classifications** : Type d'IP (tor, vpn, datacenter, community-blocklist)

#### Liens Externes
- Lien CrowdSec CTI ajouté (https://app.crowdsec.net/cti/{ip})

---

### 🔧 Fichiers Modifiés

| Fichier | Modification |
|---------|--------------|
| `backend/internal/adapter/external/threatintel/crowdsec.go` | Nouveau client CrowdSec |
| `backend/internal/adapter/external/threatintel/aggregator.go` | Intégration Tier 2, poids, queryTier2 |
| `backend/internal/config/config.go` | CrowdSecKey config |
| `backend/cmd/api/main.go` | Passage CrowdSecKey |
| `frontend/src/pages/Settings.tsx` | Plugin config CrowdSec |
| `frontend/src/components/IPThreatModal.tsx` | Pastille + section CrowdSec |
| `frontend/src/types/index.ts` | Type ThreatScore avec champs CrowdSec |
| `docker/.env` | CROWDSEC_API_KEY |
| `docker/docker-compose.yml` | Variable env CROWDSEC_API_KEY |

---

## [2.9.5] - 2026-01-08

### API External Extension

Extension majeure des sources de threat intelligence avec 3 nouveaux providers et un système de cascade intelligent pour économiser les quotas API.

---

### 🔌 Nouveaux Providers (Tier 1 - Unlimited)

3 nouveaux providers gratuits et sans limite ajoutés au système d'agrégation :

| Provider | Source | Description |
|----------|--------|-------------|
| **ThreatFox** | abuse.ch | Détection C2/malware IOCs |
| **URLhaus** | abuse.ch | Base de données URLs malveillantes |
| **Shodan InternetDB** | Shodan | Reconnaissance passive (ports, vulns, tags) |

#### ThreatFox (abuse.ch)
- Détection d'Indicators of Compromise (IOCs)
- Identification des serveurs C2 (Command & Control)
- Association avec familles de malware connues
- Tags et références aux rapports de menace

#### URLhaus (abuse.ch)
- Vérification des hosts hébergeant des URLs malveillantes
- Détection de malware downloads et phishing
- Statut blacklists Spamhaus/SURBL
- Comptage URLs actives vs totales

#### Shodan InternetDB
- Ports ouverts et services exposés
- Vulnérabilités connues (CVEs)
- Tags de classification (VPN, Proxy, Tor, Honeypot)
- CPEs (Common Platform Enumeration)
- Score basé sur ports suspects et vulnérabilités critiques

---

### 🔄 Système de Cascade (Tiered API Querying)

Nouveau système intelligent de cascade pour économiser les quotas API tout en maintenant une détection efficace.

#### Architecture des Tiers

| Tier | Providers | Limite | Quand Interrogé |
|------|-----------|--------|-----------------|
| **Tier 1** | IPSum, OTX, ThreatFox, URLhaus, Shodan IDB | Unlimited | Toujours |
| **Tier 2** | AbuseIPDB, GreyNoise | ~1000/jour | Score T1 ≥ 30 ou indicateurs critiques |
| **Tier 3** | VirusTotal, CriminalIP, Pulsedive | ~500/jour | Score T2 ≥ 60 ou indicateurs haute-risque |

#### Déclencheurs de Cascade

**Tier 1 → Tier 2** (au moins un):
- Score intermédiaire ≥ 30
- IOC trouvé dans ThreatFox (C2/malware)
- URLs malveillantes actives dans URLhaus
- Présence dans 5+ blocklists
- Vulnérabilités critiques détectées (Log4Shell, ProxyLogon, etc.)

**Tier 2 → Tier 3** (au moins un):
- Score intermédiaire ≥ 60
- Classification "malicious" par GreyNoise
- Score AbuseIPDB ≥ 50
- C2 confirmé avec présence blocklists ≥ 3

#### Configuration

```bash
# Cascade settings (defaults)
CASCADE_ENABLED=true
CASCADE_TIER2_THRESHOLD=30
CASCADE_TIER3_THRESHOLD=60
```

#### Économies de Quota Estimées
| Scénario | Sans Cascade | Avec Cascade | Économie |
|----------|--------------|--------------|----------|
| IP bénigne | 10 requêtes | 5 requêtes | 50% |
| IP suspecte | 10 requêtes | 7 requêtes | 30% |
| IP malveillante | 10 requêtes | 10 requêtes | 0% |
| **Trafic moyen** | 100% | ~30% | **~70%** |

---

### 🖼️ Favicon

Ajout d'un favicon SVG avec design géométrique représentant un œil stylisé (thème sécurité/surveillance).

---

### 🎨 UI Updates

#### Providers Display
- Affichage par tiers avec badges colorés (T1=vert, T2=jaune, T3=rouge)
- Légende des tiers dans l'en-tête
- Indicateur de clé API requise (icône cadenas)
- Tooltip avec description du provider
- Info cascade mode dans le footer

#### Nouveaux Icons Providers
| Provider | Icône |
|----------|-------|
| ThreatFox | 💀 Skull |
| URLhaus | 🔗 Link |
| Shodan InternetDB | 📡 Scan |

---

### 📊 Providers (Total: 10)

| Provider | Tier | API Key | Description |
|----------|------|---------|-------------|
| IPSum | 1 | ❌ | Blocklists agrégées (30+ sources) |
| AlienVault OTX | 1 | ✅ | Threat context & IOCs |
| ThreatFox | 1 | ❌ | abuse.ch C2/malware IOCs |
| URLhaus | 1 | ❌ | abuse.ch malicious URLs |
| Shodan InternetDB | 1 | ❌ | Passive reconnaissance |
| AbuseIPDB | 2 | ✅ | IP abuse reports & confidence |
| GreyNoise | 2 | ✅ | Benign scanner detection (FP) |
| VirusTotal | 3 | ✅ | Multi-AV consensus |
| CriminalIP | 3 | ✅ | C2/VPN/Proxy detection |
| Pulsedive | 3 | ✅ | IOC correlation |

---

### 🔧 Backend Changes

#### New Files
- `backend/internal/adapter/external/threatintel/threatfox.go` - ThreatFox client
- `backend/internal/adapter/external/threatintel/urlhaus.go` - URLhaus client
- `backend/internal/adapter/external/threatintel/shodan_internetdb.go` - Shodan IDB client
- `frontend/public/favicon.svg` - Eye logo favicon

#### Modified Files
- `backend/internal/adapter/external/threatintel/aggregator.go` - Cascade system
- `backend/internal/config/config.go` - Cascade config
- `backend/cmd/api/main.go` - Provider initialization
- `frontend/src/pages/AdvancedThreat.tsx` - Provider display with tiers
- `frontend/src/types/index.ts` - ThreatProvider type

---

### ⚙️ New Environment Variables

```bash
# Cascade Configuration (v2.9.5)
CASCADE_ENABLED=true           # Enable tiered cascade (default: true)
CASCADE_TIER2_THRESHOLD=30     # Score to trigger Tier 2 (default: 30)
CASCADE_TIER3_THRESHOLD=60     # Score to trigger Tier 3 (default: 60)
```

---

## [2.9.0] - 2026-01-07

### Licensing System & OSINT Proxy (Kill Switch)

Version majeure introduisant un système de licence avec kill switch et un proxy OSINT centralisé pour protéger les clés API.

---

### 🔑 Licensing System

Système de validation de licence avec heartbeat pour le contrôle des déploiements client.

#### Architecture
| Composant | Description |
|-----------|-------------|
| **HardwareID** | Identification unique par VM (product_uuid + machine-id) |
| **License Store** | Persistance locale chiffrée (AES-256) |
| **Heartbeat** | Validation périodique (12h par défaut) |
| **Grace Period** | Fonctionnement hors-ligne (72h par défaut) |
| **Kill Switch** | Blocage API si licence invalide |

#### Flux d'Activation
1. L'utilisateur saisit la clé licence (XXXX-XXXX-XXXX-XXXX)
2. Le backend génère le HardwareID de la VM
3. Envoi au serveur de licence (vigilanceKey)
4. Stockage local chiffré de la licence validée
5. Heartbeat périodique pour maintenir la validité

#### Grace Mode
| Condition | Comportement |
|-----------|--------------|
| Serveur accessible | Validation normale |
| Serveur injoignable | Grace mode (72h) |
| Grace expirée | Kill switch activé |

#### API Endpoints
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/v1/license/status` | GET | Status licence actuel | Public |
| `/api/v1/license/activate` | POST | Activer une licence | Public |
| `/api/v1/license/info` | GET | Détails complets licence | Admin |
| `/api/v1/license/validate` | POST | Forcer validation | Admin |

---

### 🌐 OSINT Proxy API

Proxy centralisé pour les requêtes OSINT afin de protéger les clés API payantes.

#### Avantages
| Aspect | Bénéfice |
|--------|----------|
| **Sécurité** | Clés API jamais exposées aux clients |
| **Gestion** | Mise à jour centralisée des clés |
| **Contrôle** | Rate limiting par licence |
| **Audit** | Logs centralisés des requêtes |

#### Configuration
```bash
# Mode proxy (clés API centralisées sur vigilanceKey)
OSINT_PROXY_ENABLED=true
OSINT_PROXY_URL=https://vigilancexkey.cloudcomputing.lu

# Mode local (clés API dans chaque déploiement) - défaut
OSINT_PROXY_ENABLED=false
```

#### Fonctionnement
1. Client envoie requête OSINT (IP à vérifier)
2. Aggregator route vers proxy si activé
3. Proxy valide licence + hardware ID
4. Proxy exécute requêtes vers providers (AbuseIPDB, VirusTotal, etc.)
5. Résultat agrégé retourné au client

---

### 🖥️ Frontend - License UI

#### License Activation Page (`/license`)
| Élément | Description |
|---------|-------------|
| **Input licence** | Champ avec format XXXX-XXXX-XXXX-XXXX |
| **Status actuel** | Affichage licensed/grace/expired |
| **Activation** | Bouton avec feedback succès/erreur |
| **Contact support** | Lien vers support@vigilancex.io |

#### Sidebar License Indicator
| État | Affichage |
|------|-----------|
| Licensed | Vert avec jours restants |
| Grace Mode | Jaune avec "Server unreachable" |
| Unlicensed | Rouge avec lien activation |

#### Protected Routes
| Condition | Comportement |
|-----------|--------------|
| Licence valide | Accès normal |
| Grace mode | Accès normal + warning |
| Licence invalide | Redirection `/license` |

---

### 📁 New Files

**Backend:**
| Fichier | Description |
|---------|-------------|
| `internal/license/hwid.go` | Génération HardwareID VM |
| `internal/license/store.go` | Persistance licence chiffrée |
| `internal/license/client.go` | Client service licence |
| `internal/license/heartbeat.go` | Service heartbeat background |
| `internal/adapter/controller/http/middleware/license.go` | Middleware kill switch |
| `internal/adapter/controller/http/handlers/license.go` | Handlers API licence |
| `internal/adapter/external/threatintel/proxy_client.go` | Client OSINT proxy |

**Frontend:**
| Fichier | Description |
|---------|-------------|
| `src/contexts/LicenseContext.tsx` | Context React licence |
| `src/pages/LicenseActivation.tsx` | Page activation |

---

### 📝 Modified Files

| Fichier | Modifications |
|---------|---------------|
| `backend/internal/config/config.go` | LicenseConfig, OSINTProxyConfig |
| `backend/internal/adapter/external/threatintel/aggregator.go` | Mode proxy |
| `backend/cmd/api/main.go` | Intégration licence + proxy |
| `frontend/src/lib/api.ts` | licenseApi |
| `frontend/src/components/ProtectedRoute.tsx` | Check licence |
| `frontend/src/components/layout/Sidebar.tsx` | Indicateur licence |
| `frontend/src/main.tsx` | LicenseProvider |
| `frontend/src/App.tsx` | Route /license |

---

### 🔧 Environment Variables

```bash
# Licensing System
LICENSE_SERVER_URL=https://vigilancexkey.cloudcomputing.lu
LICENSE_KEY=XXXX-XXXX-XXXX-XXXX
LICENSE_ENABLED=true
LICENSE_HEARTBEAT_INTERVAL=12h
LICENSE_GRACE_PERIOD=72h
LICENSE_STORE_PATH=/app/data/license.json

# OSINT Proxy
OSINT_PROXY_ENABLED=false
OSINT_PROXY_URL=https://vigilancexkey.cloudcomputing.lu
OSINT_PROXY_TIMEOUT=30s
OSINT_PROXY_RATE_LIMIT=60
```

---

### 🔒 Security Considerations

| Mesure | Description |
|--------|-------------|
| **Chiffrement local** | AES-256 avec clé dérivée du HardwareID |
| **Validation HardwareID** | Empêche copie licence entre VMs |
| **Heartbeat** | Permet révocation à distance |
| **Grace period** | Évite interruption service si réseau indisponible |
| **TLS obligatoire** | Production exige HTTPS |

---

### 🎨 UI Improvements

#### Logo & Branding
| Changement | Description |
|------------|-------------|
| **Logo géométrique** | Nouvel icône œil géométrique avec iris hexagonal |
| **Design épuré** | SVG personnalisé remplaçant l'icône bouclier générique |

#### Page Advanced Threat
| Amélioration | Description |
|--------------|-------------|
| **Provider badges** | Icônes distinctes par provider (AbuseIPDB, VirusTotal, etc.) |
| **Couleurs thématiques** | Chaque provider a sa couleur unique |
| **Status amélioré** | Badge coloré si configuré, grisé sinon |

#### Page Geoblocking
| Amélioration | Description |
|--------------|-------------|
| **Tri Active Rules** | Règles triées par score (points) décroissant |
| **Visibilité** | Hosts à haut risque affichés en premier |

#### Page Reports
| Amélioration | Description |
|--------------|-------------|
| **Réorganisation** | Quick Reports et Custom Report en haut de page |
| **Accès rapide** | Génération de rapports en un clic |

#### Page Settings
| Amélioration | Description |
|--------------|-------------|
| **Sections réductibles** | Chaque catégorie peut être réduite/développée |
| **Collapse all/Expand all** | Bouton pour gérer toutes les sections |
| **Section License** | Affichage status, customer, expiration, features, HardwareID |

---

## [2.6.0] - 2026-01-07

### Authentication System & Role-Based Access Control

Version majeure ajoutant un système d'authentification complet avec gestion des rôles.

---

### 🔐 Authentication Portal

Nouveau portail de connexion sécurisé avec gestion JWT.

#### Fonctionnalités
| Feature | Description |
|---------|-------------|
| **Login Page** | Portail de connexion avec branding VigilanceX |
| **JWT Tokens** | Authentification par tokens JWT (validité 24h) |
| **Auto-redirect** | Redirection automatique vers /login si non authentifié |
| **Session persistence** | Token stocké dans localStorage |

#### API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Authentification utilisateur |
| `/api/v1/auth/logout` | POST | Déconnexion (client-side) |
| `/api/v1/auth/me` | GET | Informations utilisateur courant |
| `/api/v1/auth/change-password` | POST | Changement de mot de passe |

---

### 👥 Role-Based Access Control (RBAC)

Deux rôles avec permissions différenciées.

#### Rôles
| Role | Description | Permissions |
|------|-------------|-------------|
| **admin** | Administrateur | Accès complet + Gestion utilisateurs + Settings/Integrations |
| **audit** | Audit/Lecture seule | Visualisation uniquement, pas de ban/unban |

#### Restrictions Audit
| Page | Restriction |
|------|-------------|
| **Active Bans** | Actions ban/unban masquées |
| **Reports** | Page non accessible |
| **Users** | Page non accessible |
| **Settings** | Page non accessible (utilise les paramètres admin) |

---

### 👤 User Management (Admin)

Nouvelle page de gestion des utilisateurs pour les administrateurs.

#### Fonctionnalités
| Feature | Description |
|---------|-------------|
| **Liste utilisateurs** | Tableau avec username, rôle, status, dernière connexion |
| **Création** | Modal de création avec username, password, email, rôle |
| **Modification** | Édition email, rôle, status actif/inactif |
| **Suppression** | Suppression avec confirmation |
| **Reset password** | Réinitialisation du mot de passe par l'admin |

#### API Endpoints (Admin Only)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/users` | GET | Liste des utilisateurs |
| `/api/v1/users` | POST | Création utilisateur |
| `/api/v1/users/{id}` | GET | Détails utilisateur |
| `/api/v1/users/{id}` | PUT | Modification utilisateur |
| `/api/v1/users/{id}` | DELETE | Suppression utilisateur |
| `/api/v1/users/{id}/reset-password` | POST | Reset password |

---

### 🔑 Default Admin & Password Reset

Gestion de l'utilisateur admin par défaut et outil de récupération.

#### Admin par défaut
Au premier démarrage, si aucun utilisateur n'existe :
- Username: `admin` (configurable via `ADMIN_USERNAME`)
- Password: `VigilanceX2024!` (configurable via `ADMIN_PASSWORD`)

#### Recovery Tool
En cas de perte du mot de passe admin :
```bash
# Depuis l'hôte Docker
docker exec vigilance_backend /app/reset-password admin NouveauMotDePasse123!

# Ou depuis l'intérieur du container
/app/reset-password <username> <new_password>
```

---

### 🛡️ Security Features

| Feature | Description |
|---------|-------------|
| **Password hashing** | bcrypt avec coût 12 |
| **JWT validation** | Vérification signature + expiration |
| **Route protection** | Middleware sur toutes les routes API |
| **Audit logging** | Logs des connexions/déconnexions |

---

### 📁 New Files

**Backend:**
- `internal/entity/user.go` - Modèle utilisateur
- `internal/adapter/repository/clickhouse/users_repo.go` - Repository
- `internal/usecase/auth/service.go` - Service authentification
- `internal/adapter/controller/http/middleware/jwt.go` - Middleware JWT
- `internal/adapter/controller/http/handlers/auth.go` - Handlers auth
- `internal/adapter/controller/http/handlers/users.go` - Handlers users
- `cmd/reset-password/main.go` - Outil CLI de reset password

**Frontend:**
- `src/contexts/AuthContext.tsx` - Context d'authentification
- `src/pages/Login.tsx` - Page de connexion
- `src/pages/UserManagement.tsx` - Gestion utilisateurs
- `src/components/ProtectedRoute.tsx` - Protection routes authentification
- `src/components/AdminRoute.tsx` - Protection routes admin-only

---

### 🔧 Environment Variables

Nouvelles variables d'environnement :
```bash
# JWT Configuration
JWT_SECRET=your-secure-jwt-secret-min-32-chars
JWT_EXPIRY=24h

# Default Admin (first startup only)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!
```

---

### 🐛 Bug Fixes

| Fix | Description |
|-----|-------------|
| **WebSocket Badge** | Le badge affiche maintenant toujours "WSocket" avec changement de couleur vert/rouge |
| **Settings Access** | Page Settings entièrement réservée aux administrateurs |
| **WebSocket Auth** | Authentification WebSocket via query parameter pour les connexions temps réel |

#### WebSocket Authentication
- Token JWT passé via query parameter `?token=<jwt>` pour les connexions WebSocket
- Middleware JWT backend accepte le token depuis header OU query parameter
- Reset automatique du WebSocket lors du login/logout

---

## [2.5.0] - 2026-01-07

### System IPs & Icon Style Customization

Nouvelle version majeure avec gestion des IPs système protégées et personnalisation de l'interface.

---

### 🖥️ System Protected IPs - Whitelist Page

Nouvelle section dans la page Whitelist pour visualiser les IPs système protégées.

#### Fonctionnalités
| Feature | Description |
|---------|-------------|
| **Section dédiée** | Nouvelle section "System Protected IPs" dans Whitelist |
| **Vue par catégorie** | IPs groupées par DNS, Cloud, Monitoring |
| **Toggle Show/Hide** | Affichage collapsible avec compteur d'IPs |
| **Détails complets** | IP, nom, provider pour chaque entrée |

---

### 🎨 Sidebar Icon Style

Option de personnalisation du style des icônes de la sidebar.

#### Styles disponibles
| Style | Description |
|-------|-------------|
| **Monochrome** | Icônes monochromes (style classique) |
| **Color** | Icônes colorées par catégorie de page |

#### Palette de couleurs
| Page | Couleur |
|------|---------|
| Dashboard | Bleu |
| WAF Explorer | Emeraude |
| Attacks Analyzer | Rouge |
| Advanced Threat | Orange |
| VPN & Network | Violet |
| Active Bans | Rouge foncé |
| Geoblocking | Cyan |
| Whitelist | Vert |
| Risk Scoring | Jaune |
| Reports | Indigo |

---

### 🔧 Bug Fixes

#### Dashboard - Filtre 1h
- Correction du filtre de période "1h" qui affichait les mêmes données que "24h"
- Le backend gère maintenant correctement tous les filtres : 1h, 24h, 7d, 30d

#### Geoblocking - Suppression des règles
- Correction de l'affichage des règles : seules les règles actives sont affichées
- Possibilité de supprimer toutes les règles (WATCH, BLOCK, etc.)

---

---

## [2.3.0] - 2026-01-07

### UI Improvements & Plugin Configuration Management

Améliorations de l'interface utilisateur et ajout de la gestion des plugins avec test de connexion.

---

### 🛡️ System Whitelist - Protected IPs

Nouveau système de whitelist pour les IPs légitimes (DNS, CDN, health checks) qui ne doivent jamais être bloquées.

#### IPs Protégées
| Provider | IPs | Category |
|----------|-----|----------|
| **Cloudflare DNS** | 1.1.1.1, 1.0.0.1 | DNS |
| **Google DNS** | 8.8.8.8, 8.8.4.4 | DNS |
| **Quad9** | 9.9.9.9, 149.112.112.112 | DNS |
| **OpenDNS** | 208.67.222.222, 208.67.220.220 | DNS |
| **AWS** | 54.243.31.192 | Cloud |
| **Google Cloud** | 35.191.0.1, 130.211.0.1 | Cloud |
| **UptimeRobot** | 216.144.250.150 | Monitoring |
| **Pingdom** | 76.72.167.154 | Monitoring |
| **NIST NTP** | 129.6.15.28, 129.6.15.29 | Monitoring |

#### Fonctionnalités
- Filtrage automatique des IPs système dans tous les logs (WAF, Threats, etc.)
- Option "Hide system IPs" dans Settings > Security & Privacy
- API endpoints pour consulter et vérifier la whitelist système

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/config/system-whitelist` | GET | Liste complète des IPs protégées |
| `/config/system-whitelist/check/{ip}` | GET | Vérifier si une IP est protégée |

---

### 🎨 Icon Style Option

Nouvelle option pour choisir le style des icônes de la sidebar.

#### Options
| Style | Description |
|-------|-------------|
| **Monochrome** | Icônes monochromes (style par défaut) |
| **Color** | Icônes colorées par catégorie |

#### Couleurs par Page
| Page | Couleur |
|------|---------|
| Dashboard | Blue |
| WAF Explorer | Emerald |
| Attacks Analyzer | Red |
| Advanced Threat | Orange |
| VPN & Network | Purple |
| Active Bans | Red |
| Geoblocking | Cyan |
| Whitelist | Green |
| Risk Scoring | Yellow |
| Reports | Indigo |

---

### ⚙️ Plugin Configuration Management

Nouvelle fonctionnalité permettant de configurer et tester les intégrations directement depuis l'interface.

#### Fonctionnalités
| Feature | Description |
|---------|-------------|
| **Edit Button** | Bouton crayon sur chaque intégration dans Settings |
| **Configuration Modal** | Formulaire de configuration avec champs appropriés |
| **Connection Testing** | Test automatique de la connexion lors de la sauvegarde |
| **Visual Feedback** | Indicateur vert (Connected) ou rouge (Failed) |
| **Save & Restart** | Sauvegarde et rechargement automatique |

#### Plugins Configurables
| Plugin | Champs |
|--------|--------|
| **Sophos XGS - API** | Host, Port, Username, Password |
| **Sophos XGS - SSH** | Host, Port, Username, SSH Key Path |
| **AbuseIPDB** | API Key |
| **VirusTotal** | API Key |
| **AlienVault OTX** | API Key |
| **GreyNoise** | API Key |
| **Criminal IP** | API Key |
| **Pulsedive** | API Key |

#### Tests de Connexion
| Type | Méthode de Test |
|------|-----------------|
| Sophos API | Test TCP vers le port configuré |
| Sophos SSH | Connexion SSH avec clé privée |
| Threat Intel | Validation du format de clé API |

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/config/test` | POST | Tester une configuration |
| `/config/save` | POST | Sauvegarder et tester |
| `/config` | GET | Récupérer les configurations (masquées) |

---

### 🔄 Active Bans - Simplification

Suppression du module Whitelist de la page Active Bans (page dédiée existante).

#### Changements
- Suppression de la section "Whitelist" de Active Bans
- Suppression du badge "Whitelisted" sur les IPs
- La gestion des whitelists se fait désormais via la page dédiée `/whitelist`

---

### 🌍 High Risk Countries - Extension

Extension de la liste des pays à haut risque de 5 à 10 pays avec affichage du code pays.

#### Nouveaux Pays
| Code | Pays | Risk Level | Base Score |
|------|------|------------|------------|
| KP | North Korea | Critical | 90 |
| IR | Iran | Critical | 85 |
| RU | Russia | High | 70 |
| CN | China | High | 65 |
| BY | Belarus | High | 60 |
| VE | Venezuela | Medium | 50 |
| SY | Syria | Medium | 50 |
| CU | Cuba | Medium | 45 |
| NG | Nigeria | Medium | 40 |
| PK | Pakistan | Medium | 35 |

#### Améliorations UI
- Affichage du country code entre parenthèses : `Russia (RU)`
- Message explicatif : "Reference list - create rules to customize behavior"
- Scroll automatique pour les 10 entrées

---

### 📊 Risk Scoring Dashboard

Nouvelle page dédiée à l'évaluation des risques IP avec scoring multi-facteurs.

#### Scoring Weights
| Composant | Poids | Description |
|-----------|-------|-------------|
| **Threat Intel** | 40% | Score agrégé des 7 providers OSINT |
| **Blocklist** | 30% | Présence dans les listes de blocage |
| **Freshness** | 20% | Fraîcheur des données (decay temporel) |
| **Geolocation** | 10% | Score de risque géographique |

#### Freshness Algorithm
| Paramètre | Valeur | Effet |
|-----------|--------|-------|
| Recent window | ≤ 3 jours | +25% boost |
| Normal window | ≤ 30 jours | 100% (pas de modification) |
| Stale threshold | > 30 jours | Decay exponentiel |
| Decay factor | 7 jours | Half-life du score |
| Floor | 10% | Score minimum après decay |

#### Risk Levels
| Niveau | Score | Couleur |
|--------|-------|---------|
| Critical | ≥ 80 | Rouge |
| High | ≥ 60 | Orange |
| Medium | ≥ 40 | Jaune |
| Low | ≥ 20 | Bleu |
| None | < 20 | Vert |

---

### 📝 Version Update

- Version affichée dans Settings : `v2.3.0`

---

### Fichiers Créés/Modifiés

#### Nouveaux Fichiers
| Fichier | Description |
|---------|-------------|
| `backend/internal/adapter/controller/http/handlers/config.go` | Handler configuration avec test de connexion |

#### Fichiers Modifiés
| Fichier | Modifications |
|---------|---------------|
| `backend/cmd/api/main.go` | Routes `/api/v1/config/*` |
| `backend/internal/entity/geoblocking.go` | 10 pays high-risk |
| `frontend/src/lib/api.ts` | Module `configApi` |
| `frontend/src/pages/Settings.tsx` | Plugin editor modal, version v2.3.0 |
| `frontend/src/pages/ActiveBans.tsx` | Suppression section whitelist |
| `frontend/src/pages/Geoblocking.tsx` | Country codes, message explicatif |

---

## [2.2.0] - 2026-01-07

### Frontend Integration - Soft Whitelist UI

Intégration complète de l'interface utilisateur pour le système Soft Whitelist v2.0.

---

### 🛡️ Soft Whitelist Dashboard

Nouvelle page dédiée à la gestion des whitelists avec support des trois niveaux de confiance.

#### Fonctionnalités UI
| Section | Description |
|---------|-------------|
| **Stats Cards** | Total entries, Hard whitelist, Soft whitelist, Monitor only |
| **IP Check** | Vérification d'une IP avec résultat détaillé (type, score modifier, auto-ban) |
| **Entries List** | Liste filtrable par type avec détails complets |
| **Add Entry Modal** | Création d'entrée avec type, raison, score modifier, TTL, tags |
| **Type Legend** | Explication des trois niveaux de whitelist |

#### Types de Whitelist
| Type | Comportement | Icône |
|------|--------------|-------|
| `hard` | Full bypass - jamais banni, score ignoré | ShieldCheck (vert) |
| `soft` | Score réduit, alerte uniquement (pas d'auto-ban) | Shield (bleu) |
| `monitor` | Logging uniquement, pas d'impact sur score/bans | Eye (jaune) |

#### Fonctionnalités Avancées
- **Score Modifier** : Slider 0-100% pour réduction du score (type soft)
- **Alert Only** : Option pour alerter sans auto-ban
- **TTL Support** : Durée en jours (vide = permanent)
- **Tags** : Catégorisation flexible (CDN, partner, pentest, etc.)
- **CIDR Support** : Affichage des masques CIDR

#### Navigation
- Nouvelle entrée "Whitelist" dans la sidebar avec icône ShieldCheck
- Route `/whitelist` accessible

#### Corrections Backend
- Routes API whitelist corrigées (`/stats`, `/check/{ip}`, `PUT /{ip}`)
- Fix type `int32` pour `ScoreModifier` (compatibilité ClickHouse Int32)

#### Fichiers Ajoutés/Modifiés
| Fichier | Changement |
|---------|------------|
| `frontend/src/types/index.ts` | Types WhitelistEntry, WhitelistRequest, WhitelistCheckResult, WhitelistStats |
| `frontend/src/lib/api.ts` | Module `softWhitelistApi` |
| `frontend/src/pages/SoftWhitelist.tsx` | Page complète |
| `frontend/src/App.tsx` | Route `/whitelist` |
| `frontend/src/components/layout/Sidebar.tsx` | Navigation |
| `backend/cmd/api/main.go` | Routes whitelist v2.0 |
| `backend/internal/entity/ban.go` | Fix int32 ScoreModifier |

---

## [2.1.0] - 2026-01-07

### Frontend Integration - Geoblocking UI

Intégration complète de l'interface utilisateur pour le module Geoblocking v2.0.

---

### 🌍 Geoblocking Dashboard

Nouvelle page dédiée à la gestion du geoblocking avec interface complète.

#### Fonctionnalités UI
| Section | Description |
|---------|-------------|
| **Stats Cards** | Total rules, Active rules, Blocked countries, Watched countries |
| **Rules Management** | Liste, création et suppression des règles |
| **IP Check** | Vérification d'une IP contre les règles actives |
| **GeoIP Lookup** | Recherche géographique avec détection VPN/Proxy/Tor/Datacenter |
| **High-Risk Countries** | Affichage des pays à risque élevé avec scores |

#### Types de Règles Supportés
- `country_block` - Blocage par pays (ISO 3166-1 alpha-2)
- `country_watch` - Surveillance par pays
- `asn_block` - Blocage par ASN
- `asn_watch` - Surveillance par ASN

#### Actions Disponibles
- `block` - Blocage immédiat
- `watch` - Surveillance avec score modifier
- `boost` - Augmentation du score de risque

#### Navigation
- Nouvelle entrée "Geoblocking" dans la sidebar avec icône Globe
- Route `/geoblocking` accessible

#### Fichiers Ajoutés/Modifiés
| Fichier | Changement |
|---------|------------|
| `frontend/src/types/index.ts` | Types TypeScript geoblocking |
| `frontend/src/lib/api.ts` | Module `geoblockingApi` |
| `frontend/src/pages/Geoblocking.tsx` | Page complète |
| `frontend/src/App.tsx` | Route `/geoblocking` |
| `frontend/src/components/layout/Sidebar.tsx` | Navigation |

---

## [2.0.0] - 2026-01-07

### Major Release - Advanced Risk Scoring & Geoblocking

Cette version majeure introduit trois nouveaux modules de sécurité avancés pour une protection plus granulaire et intelligente.

---

### 🛡️ Soft Whitelist System

Remplacement du système de whitelist binaire par un système gradué avec trois niveaux de confiance.

#### Types de Whitelist
| Type | Comportement | Cas d'usage |
|------|--------------|-------------|
| `hard` | Bypass total - jamais banni, score ignoré | Infrastructure critique, partenaires vérifiés |
| `soft` | Score réduit, alerte uniquement (pas de ban auto) | Clients connus, services tiers |
| `monitor` | Logging uniquement, pas d'impact sur score/bans | Surveillance, investigation |

#### Fonctionnalités
- **TTL Support**: Whitelist temporaire avec expiration automatique
- **Score Modifiers**: Réduction de score configurable (0-100%)
- **Tags**: Catégorisation flexible des entrées
- **CIDR Support**: Whitelist de plages IP complètes

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/whitelist` | GET | Liste toutes les entrées whitelist |
| `/whitelist` | POST | Ajoute une entrée (type, TTL, score_modifier) |
| `/whitelist/{ip}` | DELETE | Supprime une entrée |
| `/whitelist/check/{ip}` | GET | Vérifie le statut whitelist d'une IP |

---

### 📊 Freshness Score

Système de scoring temporel qui ajuste les scores de menace selon la fraîcheur des données.

#### Algorithme
```
multiplier = max(minMult, maxMult * e^(-daysOld / decayFactor))

Paramètres par défaut:
- decayFactor: 7 jours (demi-vie)
- minMultiplier: 0.1 (score minimum = 10% après décroissance)
- maxMultiplier: 1.5 (boost activité récente)
- recentActivityBoostDays: 3 jours
- staleThresholdDays: 30 jours
```

#### Comportement
| Âge des données | Multiplicateur | Effet |
|-----------------|----------------|-------|
| < 3 jours | 1.25x | Boost récent |
| 7 jours | ~0.75x | Score réduit |
| 14 jours | ~0.37x | Fortement réduit |
| > 30 jours | 0.1x | Score minimal |

#### Combined Scorer
Le `CombinedScorer` intègre tous les facteurs de risque:
- Score Threat Intel (7 providers)
- Score Blocklists (Feed Ingester)
- Freshness Score (décroissance temporelle)
- Geoblocking Score (pays/ASN)
- Whitelist Modifier (réduction)

---

### 🌍 Geoblocking

Système de blocage géographique par pays et ASN avec lookup GeoIP intégré.

#### Types de Règles
| Type | Description |
|------|-------------|
| `country_block` | Bloquer toutes les IPs d'un pays |
| `country_watch` | Surveiller un pays (boost score) |
| `asn_block` | Bloquer un ASN spécifique |
| `asn_watch` | Surveiller un ASN (boost score) |

#### Actions
| Action | Effet |
|--------|-------|
| `block` | Blocage automatique, `should_block: true` |
| `watch` | Surveillance, boost de score configurable |
| `boost` | Augmentation du score de risque |

#### GeoIP Lookup
- **Provider**: ip-api.com (gratuit, 45 req/min)
- **Cache local**: 24h TTL, 10000 entrées max
- **Détection**: VPN, Proxy, Tor, Datacenter
- **Données**: Pays, Ville, Région, ASN, Coordonnées

#### Pays Haute-Risque par Défaut
| Code | Pays | Score Base |
|------|------|------------|
| RU | Russia | 25 |
| CN | China | 25 |
| KP | North Korea | 30 |
| IR | Iran | 25 |
| BY | Belarus | 20 |
| VE | Venezuela | 15 |
| NG | Nigeria | 15 |
| PK | Pakistan | 15 |
| UA | Ukraine | 10 |
| VN | Vietnam | 10 |

#### API Endpoints
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/geoblocking/rules` | GET | Liste toutes les règles |
| `/geoblocking/rules` | POST | Créer une règle |
| `/geoblocking/rules/{id}` | PUT | Modifier une règle |
| `/geoblocking/rules/{id}` | DELETE | Supprimer une règle |
| `/geoblocking/stats` | GET | Statistiques geoblocking |
| `/geoblocking/check/{ip}` | GET | Vérifier une IP contre les règles |
| `/geoblocking/lookup/{ip}` | GET | Lookup géolocalisation complète |
| `/geoblocking/countries/blocked` | GET | Liste des pays bloqués |
| `/geoblocking/countries/watched` | GET | Liste des pays surveillés |
| `/geoblocking/countries/high-risk` | GET | Liste des pays haute-risque |
| `/geoblocking/cache/refresh` | POST | Rafraîchir le cache des règles |

---

### Database Changes

#### Nouvelles Tables ClickHouse
```sql
-- Whitelist v2.0 avec soft whitelist
CREATE TABLE ip_whitelist_v2 (
    ip IPv4,
    cidr_mask UInt8,
    type LowCardinality(String),      -- hard, soft, monitor
    reason String,
    description String,
    score_modifier Int32,             -- % reduction (0-100)
    alert_only UInt8,
    expires_at Nullable(DateTime),
    tags Array(String),
    created_by String,
    created_at DateTime,
    updated_at DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)

-- Règles de geoblocking
CREATE TABLE geoblock_rules (
    id UUID,
    rule_type LowCardinality(String), -- country_block, country_watch, asn_block, asn_watch
    target String,                    -- Country code (ISO 3166-1) ou ASN
    action LowCardinality(String),    -- block, watch, boost
    score_modifier Int32,
    reason String,
    is_active UInt8,
    created_by String,
    created_at DateTime,
    updated_at DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)

-- Cache géolocalisation
CREATE TABLE ip_geolocation (
    ip IPv4,
    country_code LowCardinality(String),
    country_name String,
    city String,
    region String,
    asn UInt32,
    as_org String,
    is_vpn UInt8,
    is_proxy UInt8,
    is_tor UInt8,
    is_datacenter UInt8,
    latitude Float64,
    longitude Float64,
    last_updated DateTime,
    version UInt64
) ENGINE = ReplacingMergeTree(version)
```

#### Migration
```bash
# Appliquer la migration v2.0
docker exec -i vigilancex-clickhouse clickhouse-client < docker/clickhouse/migrations/005_soft_whitelist_v2.sql
```

---

### Fichiers Créés/Modifiés

#### Nouveaux Fichiers
| Fichier | Description |
|---------|-------------|
| `internal/domain/scoring/freshness.go` | Module Freshness Score avec CombinedScorer |
| `internal/entity/geoblocking.go` | Entités geoblocking (règles, location, résultats) |
| `internal/adapter/external/geoip/client.go` | Client GeoIP avec cache local |
| `internal/adapter/repository/clickhouse/geoblocking_repo.go` | Repository ClickHouse geoblocking |
| `internal/usecase/geoblocking/service.go` | Service geoblocking avec cache règles |
| `internal/adapter/controller/http/handlers/geoblocking.go` | Handlers API geoblocking |
| `docker/clickhouse/migrations/005_soft_whitelist_v2.sql` | Migration tables v2.0 |

#### Fichiers Modifiés
| Fichier | Modifications |
|---------|---------------|
| `internal/entity/ban.go` | Ajout types whitelist (hard/soft/monitor), TTL, tags |
| `internal/adapter/repository/clickhouse/bans_repo.go` | Méthodes whitelist v2 |
| `internal/usecase/bans/service.go` | Logique soft whitelist |
| `cmd/api/main.go` | Intégration services et routes v2.0 |

---

### Technical Stack v2.0
| Component | Technology |
|-----------|------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind CSS |
| Database | ClickHouse (ReplacingMergeTree) |
| Cache | Redis + In-memory (GeoIP) |
| GeoIP | ip-api.com (free tier) |
| Log Pipeline | Vector.dev |
| Deployment | Docker Compose |

---

## [1.6.5] - 2026-01-07

### New Features

#### Blocklist Feed Ingester
Système d'ingestion de blocklists publiques avec synchronisation dynamique pour une protection proactive.

| Feed | Source | Catégorie | IPs |
|------|--------|-----------|-----|
| Firehol Level 1 | GitHub | mixed | ~565k |
| Firehol Level 2 | GitHub | mixed | ~28k |
| Spamhaus DROP | spamhaus.org | malware | ~166k |
| Spamhaus EDROP | spamhaus.org | malware | - |
| Blocklist.de | blocklist.de | attacker | ~24k |
| CI Army | cinsscore.com | attacker | 15k |
| Binary Defense | binarydefense.com | attacker | ~4k |
| Emerging Threats | emergingthreats.net | attacker | ~1.5k |
| DShield | dshield.org | scanner | 20 |
| Feodo Tracker | abuse.ch | botnet | ~4 |
| SSL Blacklist | abuse.ch | c2 | - |

**Caractéristiques clés:**
- Synchronisation automatique avec intervalles configurables (30min - 4h)
- Désactivation dynamique des IPs retirées des sources (`is_active=0`)
- Détection des IPs haute-risque (présentes dans 2+ blocklists)
- Expansion CIDR pour les blocs /24 et plus petits

#### Combined Risk Assessment API
Nouveau endpoint `/api/v1/threats/risk/{ip}` combinant:
- Score Threat Intel (7 providers: AbuseIPDB, VirusTotal, OTX, GreyNoise, IPSum, CriminalIP, Pulsedive)
- Présence dans les blocklists Feed Ingester
- Score combiné avec boost (+10pts par blocklist, max +50pts)
- Recommandation de ban automatique (`recommend_ban: true` si score >= 70)

### API Endpoints

#### Blocklists API (`/api/v1/blocklists`)
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/stats` | GET | Statistiques globales (total IPs, feeds) |
| `/feeds` | GET | Status de tous les feeds |
| `/feeds/configured` | GET | Liste des feeds configurés |
| `/sync` | POST | Synchronisation manuelle de tous les feeds |
| `/feeds/{name}/sync` | POST | Synchronisation d'un feed spécifique |
| `/check/{ip}` | GET | Vérifier si une IP est dans les blocklists |
| `/high-risk` | GET | IPs présentes dans plusieurs blocklists |

#### Threats API (Enhanced)
| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/risk/{ip}` | GET | **Nouveau:** Évaluation combinée threat+blocklist |

### Database Changes

#### New ClickHouse Tables
- `blocklist_ips` - IPs de toutes les sources avec versioning ReplacingMergeTree
- `blocklist_ip_summary` - Agrégation par IP (multi-source)
- `blocklist_feeds` - Status de synchronisation des feeds

### Technical Details

**Fichiers créés:**
- `backend/internal/adapter/external/blocklist/` - Package blocklist complet
  - `feeds.go` - 11 sources configurées
  - `parser.go` - Parseurs multi-formats (IP list, netset, CIDR, DShield, Spamhaus)
  - `ingester.go` - Service d'ingestion avec sync dynamique
- `backend/internal/adapter/repository/clickhouse/blocklist_repo.go`
- `backend/internal/usecase/blocklists/service.go`
- `backend/internal/adapter/controller/http/handlers/blocklists.go`
- `docker/clickhouse/migrations/004_add_blocklist_tables.sql`

---

## [1.6.0] - 2026-01-07

### Threat Intelligence Stack Enhancement

#### New Providers (v1.6)
| Provider | Description | API Key Required |
|----------|-------------|------------------|
| GreyNoise | Benign scanner identification (FP reduction) | Yes |
| IPSum | Aggregated blocklists (30+ sources) | No |
| CriminalIP | C2/VPN/Proxy infrastructure detection | Yes |
| Pulsedive | IOC correlation & threat actors | Yes |

**Total: 7 providers** (AbuseIPDB, VirusTotal, AlienVault OTX + 4 nouveaux)

#### Aggregation Improvements
- Rebalanced weights for 7 providers
- GreyNoise benign flag reduces score by 50% (FP reduction)
- IPSum blocklist count tracked
- CriminalIP VPN/Proxy/Tor/Scanner flags
- Pulsedive threat actors, malware families, campaigns

---

## [1.5.0] - 2026-01-07

### New Features

#### Settings Page
- **Display Settings**: Theme (Dark/Light/System), Language (FR/EN), Time format (24h/12h), Number format
- **Dashboard Settings**: Auto-refresh interval (15s/30s/60s/Manual), Top Attackers count (5/10/20), Animations toggle
- **Notifications**: Enable/disable notifications, Alert sounds, Severity threshold (Critical only / Critical+High)
- **Security**: Session timeout configuration, Mask sensitive IPs option
- **Integrations Status**: Real-time connection status for all integrations

#### Sophos XGS Triple Integration
| Method | Description |
|--------|-------------|
| **Syslog** | Real-time log ingestion (UDP 514 / TCP 1514) with events/min display |
| **SSH** | ModSecurity rules synchronization with last sync timestamp |
| **API** | Ban management via XML API with host and ban count display |

#### Reports Page
- Database statistics (size, event counts, date range)
- Quick reports: Daily, Weekly, Monthly
- Custom reports with date range and module selection
- Export formats: PDF and XML

#### Dashboard Enhancements
- Configurable default time period (1h, 24h, 7d, 30d)
- Dynamic refresh based on user settings
- Top Attackers with country flags (geolocation)
- Clickable Critical Alerts card with modal detail view

### Improvements
- Settings persistence via localStorage
- React Context for global settings state
- Enhanced type definitions for API responses
- JSON tags for proper Go struct serialization

### Technical Stack
| Component | Technology |
|-----------|------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind CSS |
| Database | ClickHouse |
| Cache | Redis |
| Log Pipeline | Vector.dev |
| Deployment | Docker Compose |

---

## [1.0.0] - 2026-01-04

### Initial Release
- Dashboard with real-time security overview
- WAF Explorer for web traffic analysis
- Attacks Analyzer for IPS events
- Advanced Threat tracking (ATP/APT)
- VPN & Network audit
- Active Bans management
- Detect2Ban engine with YAML scenarios
- Threat Intelligence integration (AbuseIPDB, VirusTotal, AlienVault OTX)
- ModSecurity log correlation via SSH
- Sophos XGS API integration for ban sync
