# VIGILANCE X - Live Active Response

> **Version 3.51.100** | Security Operations Center pour Sophos XGS

Solution de supervision de sécurité et de **réponse active centralisée** pour **Sophos XGS**.

📖 **[Quick Install Guide](https://github.com/kr1s57/vigilanceX-SOC/wiki)** - Installation rapide et configuration

---

## Pourquoi VIGILANCE X ? (vs fail2ban)

### Le problème avec fail2ban sur Linux

| Limitation | Impact |
|------------|--------|
| **Configuration lourde** | Jails et policies complexes par serveur |
| **Gestion décentralisée** | Chaque serveur = configuration isolée |
| **Interface CLI uniquement** | Pas de visibilité globale, pas de dashboard |
| **Pas de notifications** | Aucune alerte temps réel |
| **Pas de corrélation** | Chaque serveur voit uniquement ses propres logs |
| **Maintenance complexe** | Mise à jour des règles serveur par serveur |

### La solution VIGILANCE X

**VIGILANCE X centralise la réponse active** pour toute votre infrastructure :

| Avantage | Description |
|----------|-------------|
| **Centralisation totale** | Un seul point de contrôle pour tous vos serveurs |
| **Interface Web moderne** | Dashboard temps réel, graphiques, historique |
| **Moteur Detect2Ban (D2B)** | Remplacement intelligent de fail2ban |
| **Policies YAML** | Scénarios de détection configurables |
| **Threat Intelligence** | Corrélation avec 11+ providers (CrowdSec, AbuseIPDB, VirusTotal...) |
| **Notifications** | Alertes email temps réel, rapports programmés |
| **Blocage au niveau firewall** | Blocage directement sur Sophos XGS (pas iptables local) |
| **Historique et audit** | Traçabilité complète des bans/unbans |

### Architecture Detect2Ban vs fail2ban

```
┌─────────────────────────────────────────────────────────────────┐
│                    AVANT (fail2ban)                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Server 1          Server 2          Server 3                  │
│   ┌─────────┐       ┌─────────┐       ┌─────────┐              │
│   │fail2ban │       │fail2ban │       │fail2ban │              │
│   │ jails   │       │ jails   │       │ jails   │              │
│   │iptables │       │iptables │       │iptables │              │
│   └─────────┘       └─────────┘       └─────────┘              │
│        ↓                 ↓                 ↓                    │
│   Ban local         Ban local         Ban local                 │
│   (isolé)           (isolé)           (isolé)                   │
│                                                                 │
│   ❌ Pas de vue globale                                         │
│   ❌ Pas de corrélation cross-server                            │
│   ❌ Maintenance x N serveurs                                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    APRÈS (VIGILANCE X)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Server 1          Server 2          Server 3                  │
│   ┌─────────┐       ┌─────────┐       ┌─────────┐              │
│   │ Syslog  │       │ Syslog  │       │ Syslog  │              │
│   └────┬────┘       └────┬────┘       └────┬────┘              │
│        │                 │                 │                    │
│        └────────────────┬┴─────────────────┘                    │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   VIGILANCE X       │                           │
│              │  ┌───────────────┐  │                           │
│              │  │  Detect2Ban   │  │ ◄── Threat Intel APIs     │
│              │  │  Engine       │  │     (CrowdSec, VT, etc.)  │
│              │  └───────┬───────┘  │                           │
│              │          │          │                           │
│              │  ┌───────▼───────┐  │                           │
│              │  │  Policies     │  │                           │
│              │  │  YAML         │  │                           │
│              │  └───────┬───────┘  │                           │
│              └──────────┼──────────┘                           │
│                         ▼                                       │
│              ┌─────────────────────┐                           │
│              │   Sophos XGS        │                           │
│              │   (Ban global)      │                           │
│              └─────────────────────┘                           │
│                                                                 │
│   ✅ Vue centralisée                                            │
│   ✅ Corrélation multi-sources                                  │
│   ✅ Dashboard temps réel                                       │
│   ✅ Notifications et rapports                                  │
│   ✅ Ban au niveau firewall (pas iptables)                      │
└─────────────────────────────────────────────────────────────────┘
```

### Fonctionnalités D2B avancées

| Fonctionnalité | Description |
|----------------|-------------|
| **Scénarios YAML** | Règles de détection personnalisables |
| **Validate Threat** | Vérification croisée avec APIs avant ban |
| **Récidivisme** | Ban progressif (4 bans = permanent) |
| **Immunité** | Protection temporaire contre auto-ban (Unban 24h) |
| **Soft Whitelist** | Whitelist graduée (hard/soft/monitor) |
| **Geoblocking** | Blocage par pays/ASN |
| **XGS Sync** | Synchronisation bidirectionnelle avec firewall |

---

## Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.22 (Chi router, Clean Architecture) |
| Frontend | React 18 + TypeScript + Tailwind + Shadcn UI |
| Base de données | ClickHouse (analytique temps réel) |
| Cache | Redis |
| Ingestion | Vector.dev (Syslog) |
| Déploiement | Docker Compose |

## Fonctionnalités

- **Dashboard temps réel** : Vue d'ensemble de la posture de sécurité
- **WAF Explorer** : Analyse détaillée du trafic Web protégé
- **Attacks Analyzer** : Focus sur l'IPS et les tentatives d'intrusion
- **Advanced Threat** : Suivi des alertes ATP et APT
- **VPN & Network** : Audit des accès distants
- **Active Bans** : Gestion des blocages en temps réel
- **Blocklist Ingester** : Synchronisation dynamique de 11 blocklists publiques
- **Soft Whitelist** : Système de whitelist graduée (hard/soft/monitor) *(v2.0)*
- **Geoblocking** : Blocage par pays/ASN avec GeoIP lookup *(v2.0)*
- **Freshness Score** : Scoring temporel avec décroissance exponentielle *(v2.0)*
- **Risk Scoring UI** : Interface de visualisation des scores de risque *(v2.3)*
- **System Protected IPs** : IPs système protégées (DNS, CDN, Monitoring) *(v2.5)*
- **Icon Style** : Personnalisation des icônes sidebar (Monochrome/Color) *(v2.5)*
- **Authentication** : Portail de connexion JWT avec RBAC (admin/audit) *(v2.6)*
- **User Management** : Gestion des utilisateurs et rôles (admin) *(v2.6)*
- **XGS Parser Engine** : Moteur de parsing natif pour logs Sophos XGS *(v3.1)*
- **Reports** : Génération de rapports PDF/XML (journalier, hebdomadaire, mensuel)
- **Settings** : Configuration complète (thème, langue, notifications, intégrations)

### Intégrations Sophos XGS

| Méthode | Port | Usage |
|---------|------|-------|
| **Syslog** | UDP 514 / TCP 1514 | Réception des logs firewall en temps réel |
| **SSH** | 22 | Synchronisation des règles ModSecurity |
| **API XML** | 4444 | Gestion des bans (ajout/suppression IP blocklist) |

### Threat Intelligence (v1.6)

7 providers intégrés pour une analyse complète des menaces :

| Provider | Description |
|----------|-------------|
| AbuseIPDB | Réputation IP basée sur les reports |
| VirusTotal | Consensus multi-AV |
| AlienVault OTX | Contexte de menace et IOCs |
| GreyNoise | Réduction des faux positifs (scanners bénins) |
| IPSum | Agrégation de 30+ blocklists |
| CriminalIP | Détection C2/VPN/Proxy |
| Pulsedive | Corrélation IOC et acteurs de menace |

### Blocklist Feed Ingester

Ingestion automatique de blocklists publiques avec sync dynamique :

| Feed | Catégorie | ~IPs |
|------|-----------|------|
| Firehol Level 1 & 2 | mixed | 590k |
| Spamhaus DROP/EDROP | malware | 166k |
| Blocklist.de | attacker | 24k |
| CI Army | attacker | 15k |
| Binary Defense | attacker | 4k |
| Emerging Threats | attacker | 1.5k |
| Feodo Tracker | botnet | active C2 |
| DShield | scanner | top 20 |

**Total : ~800k IPs uniques**

### Soft Whitelist (v2.0)

Système de whitelist graduée remplaçant le binaire on/off :

| Type | Comportement |
|------|--------------|
| `hard` | Bypass total - jamais banni, score ignoré |
| `soft` | Score réduit (configurable), alerte uniquement |
| `monitor` | Logging uniquement, pas d'impact |

- Support TTL avec expiration automatique
- Modificateurs de score (0-100%)
- Tags pour catégorisation

### Geoblocking (v2.0)

Blocage géographique par pays et ASN :

| Type | Description |
|------|-------------|
| `country_block` | Bloquer toutes les IPs d'un pays |
| `country_watch` | Surveiller un pays (boost score) |
| `asn_block` | Bloquer un ASN spécifique |
| `asn_watch` | Surveiller un ASN (boost score) |

- GeoIP lookup via ip-api.com avec cache local
- Détection VPN/Proxy/Tor/Datacenter
- 10 pays haute-risque préconfigurés

### Freshness Score (v2.0)

Scoring temporel avec décroissance exponentielle :

| Âge des données | Multiplicateur |
|-----------------|----------------|
| < 3 jours | 1.25x (boost) |
| 7 jours | ~0.75x |
| 14 jours | ~0.37x |
| > 30 jours | 0.1x (minimal) |

### System Protected IPs (v2.5)

IPs système protégées automatiquement contre tout blocage :

| Catégorie | Fournisseurs |
|-----------|-------------|
| **DNS** | Cloudflare (1.1.1.1, 1.0.0.1), Google (8.8.8.8, 8.8.4.4), Quad9, OpenDNS |
| **Cloud** | AWS Health Checks, Google Cloud Health |
| **Monitoring** | UptimeRobot, Pingdom, StatusCake |
| **NTP** | NIST Time Servers |

Ces IPs sont visibles dans la page Whitelist avec toggle affichage.

### Icon Style (v2.5)

Personnalisation du style des icônes de navigation :

| Style | Description |
|-------|-------------|
| **Monochrome** | Icônes monochromes classiques |
| **Color** | Icônes colorées par catégorie |

### Authentication & RBAC (v2.6)

Système d'authentification complet avec contrôle d'accès basé sur les rôles.

#### Rôles

| Rôle | Description | Accès |
|------|-------------|-------|
| **admin** | Administrateur | Accès complet + Settings + Gestion utilisateurs |
| **audit** | Audit/Lecture seule | Visualisation uniquement, pas de ban/unban |

#### Restrictions Audit

| Page | Accès |
|------|-------|
| Dashboard, WAF, Attacks, Threats, VPN, Bans, Geoblocking, Whitelist, Scoring | ✅ Lecture |
| Reports, Settings, Users | ❌ Admin uniquement |
| Actions ban/unban | ❌ Désactivé |

#### Fonctionnalités

- **JWT Authentication** : Tokens avec validité 24h
- **Login Portal** : Interface de connexion sécurisée
- **User Management** : CRUD utilisateurs (admin)
- **Password Reset CLI** : Outil de récupération d'urgence
- **WebSocket Auth** : Connexions temps réel authentifiées

### XGS Parser Engine (v3.1)

Moteur de parsing propriétaire pour les logs Sophos XGS avec décodeurs XML et règles de détection.

#### Architecture XML

| Fichier | Description | Contenu |
|---------|-------------|---------|
| `vigilanceX_XGS_decoders.xml` | Définition des champs | 104 champs, 17 groupes |
| `vigilanceX_XGS_rules.xml` | Règles de détection | 74 règles, 10 catégories |

#### Groupes de Champs (Decoders)

| Groupe | Champs | Description |
|--------|--------|-------------|
| `device_identity` | 3 | Identification firewall (serial, model, name) |
| `log_metadata` | 5 | Métadonnées log (log_id, timestamp, type) |
| `network_layer` | 8 | Couche réseau (IPs, ports, protocol, zones) |
| `user_identity` | 5 | Identité utilisateur |
| `http_request` | 8 | Requêtes HTTP (method, url, status) |
| `tls_analysis` | 4 | Analyse TLS (version, cipher_suite, sni) |
| `threat_intel` | 6 | Threat intelligence (threatfeed, malware) |
| `waf_modsec` | 6 | WAF/ModSecurity (reason, rule_id) |
| `vpn_session` | 8 | Sessions VPN |
| `endpoint_health` | 5 | Synchronized Security |
| `email_fields` | 6 | Anti-spam |
| `firewall_action` | 5 | Actions firewall |
| `atp_sandbox` | 5 | ATP/Sandstorm |
| `antivirus` | 4 | Anti-virus |
| `nat_translation` | 4 | NAT |
| `bandwidth` | 4 | Bande passante |
| `custom` | 2 | Champs personnalisés |

#### Catégories de Règles

| Catégorie | Règles | ID Range | Description |
|-----------|--------|----------|-------------|
| WAF Attack Detection | 15 | 100xxx | SQL injection, XSS, RCE, LFI |
| ATP Threats | 8 | 200xxx | C2, malware, zero-day |
| IPS Alerts | 8 | 300xxx | Intrusion, exploit |
| VPN Security | 10 | 400xxx | Auth failure, brute force |
| Firewall Violations | 8 | 500xxx | Zone violations, scanning |
| Sandstorm Analysis | 6 | 600xxx | Sandbox results, APT |
| Authentication | 8 | 700xxx | Login failures |
| Endpoint Health | 4 | 800xxx | Heartbeat status |
| Email Threats | 4 | 900xxx | Spam, phishing |
| Custom Rules | 3 | 990xxx | Règles personnalisées |

#### MITRE ATT&CK Coverage

23 techniques MITRE ATT&CK mappées :

| Tactique | Techniques |
|----------|------------|
| Initial Access | T1190, T1133 |
| Execution | T1059 |
| Defense Evasion | T1070, T1562 |
| Credential Access | T1110, T1003 |
| Discovery | T1046, T1018 |
| Command & Control | T1071, T1573, T1095 |
| Exfiltration | T1041, T1567 |
| Impact | T1499, T1486 |

#### API Endpoints Parser

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/v1/parser/stats` | GET | Statistiques du parser |
| `/api/v1/parser/fields` | GET | Définitions des champs |
| `/api/v1/parser/rules` | GET | Règles par catégorie |
| `/api/v1/parser/mitre` | GET | Couverture MITRE ATT&CK |
| `/api/v1/parser/test` | POST | Test de parsing d'un log |

### Moteur Detect2Ban

- Scénarios YAML configurables
- Récidivisme automatique (4 bans = permanent)
- Synchronisation avec groupes Sophos XGS
- Combined Risk Assessment (Threat Intel + Blocklists)

## Démarrage Rapide

### Prérequis

- Docker & Docker Compose
- Sophos XGS Firewall avec accès administrateur
- Clés API Threat Intel (optionnel)

### Configuration Sophos XGS

#### 1. Créer un compte de service API

1. Aller dans `Administration > Device access > Local service accounts`
2. Créer un nouveau compte :
   - **Nom** : `vigilance_api`
   - **Type** : Administrateur
3. Dans **Profil**, créer un nouveau profil `vigilance_profil` avec les permissions :
   - **Lecture/Écriture** sur `System - Objets`

#### 2. Configurer l'envoi des logs Syslog

1. Aller dans `System services > Log settings`
2. Ajouter un serveur Syslog :

| Paramètre | Valeur |
|-----------|--------|
| **Serveur** | IP du serveur VIGILANCE X |
| **Port** | 514 |
| **Installation** | daemon |
| **Niveau de gravité** | information |
| **Format** | Standard Syslog Protocol |

#### 3. Activer l'API XML

1. Aller dans `Backup & firmware > API`
2. **Activer** l'API
3. Ajouter l'IP du serveur VIGILANCE X dans les IP autorisées

#### 4. Créer le groupe de blocage

1. Aller dans `Hosts and services > IP host group`
2. Créer le groupe : `VIGILANCE_X_BLOCKLIST`
3. Créer une règle Firewall **DROP** utilisant ce groupe

### Installation

```bash
# Cloner le projet
cd /opt/vigilanceX

# Copier et configurer l'environnement
cp .env.example .env
# Éditer .env avec vos paramètres

# Démarrer les services
cd docker
docker-compose up -d

# Vérifier les logs
docker-compose logs -f
```

### Accès

- **Dashboard** : http://localhost:3000
- **API** : http://localhost:8080
- **ClickHouse** : http://localhost:8123
- **Vector** : http://localhost:8686

## Architecture

```
Sophos XGS
    │
    ├── Syslog (UDP 514) ──► Vector.dev ──► ClickHouse
    │
    └── API XML (4444) ◄──► Backend Go
                              │
                              ├── API REST
                              ├── WebSocket
                              └── Detect2Ban Engine
                                    │
                                    ▼
                              Frontend React
```

## Structure du Projet

```
vigilance-x/
├── docker/           # Docker Compose et configs
├── backend/          # API Go + Detect2Ban
│   ├── cmd/          # Points d'entrée
│   ├── internal/     # Code applicatif
│   └── scenarios/    # Scénarios YAML
├── frontend/         # React SPA
├── docs/             # Documentation
└── scripts/          # Scripts utilitaires
```

## Développement

### Backend

```bash
cd backend
make tidy        # Télécharger les dépendances
make build       # Compiler
make run-api     # Lancer l'API
make test        # Tests
```

### Frontend

```bash
cd frontend
npm install
npm run dev      # Dev server
npm run build    # Build production
```

## API Endpoints

### Core
| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/v1/events` | Liste des événements |
| `GET /api/v1/stats/overview` | Statistiques globales |

### Bans
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/bans` | Bans actifs |
| `POST /api/v1/bans` | Créer un ban |
| `DELETE /api/v1/bans/{ip}` | Supprimer un ban |

### Threats (v1.6)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/threats/check/{ip}` | Analyse threat intel complète |
| `GET /api/v1/threats/risk/{ip}` | Évaluation combinée threat+blocklist |
| `GET /api/v1/threats/should-ban/{ip}` | Recommandation de ban |
| `GET /api/v1/threats/providers` | Status des 7 providers |

### Blocklists
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/blocklists/stats` | Statistiques (total IPs, feeds) |
| `GET /api/v1/blocklists/feeds` | Status de tous les feeds |
| `POST /api/v1/blocklists/sync` | Synchronisation manuelle |
| `GET /api/v1/blocklists/check/{ip}` | Vérifier une IP |
| `GET /api/v1/blocklists/high-risk` | IPs multi-sources |

### Geoblocking (v2.0)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/geoblocking/rules` | Liste des règles |
| `POST /api/v1/geoblocking/rules` | Créer une règle |
| `PUT /api/v1/geoblocking/rules/{id}` | Modifier une règle |
| `DELETE /api/v1/geoblocking/rules/{id}` | Supprimer une règle |
| `GET /api/v1/geoblocking/check/{ip}` | Vérifier une IP |
| `GET /api/v1/geoblocking/lookup/{ip}` | Lookup géolocalisation |
| `GET /api/v1/geoblocking/countries/blocked` | Pays bloqués |
| `GET /api/v1/geoblocking/countries/high-risk` | Pays haute-risque |

### Whitelist (v2.0)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/whitelist` | Liste des entrées |
| `POST /api/v1/whitelist` | Ajouter (type, TTL, score_modifier) |
| `DELETE /api/v1/whitelist/{ip}` | Supprimer |

### Config (v2.5)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/config/system-whitelist` | IPs système protégées |
| `GET /api/v1/config/settings` | Paramètres application |
| `PUT /api/v1/config/settings` | Modifier paramètres |

### Authentication (v2.6)
| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/login` | Authentification (retourne JWT) |
| `POST /api/v1/auth/logout` | Déconnexion |
| `GET /api/v1/auth/me` | Infos utilisateur courant |
| `POST /api/v1/auth/change-password` | Changer son mot de passe |

### Users (v2.6 - Admin)
| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/users` | Liste des utilisateurs |
| `POST /api/v1/users` | Créer un utilisateur |
| `GET /api/v1/users/{id}` | Détails utilisateur |
| `PUT /api/v1/users/{id}` | Modifier utilisateur |
| `DELETE /api/v1/users/{id}` | Supprimer utilisateur |
| `POST /api/v1/users/{id}/reset-password` | Reset mot de passe |

## Configuration Authentification

### Variables d'environnement

```bash
# JWT
JWT_SECRET=your-secure-jwt-secret-min-32-chars
JWT_EXPIRY=24h

# Admin par défaut (premier démarrage)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!
```

### Utilisateur Admin par défaut

Au premier démarrage, si aucun utilisateur n'existe, un compte admin est créé automatiquement avec les credentials définis dans les variables d'environnement.

### Reset mot de passe (urgence)

En cas de perte du mot de passe admin :

```bash
docker exec vigilance_backend /app/reset-password <username> <new_password>
```

**Mot de passe par défaut pour les resets** : `Admin12345`

Exemple :
```bash
docker exec vigilance_backend /app/reset-password admin Admin12345
```

## Versioning

VIGILANCE X utilise un schema de versioning **X.Y.Z** :

| Digit | Nom | Description |
|-------|-----|-------------|
| **X** | MAJOR | Montée de version majeure (sur demande explicite) |
| **Y** | FEATURE | Ajout de fonctionnalités (+1 par feature) |
| **Z** | BUGFIX | Corrections de bugs (commence à 100) |

**Règles d'incrémentation :**

```
Bugfix    : X.Y.Z   → X.Y.Z+1     (ex: 3.2.105 → 3.2.106)
Feature   : X.Y.Z   → X.Y+1.100   (ex: 3.2.106 → 3.3.100)
Major     : X.Y.Z   → X+1.0.100   (ex: 3.10.115 → 4.0.100)
```

- Le digit BUGFIX (Z) **commence à 100** et s'incrémente pour chaque correction
- Le digit BUGFIX **revient à 100** lors d'une montée FEATURE
- Les digits FEATURE et BUGFIX **reviennent à 0 et 100** lors d'une montée MAJOR

## Licence

MIT

## Auteur

Développé par l'équipe VIGILANCE X
