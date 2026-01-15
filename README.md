# VIGILANCE X

**Plateforme SOC Next-Gen pour Sophos XGS**

---

## La Solution VIGILANCE X

VIGILANCE X centralise la supervision et la réponse active pour toute votre infrastructure Sophos XGS :

- **Visibilité totale** — Tous vos logs WAF, IPS, VPN, ATP et Antivirus dans une interface unifiée
- **Parser Sophos natif** — Support de 100+ champs XGS, 70+ règles de détection, mapping MITRE ATT&CK
- **Analyse en temps réel** — Visualisez instantanément chaque blocage, chaque attaque, chaque menace
- **Threat Intelligence** — Enrichissement automatique des IPs via 11 sources (AbuseIPDB, VirusTotal, CrowdSec...)
- **Réponse automatisée** — Détection et bannissement des menaces directement sur votre firewall XGS
- **Cartographie des attaques** — Carte mondiale interactive des flux d'attaques
- **Reporting avancé** — Rapports PDF/XML programmables avec envoi automatique par email

**[→ Démarrage rapide](#démarrage-rapide)**

---

## Fonctionnalités

| Module | Description |
|--------|-------------|
| **Dashboard** | Centre de commandement avec métriques temps réel et notifications |
| **WAF Explorer** | Visualisation des blocages WAF — Debug et tuning des règles ModSecurity |
| **Attacks Analyzer** | Analyse statistique des attaques, patterns et campagnes |
| **Attack Map** | Carte mondiale interactive des flux d'attaques en temps réel |
| **Advanced Threat** | Lookup multi-providers avec score de risque agrégé |
| **VPN & Network** | Supervision des sessions VPN et activité réseau |
| **Geoblocking** | Politiques de blocage géographique avec statistiques par pays |
| **Soft Whitelist** | Gestion graduée des IPs de confiance (Hard/Soft/Monitor) |
| **Detect2Ban** | Détection automatique et bannissement sur le firewall XGS |
| **Vigimail Checker** | Surveillance fuites email + vérification DNS (SPF/DKIM/DMARC) |
| **Neural-Sync** | Synchronisation des blocklists CrowdSec premium vers XGS |
| **Reports** | Génération de rapports PDF/XML programmables |

---

## Table des Matières

### Guide Utilisateur
- [Dashboard](#dashboard)
- [WAF Explorer](#waf-explorer)
- [Attacks Analyzer](#attacks-analyzer)
- [Attack Map](#attack-map)
- [Advanced Threat](#advanced-threat)
- [VPN & Network](#vpn--network)
- [Geoblocking](#geoblocking)
- [Soft Whitelist](#soft-whitelist)
- [Detect2Ban](#detect2ban)
- [Vigimail Checker](#vigimail-checker)
- [Neural-Sync](#neural-sync)
- [Reports](#reports)
- [Settings](#settings)

### Guide Administrateur
- [Prérequis Système](#prérequis-système)
- [Sécurité et Déploiement](#sécurité-et-déploiement)
- [Démarrage Rapide](#démarrage-rapide)
- [Configuration Sophos XGS](#configuration-sophos-xgs)
- [Commandes de Maintenance](#commandes-de-maintenance)
- [Structure des Fichiers](#structure-des-fichiers)
- [Logs et Diagnostics](#logs-et-diagnostics)
- [Sauvegarde et Restauration](#sauvegarde-et-restauration)

### Support
- [Contact](#contact)
- [Licence](#licence)

---

# Guide Utilisateur

## Dashboard

Le Dashboard est votre centre de commandement sécurité, offrant une vue synthétique de l'état de votre infrastructure.

**Éléments affichés :**
- Score de sécurité global
- Compteur de menaces actives
- Résumé des IPs bannies
- Timeline des événements récents
- Top des attaquants
- Distribution géographique des attaques
- Notifications en temps réel

**Cas d'usage :**
- Briefing sécurité quotidien
- Point de départ pour le triage d'incidents
- Présentations pour la direction

---

## WAF Explorer

Explorez en profondeur les événements du Web Application Firewall avec des outils de filtrage et d'analyse complets.

**Fonctionnalités :**
- Navigation hiérarchique (par jour, règle, IP)
- Catégorisation des règles et indicateurs de sévérité
- Inspection des payloads requête/réponse
- Corrélation des Rule ID ModSecurity
- Identification des patterns d'attaque
- Boutons Expand/Collapse All
- Sélecteur de période (7j/14j/30j)

**Cas d'usage :**
- Investigation des attaques web
- Tuning des règles WAF
- Identification des faux positifs
- Compréhension des techniques d'attaque

---

## Attacks Analyzer

Analyse statistique des patterns d'attaques avec représentations visuelles et identification des tendances.

**Fonctionnalités :**
- Graphique timeline des attaques
- Top des attaques par catégorie
- Résumé des attaquants uniques
- Distribution par type d'attaque
- Modal d'investigation IP
- Analyse de fréquence des triggers

**Cas d'usage :**
- Identification des campagnes d'attaques
- Analyse des tendances
- Priorisation des réponses
- Génération de rapports d'attaques

---

## Attack Map

Visualisation interactive mondiale des origines et patterns d'attaques.

**Fonctionnalités :**
- Flux d'attaques animés sur carte mondiale
- Filtrage par type (WAF, IPS, Malware, Threat)
- Sélection multi-types
- Sélecteur de période (Live/24h/7d/30d)
- Modal détail pays avec Top IPs
- Enrichissement géographique automatique

**Cas d'usage :**
- Visualisation de la géographie des attaques
- Identification des régions hostiles
- Présentations et reporting
- Monitoring temps réel

---

## Advanced Threat

Lookup complet de threat intelligence et analyse pour n'importe quelle adresse IP.

**Fonctionnalités :**
- Score de menace multi-providers (11 sources)
- Évaluation du niveau de risque (Critical/High/Medium/Low/Minimal)
- Détails par provider
- Timeline historique des attaques
- Suivi de l'historique des bans
- Vérification par lot d'IPs

**Providers intégrés :**
AbuseIPDB, VirusTotal, GreyNoise, CrowdSec CTI, Pulsedive, CriminalIP, AlienVault OTX, IPsum, Shodan InternetDB, ThreatFox, URLhaus

**Cas d'usage :**
- Investigation d'IPs suspectes
- Évaluation préventive des menaces
- Investigation d'incidents
- Threat hunting

---

## VPN & Network

Supervision des connexions VPN et de l'activité réseau.

**Fonctionnalités :**
- Sessions VPN actives
- Historique des connexions par jour
- Suivi de l'activité utilisateur
- Métriques de durée de session
- Mapping géographique des connexions

**Cas d'usage :**
- Monitoring des accès distants
- Identification d'activité VPN inhabituelle
- Audit de conformité
- Revue d'activité utilisateur

---

## Geoblocking

Implémentation de politiques d'accès géographiques basées sur le pays d'origine.

**Fonctionnalités :**
- Règles allow/deny par pays
- Statistiques des pays les plus attaquants
- Gestion des règles (ajout/modification/suppression)
- Modal détail pays
- Création de règles en masse

**Cas d'usage :**
- Blocage des régions hostiles
- Conformité réglementaire
- Réduction de la surface d'attaque
- Autorisation de pays spécifiques uniquement

---

## Soft Whitelist

Système de whitelist gradué pour gérer les IPs de confiance avec flexibilité.

**Fonctionnalités :**
- Trois niveaux : Hard, Soft, Monitor
- Support IP/CIDR
- Dates d'expiration
- Champs notes et justification
- Actions rapides (promotion/rétrogradation)

**Niveaux de Whitelist :**
| Niveau | Comportement |
|--------|--------------|
| **Hard** | Immunité complète contre le blocage |
| **Soft** | Alertes générées mais pas de blocage automatique |
| **Monitor** | Journalisé avec visibilité accrue |

**Cas d'usage :**
- Gestion des IPs partenaires
- Accès temporaires
- Exclusions de test
- Protection clients VIP

---

## Detect2Ban

Moteur de détection et réponse automatisée intégré à VIGILANCE X.

**Fonctionnalités :**
- Détection basée sur des scénarios YAML configurables
- Corrélation multi-sources (WAF, IPS, brute-force...)
- Validation Threat Intelligence avant ban
- Bannissement direct sur le firewall Sophos XGS via API
- Tiers progressifs (récidivisme)
- Classification géographique (GeoZone)
- Immunité temporaire pour faux positifs
- Historique complet des actions

**Avantages :**
- Centralisation : une console pour tous vos serveurs
- Visibilité : dashboard, graphiques, historique complet
- Intelligence : enrichissement TI avant décision
- Action firewall : ban au niveau XGS, pas iptables local
- Traçabilité : audit trail de chaque action

**Cas d'usage :**
- Protection automatisée contre les attaques WAF
- Détection de brute-force
- Réponse aux menaces identifiées par Threat Intelligence

---

## Vigimail Checker

Surveillance de la sécurité email pour la détection de fuites et la vérification de configuration.

**Fonctionnalités :**
- Gestion des domaines
- Surveillance des adresses email
- Détection de fuites de données (HaveIBeenPwned, LeakCheck)
- Vérification DNS (SPF, DKIM, DMARC, MX)
- Vérifications périodiques automatisées
- Détails des fuites avec informations sur les breaches

**Cas d'usage :**
- Surveillance de l'exposition des emails d'entreprise
- Vérification de la configuration sécurité email
- Conformité aux politiques de sécurité
- Monitoring proactif des credentials

---

## Neural-Sync

Intégration premium des blocklists CrowdSec pour une protection renforcée.

**Fonctionnalités :**
- Gestion des abonnements aux blocklists CrowdSec
- Synchronisation automatique des IPs
- Enrichissement pays pour les IPs blocklist
- Intégration groupe firewall XGS
- Statut et historique de synchronisation

**Cas d'usage :**
- Exploitation de l'intelligence communautaire
- Blocage proactif d'IPs malveillantes connues
- Protection périmétrique renforcée
- Flux de menaces automatisés

---

## Reports

Génération et planification de rapports sécurité en plusieurs formats.

**Fonctionnalités :**
- Génération de rapports à la demande
- Rapports programmés (Quotidien/Hebdomadaire/Mensuel)
- Export PDF et XML
- Envoi par email avec pièces jointes
- Périodes personnalisables

**Contenu des Rapports :**
- Résumé exécutif
- Statistiques d'attaques
- Top des menaces
- Analyse géographique
- Comparaisons de tendances

**Cas d'usage :**
- Reporting de conformité
- Briefings direction
- Documentation d'audit
- Archives d'incidents

---

## Settings

Hub central de configuration pour toutes les fonctionnalités VIGILANCE X.

**Sections :**
- **Général** : Préférences système et options d'affichage
- **Intégrations** : Connexions aux services externes
  - Sophos Firewall (Syslog, SSH, API)
  - CrowdSec (CTI, Blocklist)
  - Providers Threat Intelligence
  - Notifications Email (SMTP)
  - Fonctionnalités Premium (Neural-Sync)
- **Detect2Ban** : Configuration de détection et réponse automatique
- **Log Retention** : Gestion du cycle de vie des données
- **User Management** : Administration des comptes

---

# Guide Administrateur

## Prérequis Système

### Matériel Minimum
| Composant | Requis |
|-----------|--------|
| CPU | 4 cœurs |
| RAM | 8 Go |
| Stockage | 100 Go SSD |
| Réseau | 1 Gbps |

### Matériel Recommandé
| Composant | Requis |
|-----------|--------|
| CPU | 8+ cœurs |
| RAM | 16+ Go |
| Stockage | 500 Go NVMe |
| Réseau | 1 Gbps |

### Logiciels Requis
- Docker Engine 24.0+
- Docker Compose 2.20+
- Linux (Ubuntu 22.04 LTS recommandé)

### Ports Réseau
| Port | Protocole | Usage |
|------|-----------|-------|
| 80 | TCP | Redirection HTTP |
| 443 | TCP | Interface web HTTPS |
| 514 | UDP | Réception Syslog |
| 1514 | TCP | Réception Syslog (TCP) |

---

## Sécurité et Déploiement

### Architecture Sécurisée Recommandée

> **VIGILANCE X est un outil SIEM critique qui ne doit JAMAIS être exposé sur Internet.**

Comme tout outil de sécurité (firewall, SIEM, console d'administration), VIGILANCE X doit être déployé dans un environnement réseau sécurisé et isolé.

### Recommandations de Déploiement

| Aspect | Recommandation |
|--------|----------------|
| **Exposition réseau** | Réseau interne uniquement — Aucune exposition Internet |
| **VLAN** | Déployer dans un VLAN dédié à l'administration sécurité |
| **Accès réseau** | Limiter aux IPs des administrateurs sécurité uniquement |
| **Accès distant** | VPN obligatoire pour tout accès hors site |
| **Utilisateurs** | Restreindre aux membres autorisés (équipe sécurité/infra) |

### Pourquoi cette isolation ?

VIGILANCE X contient et traite des informations sensibles :
- Logs de sécurité complets (WAF, IPS, VPN, ATP)
- Adresses IP internes et externes
- Patterns d'attaques et signatures
- Configuration du firewall Sophos XGS
- Données de Threat Intelligence

Exposer cette interface reviendrait à donner aux attaquants :
- Une cartographie complète de votre infrastructure
- Les règles de détection et leurs seuils
- Les IPs bannies (qu'ils pourraient contourner)
- Des vecteurs d'attaque potentiels vers le firewall

### Modèle d'Accès Recommandé

```
┌─────────────────────────────────────────────────────────────┐
│                        INTERNET                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ (Aucun accès direct)
                              ✕
┌─────────────────────────────────────────────────────────────┐
│                     FIREWALL (XGS)                          │
│                   VPN Gateway + Rules                        │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌─────────────────┐   ┌───────────────────┐
│ VLAN Servers  │   │ VLAN Admin/Sécu │   │    VPN Users      │
│               │   │                 │   │  (Autorisés)      │
│  Syslog ────────► │  VIGILANCE X    │ ◄─────────────────────┤
│               │   │  (Port 443)     │   │                   │
└───────────────┘   └─────────────────┘   └───────────────────┘
                              │
                    Accès limité aux:
                    • Administrateurs infra
                    • Équipe sécurité
                    • Auditeurs autorisés
```

### Règles Firewall Suggérées

```
# Autoriser Syslog depuis les serveurs
ALLOW UDP/514, TCP/1514 FROM servers_vlan TO vigilancex_ip

# Autoriser HTTPS depuis VLAN Admin uniquement
ALLOW TCP/443 FROM admin_vlan TO vigilancex_ip

# Autoriser HTTPS depuis VPN (utilisateurs autorisés)
ALLOW TCP/443 FROM vpn_pool TO vigilancex_ip

# Bloquer tout autre accès
DENY ANY TO vigilancex_ip
```

### Accès Base de Données

Les bases de données VIGILANCE X (ClickHouse, Redis) ne sont accessibles que depuis les conteneurs Docker internes. Seuls les administrateurs qui implémentent, administrent et opèrent la plateforme doivent avoir accès au serveur hébergeant VIGILANCE X.

---

## Démarrage Rapide

### 1. Cloner le dépôt
```bash
git clone https://github.com/kr1s57/vigilanceX-SOC.git
cd vigilanceX-SOC
```

### 2. Configurer l'environnement
```bash
cp .env.example docker/.env
nano docker/.env
```

**Variables essentielles à modifier :**
- `CLICKHOUSE_PASSWORD` — Mot de passe base de données
- `REDIS_PASSWORD` — Mot de passe cache Redis
- `JWT_SECRET` — Clé secrète JWT (générer avec `openssl rand -hex 32`)
- `SOPHOS_HOST` — IP de votre firewall Sophos XGS
- `SOPHOS_PASSWORD` — Mot de passe API Sophos

### 3. Démarrer les services
```bash
cd docker
docker compose up -d
```

### 4. Accéder à l'interface
```
https://votre-serveur-ip
Identifiants par défaut : admin / VigilanceX2024!
```

> **Important** : Changez le mot de passe admin dès la première connexion via Settings > User Management.

### Variables d'Environnement Essentielles

```bash
# Connexion Sophos XGS
SOPHOS_HOST=10.x.x.x
SOPHOS_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASSWORD=votre_mot_de_passe

# Base de données
CLICKHOUSE_PASSWORD=mot_de_passe_securise

# Authentification
JWT_SECRET=cle-secrete-minimum-32-caracteres
ADMIN_PASSWORD=changer_ce_mot_de_passe

# Licence
LICENSE_KEY=votre_cle_de_licence
```

### Post-Installation

1. **Changer le mot de passe par défaut** — Immédiatement après la première connexion
2. **Configurer Sophos XGS** — Ajouter la destination syslog pointant vers VIGILANCE X
3. **Activer la licence** — Entrer votre clé de licence ou demander un essai
4. **Configurer les intégrations** — Paramétrer les clés API Threat Intelligence

---

## Configuration Sophos XGS

### Configuration Syslog

1. Connectez-vous à Sophos XGS Central
2. Naviguez vers **System** > **Logs & Reports** > **Log Settings**
3. Ajoutez un nouveau serveur syslog :
   - IP : Adresse IP de votre serveur VIGILANCE X
   - Port : 514 (UDP) ou 1514 (TCP)
   - Facility : Local0
   - Severity : Informational
4. Sélectionnez les types de logs à transmettre :
   - Web Filter
   - IPS
   - WAF
   - ATP
   - VPN

### Certificats SSL

Remplacez les certificats auto-signés par défaut :

```bash
# Copier vos certificats
cp votre_cert.crt docker/nginx/ssl/server.crt
cp votre_cle.key docker/nginx/ssl/server.key

# Redémarrer nginx
docker compose restart nginx
```

---

## Commandes de Maintenance

### Contrôle des Services

```bash
# Démarrer tous les services
docker compose up -d

# Arrêter tous les services
docker compose down

# Redémarrer un service spécifique
docker compose restart api
docker compose restart frontend
docker compose restart clickhouse

# Voir le statut des services
docker compose ps
```

### Logs

```bash
# Voir tous les logs
docker compose logs -f

# Voir les logs d'un service spécifique
docker compose logs -f api
docker compose logs -f clickhouse

# Voir les 100 dernières lignes
docker compose logs --tail=100 api
```

### Reset Mot de Passe

Si vous perdez l'accès au compte admin :

```bash
# Reset interactif
docker compose exec api /app/reset-password

# Reset direct
docker compose exec api /app/reset-password -u admin -p NouveauMotDePasse123!
```

### Maintenance Base de Données

```bash
# Accéder au CLI ClickHouse
docker compose exec clickhouse clickhouse-client

# Vérifier la taille de la base
docker compose exec clickhouse clickhouse-client -q "SELECT formatReadableSize(sum(bytes)) FROM system.parts WHERE active"

# Nettoyage manuel (utiliser avec précaution)
docker compose exec clickhouse clickhouse-client -q "OPTIMIZE TABLE vigilance_x.events FINAL"
```

### Mises à Jour

```bash
# Récupérer les dernières images
docker compose pull

# Recréer les containers
docker compose up -d --force-recreate

# Nettoyer les anciennes images
docker image prune -f
```

---

## Structure des Fichiers

```
vigilanceX/
├── docker/
│   ├── docker-compose.yml    # Définitions des services
│   ├── .env                  # Configuration environnement
│   ├── clickhouse/
│   │   ├── config/          # Configuration ClickHouse
│   │   └── migrations/      # Migrations base de données
│   ├── nginx/
│   │   ├── nginx.conf       # Configuration serveur web
│   │   └── ssl/             # Certificats SSL
│   └── vector/
│       └── vector.toml      # Configuration ingestion logs
├── backend/                  # Code source API
└── frontend/                 # Code source interface web
```

### Chemins Importants

| Chemin | Usage |
|--------|-------|
| `/opt/vigilanceX/docker/.env` | Fichier de configuration principal |
| `/opt/vigilanceX/docker/nginx/ssl/` | Certificats SSL |
| `/var/lib/docker/volumes/` | Stockage des données persistantes |

---

## Logs et Diagnostics

### Logs Applicatifs

| Log | Emplacement | Usage |
|-----|-------------|-------|
| API | `docker compose logs api` | Opérations backend |
| Frontend | `docker compose logs frontend` | Interface web |
| Database | `docker compose logs clickhouse` | Stockage données |
| Ingestion | `docker compose logs vector` | Réception logs |

### Vérifications de Santé

```bash
# Vérifier tous les services
docker compose ps

# Santé API
curl -s http://localhost:8080/health

# Santé ClickHouse
docker compose exec clickhouse clickhouse-client -q "SELECT 1"
```

### Problèmes Courants

**Services qui ne démarrent pas :**
```bash
docker compose logs --tail=50 [nom_service]
```

**Erreurs de connexion base de données :**
```bash
docker compose restart clickhouse
docker compose restart api
```

**Pas de logs reçus :**
- Vérifier que le firewall autorise UDP 514 / TCP 1514
- Vérifier la configuration syslog sur Sophos XGS
- Vérifier que Vector tourne : `docker compose logs vector`

---

## Sauvegarde et Restauration

### Sauvegarde

```bash
# Arrêter les services
docker compose down

# Sauvegarder les volumes de données
tar -czvf vigilancex-backup-$(date +%Y%m%d).tar.gz \
  /var/lib/docker/volumes/docker_clickhouse_data \
  /var/lib/docker/volumes/docker_redis_data

# Sauvegarder la configuration
cp .env .env.backup
```

### Restauration

```bash
# Arrêter les services
docker compose down

# Restaurer les volumes de données
tar -xzvf vigilancex-backup-YYYYMMDD.tar.gz -C /

# Démarrer les services
docker compose up -d
```

---

# Support

## Contact

Pour le support, les demandes de licence ou les suggestions :

**Email :** contact@vigilancex.io

**GitHub Issues :** [github.com/kr1s57/vigilanceX-SOC/issues](https://github.com/kr1s57/vigilanceX-SOC/issues)

---

## Licence

VIGILANCE X nécessite une licence valide pour un fonctionnement complet.

### Types de Licence

| Type | Durée | Fonctionnalités |
|------|-------|-----------------|
| Trial | 15 jours | Toutes les fonctionnalités |
| Professional | 1 an | Toutes les fonctionnalités + support |
| Enterprise | Personnalisé | Fonctionnalités personnalisées + support prioritaire |

### Activation

1. Naviguez vers **Settings** > **License**
2. Entrez votre clé de licence
3. Cliquez sur **Activate**

Pour les licences d'essai, cliquez sur **Request Trial** depuis l'écran d'activation.

---

**VIGILANCE X** — Plateforme SOC Next-Gen pour Sophos XGS

*Conçu pour la sécurité, pensé pour les professionnels.*
