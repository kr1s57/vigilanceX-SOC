# VIGILANCE X

**La plateforme SOC temps réel conçue pour Sophos XGS**

[![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)]()
[![License](https://img.shields.io/badge/license-Commercial-green.svg)]()
[![Sophos](https://img.shields.io/badge/Sophos-XGS%20Ready-red.svg)]()

---

## Le Problème

**80% des administrateurs désactivent le WAF de leur Sophos XGS.**

Pourquoi ? Parce que ModSecurity génère trop de faux positifs, et la WebUI Sophos ne permet pas de debugger efficacement. Résultat : des heures perdues à analyser des milliers de lignes de logs en CLI pour trouver les règles qui bloquent.

**VIGILANCE X change la donne.**

---

## Ce que VIGILANCE X Apporte

### WAF Debug Engine - *Notre Force*

> *"De plusieurs heures de debug à 30 secondes."*

Contrairement aux solutions syslog classiques qui ne capturent pas les IDs ModSecurity, VIGILANCE X corrèle automatiquement chaque blocage WAF avec ses règles déclencheuses.

| Avant VIGILANCE X | Avec VIGILANCE X |
|-------------------|------------------|
| SSH sur le XGS | Interface web intuitive |
| `grep` dans des milliers de lignes | Vue consolidée instantanée |
| Heures de debug | **30 secondes** |
| WAF souvent désactivé | WAF optimisé et actif |

**Fonctionnalités clés :**
- Identification instantanée des règles ModSec bloquantes
- Distinction rapide entre blocages légitimes et faux positifs
- Historique des patterns de blocage par application
- Recommandations d'exclusions ciblées

---

### Risk Scoring Engine

Notre moteur de scoring propriétaire ne se contente pas d'interroger des APIs. Il **corrèle** les données pour établir un score de risque contextuel.

```
                    ┌─────────────────────┐
   Threat Intel ───►│                     │
   (11 providers)   │   RISK SCORING      │───► Score 0-100
                    │     ENGINE          │───► Threat Level
   Internal ───────►│                     │───► Action recommandée
   Policies         └─────────────────────┘
```

**Sources intégrées :**
- AbuseIPDB, VirusTotal, GreyNoise, CrowdSec
- AlienVault OTX, Shodan, IPSum, ThreatFox
- Pulsedive, CriminalIP, URLhaus

**Ce qui nous différencie :**
- Système de cascade intelligent (économise vos quotas API)
- Corrélation avec vos policies internes
- Score contextuel basé sur VOTRE infrastructure
- Historique et tendances par IP

---

### Active Response - Detect2Ban

> *"Le fail2ban nouvelle génération pour environnements critiques."*

Detect2Ban va au-delà de la simple détection. C'est un système **Active/Response** qui protège vos assets en temps réel.

**Scénario type :**
```
22:47 - IP 185.x.x.x scanne votre serveur web critique
22:47 - Detect2Ban détecte le pattern d'attaque
22:47 - Score de risque calculé : 87/100 (Critical)
22:47 - IP marquée "BANNED" dans VIGILANCE X
22:47 - IP créée sur Sophos XGS
22:47 - IP ajoutée au groupe VIGILANCE_X_BLOCKLIST
22:47 - Trafic DROP immédiat

       Temps total : < 5 secondes
```

**Capacités :**
- Réponse automatique 24/7
- Escalade progressive (warn → temp ban → permanent)
- Intégration native API XML Sophos
- Synchronisation bidirectionnelle des blocklists
- Policies personnalisables par criticité d'asset

---

### XGS Parser Engine (v3.1) - *Nouveau*

> *"Parsing natif des logs Sophos XGS avec 104 champs et 74 règles de détection"*

Notre moteur de parsing propriétaire analyse en profondeur chaque log Sophos XGS.

**Architecture XML :**

| Fichier | Description |
|---------|-------------|
| `vigilanceX_XGS_decoders.xml` | 104 champs extraits dans 17 groupes |
| `vigilanceX_XGS_rules.xml` | 74 règles de détection dans 10 catégories |

**Groupes de champs extraits :**
- **Device Identity** : Serial firewall (binding VX3), modèle, nom
- **Network Layer** : IPs source/destination, ports, protocoles, zones
- **TLS Analysis** : Version TLS, cipher suite, SNI
- **Threat Intel** : Threatfeeds, malware détecté, classification
- **VPN Session** : Connexions, tunnels, bytes in/out
- **Endpoint Health** : Synchronized Security, heartbeat status
- **WAF/ModSec** : Raison blocage, IDs règles, sévérité

**Règles de détection par catégorie :**

| Catégorie | Règles | Description |
|-----------|--------|-------------|
| WAF Attacks | 15 | SQL injection, XSS, RCE, LFI, scanners |
| ATP Threats | 8 | C2, malware, zero-day |
| IPS Alerts | 8 | Intrusion, exploits |
| VPN Security | 10 | Auth failures, brute force |
| Firewall | 8 | Zone violations, port scanning |
| Sandstorm | 6 | Sandbox analysis, APT |
| Authentication | 8 | Login failures |

**MITRE ATT&CK Coverage : 23 techniques mappées**
- Initial Access, Credential Access, Command & Control
- Defense Evasion, Discovery, Exfiltration, Impact

---

### Syslog Server Nouvelle Génération

VIGILANCE X ingère et structure **tous** vos logs Sophos XGS :

| Type de Log | Traitement |
|-------------|------------|
| WAF / ModSecurity | Parsing avancé avec extraction IDs |
| IPS/IDS | Corrélation avec Threat Intel |
| Firewall | Timeline et géolocalisation |
| Authentication | Détection brute-force |
| VPN | Monitoring sessions |
| Web Filter | Catégorisation et tendances |

**Architecture haute performance :**
- **Vector.dev** pour l'ingestion (100K+ events/sec)
- **ClickHouse** pour l'analytique temps réel
- **WebSocket** pour le dashboard live

---

## Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.22 (haute performance) |
| Frontend | React + TypeScript |
| Database | ClickHouse (analytique) |
| Ingestion | Vector.dev |
| Cache | Redis |
| Conteneurisation | Docker |

---

## Prérequis

- **Serveur** : Ubuntu 22.04 LTS, 4GB RAM, 20GB SSD
- **Firewall** : Sophos XGS (toute version supportant Syslog)
- **Réseau** : Accès Syslog (UDP 514 / TCP 1514)
- **Licence** : Clé VIGILANCE X active

---

## Installation Rapide

```bash
# 1. Cloner le repository
git clone https://github.com/kr1s57/vigilanceX-SOC.git
cd vigilanceX-SOC

# 2. Se connecter au registry Docker
echo "VOTRE_TOKEN" | docker login ghcr.io -u kr1s57 --password-stdin

# 3. Configurer
cp deploy/config.template deploy/.env
nano deploy/.env

# 4. Installer et démarrer
./vigilance.sh install
./vigilance.sh start

# 5. Accéder au dashboard
# https://VOTRE_IP (admin / VigilanceX2024!)
```

---

## Configuration Sophos XGS

### Activer Syslog

1. **System** → **Administration** → **Notification** → **Syslog**
2. Ajouter un serveur :
   - IP : Votre serveur VIGILANCE X
   - Port : 514 (UDP) ou 1514 (TCP)
3. Sélectionner les logs : WAF, IPS, Firewall, Auth, VPN

### Activer l'API XML (pour Active Response)

1. **System** → **Administration** → **Admin Settings**
2. Activer "Allow API access"
3. Noter le port (défaut : 4444)

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](wiki/Installation-Guide.md) | Guide complet d'installation |
| [Configuration](wiki/Configuration.md) | Variables et paramètres |
| [Architecture](wiki/Architecture.md) | Schémas et flux réseau |
| [Administration](wiki/Administration.md) | Backup, updates, users |
| [Sécurité](wiki/Security-Hardening.md) | Hardening et bonnes pratiques |
| [Troubleshooting](wiki/Troubleshooting.md) | Diagnostic et résolution |

---

## Commandes Essentielles

```bash
./vigilance.sh status      # État des services
./vigilance.sh logs        # Voir les logs
./vigilance.sh backup      # Backup des données
./vigilance.sh update      # Mise à jour
./vigilance.sh restart     # Redémarrer
```

---

## Support

- **Email** : support@vigilancex.io
- **Documentation** : wiki/
- **Licence** : Settings → License dans le dashboard

---

## Sécurité

- Images Docker signées (Cosign)
- Binaires obfusqués
- TLS 1.2+ obligatoire
- Authentification JWT
- RBAC (admin/audit)

---

<p align="center">
  <strong>VIGILANCE X</strong><br>
  <em>Transformez votre Sophos XGS en plateforme SOC</em>
</p>
