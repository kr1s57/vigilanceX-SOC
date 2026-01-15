# VIGILANCE X

**La plateforme SOC temps réel conçue pour Sophos XGS**

[![Version](https://img.shields.io/badge/version-3.55.112-blue.svg)]()
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

### Étape 1 - Cloner et configurer

```bash
# Cloner le repository
git clone https://github.com/kr1s57/vigilanceX-SOC.git
cd vigilanceX-SOC

# Se connecter au registry Docker (token fourni avec licence)
echo "VOTRE_TOKEN" | docker login ghcr.io -u kr1s57 --password-stdin
```

### Étape 2 - Créer le fichier .env

Créer le fichier `deploy/.env` avec le contenu suivant :

```bash
# ======================================
# VIGILANCE X - Configuration
# ======================================

# === Base de données ===
CLICKHOUSE_USER=vigilance
CLICKHOUSE_PASSWORD=VOTRE_MOT_DE_PASSE_CH

# === Cache Redis ===
REDIS_PASSWORD=VOTRE_MOT_DE_PASSE_REDIS

# === Authentification ===
JWT_SECRET=votre-cle-secrete-jwt-minimum-32-caracteres
ADMIN_USERNAME=admin
ADMIN_PASSWORD=VigilanceX2024!

# === Sophos XGS Integration ===
SOPHOS_HOST=IP_DE_VOTRE_SOPHOS_XGS
SOPHOS_PORT=4444
SOPHOS_USER=admin
SOPHOS_PASSWORD=VOTRE_MOT_DE_PASSE_XGS

# === Licence (optionnel si Fresh Deploy) ===
LICENSE_KEY=

# === Version (optionnel, défaut: latest) ===
# VGX_VERSION=3.55.112
```

### Étape 3 - Démarrer les services

```bash
cd deploy
docker compose pull
docker compose up -d
```

### Étape 4 - Accéder au dashboard

```
URL: http://VOTRE_IP:3000
Login: admin
Password: VigilanceX2024!
```

> **Note** : Après le premier login, configurez votre licence via l'interface ou utilisez Fresh Deploy pour un trial de 15 jours.

---

## Déploiement via Reverse Proxy (WAF/nginx)

Si vous accédez à VIGILANCE X via un reverse proxy (Sophos WAF, nginx, etc.) :

```bash
# Accès direct au backend pour tests
curl http://localhost:8080/health

# Le frontend est sur le port 3000
curl http://localhost:3000
```

**Configuration nginx recommandée** :
```nginx
location / {
    proxy_pass http://vigilance_frontend;
}

location /api/ {
    proxy_pass http://vigilance_backend:8080;
}

location /ws {
    proxy_pass http://vigilance_backend:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
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
