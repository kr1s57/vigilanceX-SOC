# 🛡️ VIGILANCE X - Live Active Response

**VIGILANCE X** est une solution de supervision de sécurité et de réponse active automatisée conçue spécifiquement pour l'écosystème **Sophos XGS**. Elle transforme les flux de logs passifs en actions défensives immédiates grâce à la corrélation intelligente et l'automatisation via API.

---

## 📋 Table des Matières
- [Vision & Objectifs](#vision--objectifs)
- [Architecture Technique](#architecture-technique)
- [Sources de Données & Corrélation](#sources-de-données--corrélation)
- [Moteur Detect2Ban](#moteur-detect2ban)
- [Fonctionnalités WebUI](#fonctionnalités-webui)
- [Installation & Sécurité](#installation--sécurité)

---

## 🎯 Vision & Objectifs
Le projet vise à combler l'écart entre la détection (logs) et la réaction (blocage). 
- **Centraliser :** Collecter l'intégralité des logs Sophos XGS (Syslog).
- **Analyser :** Corréler les événements (WAF, IPS, ATP, Antivirus).
- **Réagir :** Bannir automatiquement les attaquants via l'API XML du Sophos.
- **Visualiser :** Offrir une interface moderne dédiée aux opérations de sécurité (SOC).

---

## 🏗️ Architecture Technique

### Stack Recommandée
- **OS :** Ubuntu Server 22.04+ (Partition 300Go pour `/var/lib/vigilance_x`)
- **Ingestion :** Vector.dev (Parser haute performance)
- **Base de Données :** ClickHouse (Stockage analytique des logs)
- **Backend :** Go ou Python (FastAPI)
- **Frontend :** React ou Vue.js (Tailwind CSS / Shadcn UI)
- **Communications :** - API XML Sophos (Port 4444)
    - SSH avec clé publique (Récupération logs profonds)

---

## 🔍 Sources de Données & Corrélation
VIGILANCE X analyse les flux suivants pour identifier les comportements malveillants :

| Module | Log Type | Action Critique |
| :--- | :--- | :--- |
| **WAF** | `log_type="WAF"` | Blocage sur injections (SQLi, XSS). |
| **ATP** | `log_type="ATP"` | Isolement immédiat sur détection de C&C. |
| **IPS** | `log_type="IPS"` | Bannissement sur Scan de ports / Exploits. |
| **Antivirus** | `log_type="Anti-Virus"` | Blocage des sources de distribution de Malware. |
| **Heartbeat** | `log_type="Heartbeat"` | Monitoring de l'état de santé des endpoints (MDR). |
| **Threat Intel** | Flux Externes | Intégration Sophos X-Ops & AbuseIPDB. |

---

## ⚡ Moteur Detect2Ban
Le cœur du projet repose sur un moteur de décision en 4 étapes :
1. **Parsing :** Normalisation des logs Syslog en JSON.
2. **Scénarios (YAML) :** Définition de seuils (ex: 5 drops WAF + 1 alerte IPS = Blocage).
3. **Validation :** Vérification de la réputation de l'IP via des API tierces.
4. **Action LAR :** - Appel API Sophos pour ajout dans le groupe `VIGILANCE_X_BLOCKLIST`.
    - Notification Webhook (Discord/Slack).
    - Gestion du TTL (Expiration automatique du bannissement).

---

## 💻 Fonctionnalités WebUI
Interface "Dark Mode" structurée en 6 modules :
- **Dashboard :** Vue d'ensemble de la posture de sécurité.
- **WAF Explorer :** Analyse détaillée du trafic Web protégé.
- **Attacks Analyzer :** Focus sur l'IPS et les tentatives d'intrusion.
- **Advanced Threat :** Suivi des alertes ATP et de la santé des hôtes (MDR).
- **VPN & Network :** Audit des accès distants et performances interfaces.
- **Active Bans :** Gestion en temps réel des blocages en cours.

---

## 🔒 Installation & Sécurité
### Prérequis Sophos XGS
1. Activer l'API XML dans `System > Administration > API`.
2. Autoriser l'IP du serveur Vigilance X pour l'accès API et SSH.
3. Créer une règle de Firewall prioritaire (Drop) utilisant le groupe `VIGILANCE_X_BLOCKLIST`.

### Sécurisation du Serveur LAR
- Accès WebUI limité au LAN / VPN.
- Authentification MFA obligatoire.
- Chiffrement des logs au repos.

---
*Projet conçu pour une infrastructure hybride Cyber/DevOps. Développé par l'équipe VIGILANCE X.*
