1. 🏗️ Master Prompt : Packaging, Distribution & Documentation Client
Contexte : Je développe VigilanceX, une solution de sécurité/réseau Fullstack (Go/React). Je souhaite automatiser sa distribution vers un dépôt Git privé dédié aux clients (VigilanceX-Distribution). Le public cible est composé d'administrateurs réseaux et d'ingénieurs IT.
Objectif :
	1	Sécuriser le code (obfuscation/compilation).
	2	Automatiser le déploiement vers le dépôt client.
	3	Générer une documentation technique (Wiki/Markdown) de niveau professionnel.

1. Hardening & Pipeline de Distribution (CI/CD)
Configure un workflow (GitHub Actions/GitLab CI) qui réalise les étapes suivantes à chaque nouveau tag de version :
	•	Backend (Go) : Compilation avec -ldflags="-s -w", compression via UPX, et scan de vulnérabilités.
	•	Frontend (React) : Build avec obfuscation stricte (flux logique écrasé, suppression logs/commentaires, encodage des strings).
	•	Containerisation : Signature des images avec Cosign.
	•	Synchronisation Client : Le pipeline doit automatiser un git push des fichiers nécessaires (uniquement docker-compose.yml, .env.example, et les scripts de config) vers le repository privé "VigilanceX-Client".
2. Structure du Repository Client
L'agent doit organiser le dépôt client de la manière suivante :
	•	deploy/ : Contient le docker-compose.yml pointant vers les images sécurisées de mon registre privé.
	•	config/ : Modèles de configuration pour les modules et l'API.
	•	scripts/ : Scripts d'installation (ex: install.sh, setup-ssl.sh).
	•	README.md : Guide d'accueil et de démarrage rapide.

3. Système de Mise à Jour (Update Flow)
L'agent doit mettre en place une structure permettant une mise à jour simple :
	•	Script vigilance.sh : Crée un script wrapper à la racine du dépôt client qui gère les commandes :
	◦	./vigilance.sh install : Vérifie les prérequis (Docker/Docker-compose) et lance l'installation.
	◦	./vigilance.sh update : Exécute un git pull, effectue un docker-compose pull et relance les containers (up -d). Ce script doit inclure une étape de sauvegarde automatique du volume de base de données avant la montée de version.
	•	Gestion des Tags : Utilise des tags d'images Docker fixes (ex: v1.2.0) dans le compose plutôt que latest pour garantir la stabilité et permettre le rollback.


4. Rédaction du Wiki / Documentation Technique (Cible : Admins IT)
Génère un ensemble de fichiers Markdown pour le Wiki du dépôt client, structurés ainsi :
	•	🏠 Home / Architecture : Schéma de fonctionnement de VigilanceX, flux réseau utilisés (ports, protocoles), et prérequis système (CPU/RAM/OS).
	•	🚀 Guide d'Installation : Procédure pas à pas pour Docker/Podman, gestion des volumes persistants et déploiement en environnement air-gapped.
	•	⚙️ Configuration des Modules & API :
	◦	Détails des variables d'environnement.
	◦	Documentation des endpoints API (format OpenAPI/Swagger).
	◦	Guide de connexion au module de licence.
	•	🛡️ Sécurité & Hardening :
	◦	Explication des mesures de protection (images signées, binaire strippé).
	◦	Bonnes pratiques pour isoler le container (Network policies, non-root user).
	◦	Gestion des certificats SSL/TLS.
	•	🛠️ Administration & Troubleshooting : Diagnostic des logs, procédures de mise à jour et sauvegarde des données.

Livrables attendus :
	1	Le script CI/CD de "Mirroring Sécurisé" vers le dépôt client.
	2	Le Dockerfile et les fichiers de config obfuscés.
	3	L'arborescence complète du Wiki client au format .md.

Conseils pour votre Wiki :
Comme vos clients sont des administrateurs réseaux, je vous suggère d'inclure dans la section "Sécurité" un tableau des flux réseau (Matrice d'ouverture de ports) :
Composant
Port
Protocole
Direction
Description
Dashboard UI
443
TCP
Entrant
Accès utilisateur HTTPS
API Backend
8080
TCP
Interne
Communication inter-services
License Check
443
TCP
Sortant
Validation vers votre serveur
Souhaitez-vous que je rédige un exemple de script d'installation (install.sh) automatisé que l'agent devra inclure pour vos clients ?


