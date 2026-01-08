Le modèle On-Premise + Heartbeat est le standard industriel pour les solutions de cybersécurité : il rassure le client sur la confidentialité des logs (qui restent chez lui) tout en te garantissant le contrôle commercial.
Voici le plan d'action structuré sous forme de Backlog Technique.

1. Sécurisation et Distribution (Packaging)
Objectif : Rendre l'application inviolable et opaque pour l'utilisateur final.
	•	Migration vers un Registre Privé :
	◦	Mettre en place un pipeline CI/CD (GitHub Actions ou GitLab CI).
	◦	Configurer la publication automatique des images vers Docker Hub (Private) ou GitHub Container Registry.
	•	Renforcement du Backend (Go) :
	◦	Compiler les binaires Go avec les flags de réduction de debug : go build -ldflags="-s -w".
	◦	Intégrer une étape de vérification de signature des images Docker pour éviter les modifications malveillantes.
	•	Obfuscation Frontend (React) :
	◦	Configurer Vite pour supprimer tous les console.log et commentaires en production.
	◦	Utiliser un plugin d'obfuscation (ex: javascript-obfuscator) sur les chunks JS pour rendre le reverse-engineering du Dashboard illisible.

2. Système de Licensing (Le "Kill Switch")
Objectif : Créer un lien de dépendance entre l'instance locale et ton autorité de licence.
	•	Développement du "Licensing Server" (Central) :
	◦	Créer une API minimale pour gérer : Clés de licence, Date d'expiration, IP autorisée, Nombre de Sophos XGS max.
	•	Intégration du Client de Licence (Dans VIGILANCE X) :
	◦	Phase d'Initialisation : Au premier lancement, l'app demande une clé. Elle génère un HardwareID unique (basé sur le CPU/ID Docker) et l'envoie à ton serveur.
	◦	Le mécanisme de Heartbeat : Le backend Go doit vérifier la licence toutes les 12h ou 24h.
	◦	Mode Dégradé (Fail-Safe) : Si la licence expire ou est révoquée, le backend doit bloquer les routes API critiques et n'afficher qu'une page "Licence Invalide" sur le frontend.

3. Architecture "Proxy API" pour les Coûts OSINT
Objectif : Empêcher le vol de tes clés d'API payantes (VirusTotal, etc.).
	•	Développement d'un Middleware de Relais :
	◦	Déplacer les appels API OSINT du backend client vers ton propre serveur "Proxy".
	◦	Le client envoie une requête IP à ton serveur -> Ton serveur vérifie que la licence est active -> Ton serveur interroge VirusTotal/AbuseIPDB -> Renvoie le résultat.
	•	Sécurité : Les clés API réelles ne doivent jamais être présentes dans les fichiers .env ou le code livré au client.

4. Plan de déploiement (Action Plan)
Phase
Tâche Prioritaire
Responsable
P1 - Build
Script de build Go avec stripping + Obfuscation React
Dev Backend / DevOps
P2 - Control
Création du serveur de licences + API Heartbeat
Dev Backend
P3 - Integration
Module de vérification dans VIGILANCE X (Go)
Dev Backend
P4 - Proxy
Déportation des clés OSINT vers un serveur relais
Dev Backend / PM
P5 - Delivery
Création du nouveau docker-compose.yml pointant vers les images privées
DevOps
