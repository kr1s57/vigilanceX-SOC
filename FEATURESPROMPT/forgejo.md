**Contexte : Architecture Git Local & Backup Privé**

Je souhaite automatiser la sauvegarde de mes projets vers mon instance **Forgejo** personnelle. Cette instance est hébergée sur un serveur local, accessible uniquement via SSH et non exposée sur Internet.

**Objectifs :**

1. Analyser la pertinence de cette architecture (Sécurité vs Redondance).
2. Configurer les "remotes" Git pour trois projets spécifiques : `vigilanceX`, `vigilanceX-SOC` et `vigilanceKey`.
3. Automatiser le push du contenu vers Forgejo pour garantir un backup systématique.

**Détails Techniques :**

- **Serveur :** Accès SSH déjà configuré dans mon `~/.ssh/config` (ou précise l'IP/User).
- **Projets à traiter :** `vigilanceX`, `vigilanceX-SOC`, `vigilanceKey`.
- **Action attendue :** > - Vérifie si les dépôts existent sur Forgejo via SSH.
    - Si non, aide-moi à les créer (via l'API Forgejo ou ligne de commande).
    - Ajoute un remote nommé `forgejo` ou `backup` à chaque projet local.
    - Effectue un premier push complet.

**Sécurité :** Ne modifie aucune configuration d'exposition réseau. Le serveur doit rester strictement local.

**Analyse :** Avant de commencer, donne-moi ton avis sur cette stratégie de backup "Air-gapped" (isolée) et si tu vois des points d'amélioration.
