**Objet : Implémentation du stockage externe des logs (Phase 1 : SMB)**

**Contexte :**
Le projet **VigilanceX** doit pouvoir traiter et stocker une quantité massive de logs provenant de l'ingestion **XGS**. Actuellement, le stockage est local. Nous devons migrer vers une solution de stockage externe configurable pour garantir la scalabilité.

**Objectifs :**

1. **Interface Utilisateur (Paramètres) :**
    - Dans le menu **Settings**, créer une nouvelle section **Storage**.
    - Implémenter une interface (via accordéons ou modales) permettant de configurer les types de stockage.
    - Prévoir les champs pour **SMB** (obligatoire maintenant) et préparer le squelette pour **S3/MinIO** (phase ultérieure, grisé ou marqué "Coming Soon").
    - Les champs SMB doivent inclure : Host, Share Name, Username, Password, et Domain.
    
2. **Backend & Logique d'ingestion :**
    - Modifier le flux d'ingestion des logs **XGS**.
    - Au lieu de l'écriture locale, rediriger le flux vers le stockage SMB configuré.
    - Mettre en place une couche d'abstraction (Interface/Provider) pour le stockage afin de faciliter l'ajout futur de S3.
    
3. **Détails Techniques :**
    - Assurer la gestion des erreurs de connexion au partage réseau (retry logic).
    - Sécuriser les identifiants de stockage.
    - Vérifier que les performances d'écriture ne ralentissent pas le processus d'ingestion XGS.

**Livrables attendus :**

- Le code frontend pour la page Settings.
- Le service de gestion du stockage (Storage Manager/Provider).
- La modification du worker d'ingestion XGS pour utiliser le nouveau provider.
