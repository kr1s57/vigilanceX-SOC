Documentation Complète sur les Niveaux de Paranoïa dans le Core Rule Set (CRS)
Introduction
Le Core Rule Set (CRS) de ModSecurity est un ensemble de règles de sécurité conçues pour protéger
les applications web contre une large gamme de menaces, y compris les attaques par injection, les
scripts intersites (XSS), et bien d'autres. L'une des fonctionnalités clés du CRS est la gestion des
niveaux de paranoïa, qui permettent d'ajuster la sensibilité des règles de sécurité en fonction des
besoins spécifiques de votre environnement.
Cette documentation détaillée explore les niveaux de paranoïa du CRS, leur configuration, leurs
implications et les meilleures pratiques pour optimiser la sécurité de votre application web.
Table des Matières
1. Qu'est-ce que le Core Rule Set (CRS) ?
2. Comprendre les Niveaux de Paranoïa
3. Les Différents Niveaux de Paranoïa
o Niveau 1 : Basique
o Niveau 2 : Standard
o Niveau 3 : Avancé
o Niveau 4 : Très Avancé
o Niveau 5 : Extrême
4. Configuration des Niveaux de Paranoïa
5. Implications des Niveaux de Paranoïa
6. Meilleures Pratiques
7. Exemples de Configuration
8. Conclusion
Qu'est-ce que le Core Rule Set (CRS) ?
Le Core Rule Set (CRS) est un ensemble de règles de sécurité open-source développées par l'OWASP
(Open Web Application Security Project). Ces règles sont destinées à fournir une protection robuste
contre les attaques courantes ciblant les applications web. Le CRS fonctionne avec ModSecurity, un
pare-feu d'applications web (WAF) qui analyse et filtre le trafic HTTP pour détecter et prévenir les
attaques.
Comprendre les Niveaux de Paranoïa
Les niveaux de paranoïa dans le CRS permettent aux administrateurs de contrôler la sensibilité des
règles de sécurité. En ajustant le niveau de paranoïa, vous pouvez équilibrer la protection et la
tolérance aux faux positifs. Un niveau de paranoïa plus élevé signifie une analyse plus stricte,
augmentant la détection des menaces mais potentiellement aussi les faux positifs.

Les Différents Niveaux de Paranoïa
Le CRS définit généralement cinq niveaux de paranoïa, chacun offrant un degré de sensibilité
différent.
Niveau 1 : Basique
• Description : Ce niveau est conçu pour fournir une protection essentielle avec un minimum
de perturbations pour les utilisateurs légitimes.
• Utilisation : Idéal pour les environnements de production où la stabilité et la fiabilité sont
prioritaires.
• Caractéristiques :
o Protection contre les attaques les plus courantes.
o Faible taux de faux positifs.
o Configuration par défaut pour une sécurité standard.
Niveau 2 : Standard
• Description : Offre une sécurité accrue tout en maintenant un équilibre entre protection et
accessibilité.
• Utilisation : Convient aux applications nécessitant une sécurité renforcée sans impact
significatif sur l'expérience utilisateur.
• Caractéristiques :
o Règles supplémentaires pour couvrir une gamme plus large de menaces.
o Modération des règles pour éviter les perturbations excessives.
Niveau 3 : Avancé
• Description : Augmente la sensibilité des règles pour détecter des menaces plus
sophistiquées.
• Utilisation : Recommandé pour les applications critiques où la sécurité est une priorité
absolue.
• Caractéristiques :
o Détection avancée des attaques ciblées.
o Possibilité d'identifier des schémas d'attaque plus complexes.
o Augmentation du nombre de règles actives.
Niveau 4 : Très Avancé
• Description : Maximise la détection des menaces en activant un ensemble complet de règles
de sécurité.
• Utilisation : Adapté aux environnements hautement sensibles nécessitant une surveillance et
une protection rigoureuses.

• Caractéristiques :
o Analyse approfondie du trafic pour identifier des attaques sophistiquées.
o Augmentation significative des règles de détection.
o Surveillance étendue des comportements suspects.
Niveau 5 : Extrême
• Description : Niveau de paranoïa le plus élevé, conçu pour les environnements nécessitant
une sécurité maximale.
• Utilisation : Utilisé dans des contextes où même les menaces les plus rares doivent être
détectées et bloquées.
• Caractéristiques :
o Toutes les règles disponibles sont activées.
o Détection proactive des menaces émergentes.
o Potentiel élevé de faux positifs nécessitant une gestion rigoureuse.
Configuration des Niveaux de Paranoïa
La configuration des niveaux de paranoïa se fait généralement via le fichier de configuration de
ModSecurity ou directement dans les fichiers de règles du CRS.
Exemple de Configuration
# Définir le niveau de paranoïa
SecDefaultAction "phase:1,log,deny,paranoia_level=2"
# Ou via les fichiers de règles CRS
Include /path/to/crs-setup.conf
Include /path/to/rules/*.conf
Dans le fichier crs-setup.conf, vous pouvez spécifier le niveau de paranoïa souhaité :
# Set the paranoia level
SecRuleEngine On
SecDefaultAction "phase:2,deny,log,paranoia_level=3"
Ajustement Dynamique
Il est possible d'ajuster dynamiquement le niveau de paranoïa en fonction des besoins spécifiques de
l'application ou des segments de trafic. Cela permet une flexibilité accrue dans la gestion de la
sécurité.
Implications des Niveaux de Paranoïa
Avantages

• Sécurité Ajustable : Permet de calibrer la protection en fonction des exigences spécifiques de
l'application.
• Gestion des Faux Positifs : Des niveaux plus bas réduisent les faux positifs, améliorant
l'expérience utilisateur.
• Détection Progressive : Les niveaux plus élevés offrent une détection plus exhaustive des
menaces.
Inconvénients
• Faux Positifs Accrus : Des niveaux de paranoïa élevés peuvent entraîner une augmentation
des faux positifs, nécessitant une gestion et une analyse supplémentaires.
• Complexité de Configuration : Plus le niveau est élevé, plus la configuration peut devenir
complexe et requérir une expertise avancée.
• Impact sur les Performances : Des niveaux plus stricts peuvent augmenter la charge sur le
serveur en raison de l'analyse plus approfondie du trafic.
Meilleures Pratiques
1. Commencer par un Niveau Basique : Déployez le CRS avec un niveau de paranoïa faible
(niveau 1 ou 2) pour établir une base de sécurité solide tout en minimisant les perturbations.
2. Surveiller les Logs : Analysez régulièrement les journaux pour identifier et ajuster les règles
qui génèrent des faux positifs.
3. Augmenter Graduellement le Niveau : Une fois que le système est stable, augmentez
progressivement le niveau de paranoïa tout en surveillant l'impact sur le trafic légitime.
4. Personnaliser les Règles : Adaptez les règles spécifiques en fonction des besoins de votre
application pour optimiser la sécurité et réduire les faux positifs.
5. Tester en Environnement Contrôlé : Avant de déployer des niveaux de paranoïa élevés en
production, effectuez des tests approfondis dans un environnement de pré-production.
6. Mettre à Jour Régulièrement : Assurez-vous que le CRS et ModSecurity sont régulièrement
mis à jour pour bénéficier des dernières améliorations et correctifs de sécurité.
Exemples de Configuration
Configuration pour le Niveau 2 : Standard
# Dans crs-setup.conf
SecDefaultAction "phase:1,log,deny,paranoia_level=2"
SecDefaultAction "phase:2,log,deny,paranoia_level=2"
Configuration pour le Niveau 4 : Très Avancé
# Dans crs-setup.conf
SecDefaultAction "phase:1,log,deny,paranoia_level=4"
SecDefaultAction "phase:2,log,deny,paranoia_level=4"

Désactivation de Certaines Règles au Niveau 3
# Dans un fichier de configuration personnalisé
SecRuleRemoveById 950001
SecRuleRemoveById 960014
Conclusion
Les niveaux de paranoïa du Core Rule Set offrent une flexibilité essentielle pour adapter la sécurité
de votre application web en fonction de vos besoins spécifiques. En comprenant les implications de
chaque niveau et en suivant les meilleures pratiques de configuration, vous pouvez optimiser la
protection contre les menaces tout en minimisant les perturbations pour les utilisateurs légitimes. Il
est crucial de surveiller en continu les performances et les logs pour ajuster les niveaux de paranoïa
de manière appropriée, garantissant ainsi une sécurité robuste et efficace.
Remerciements
Cette documentation s'appuie sur les informations disponibles au sein de la communauté OWASP et
les pratiques recommandées pour l'utilisation du Core Rule Set de ModSecurity. Pour des
informations plus détaillées et des mises à jour, veuillez consulter la documentation officielle du CRS.
Licence
Cette documentation est distribuée sous licence Creative Commons Attribution-ShareAlike 4.0
International.
Contact
Pour toute question ou suggestion concernant cette documentation, veuillez contacter
l'administrateur système ou le responsable de la sécurité de votre organisation.
Annexes
Glossaire
• WAF (Web Application Firewall) : Pare-feu d'applications web qui filtre et surveille le trafic
HTTP pour protéger contre les attaques.
• Faux Positif : Une alerte de sécurité qui signale une menace inexistante, souvent causée par
une règle trop sensible.
• Injection SQL : Type d'attaque où des commandes SQL malveillantes sont insérées dans une
requête pour manipuler la base de données.
• XSS (Cross-Site Scripting) : Attaque où des scripts malveillants sont injectés dans des pages
web vues par d'autres utilisateurs.
Ressources Supplémentaires
• OWASP Core Rule Set (CRS) GitHub
• Documentation Officielle de ModSecurity
• Guide de Déploiement du CRS
Historique des Versions

• Version 1.0 - Création initiale de la documentation.
• Version 1.1 - Ajout des exemples de configuration.
• Version 1.2 - Mise à jour des meilleures pratiques et des ressources supplémentaires.
Avertissement
Cette documentation est fournie "telle quelle" sans garantie d'aucune sorte. L'auteur et les
contributeurs ne sont pas responsables des dommages résultant de l'utilisation de cette
documentation.
Fin de la Documentation
