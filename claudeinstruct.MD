Explore mon projet et créer un fichier de mémoire, de le diviser en sous-arborescences et de référencer le document de mémoire officiel d'Anthropic.

Après chaque test je validerai les steps et lorsque je te dirai “gitgo” tu réalisera toutes les taches de publication dans le repository git privé du projet. Tu mettra à jours tous les fichiers MD et descriptis.

Sécurité Déterministe (Safe YOLO)
L'utilisation du flag --dangerously-skip-permissions accélère le flux (plus de confirmation manuelle), mais est risquée. La solution est l'utilisation de Hooks.
Principe : Des scripts interceptent les actions de Claude avant exécution.

Configuration (hooks/) :
Bloquer les commandes fatales : rm -rf.

Auto-correction : Lancer automatiquement prettier ou un linter après chaque écriture de fichier (PostToolUse).

Règle d'or :
Forcer l'utilisation du modèle Opus pour tous les sous-agents dans [CLAUDE.md]
Spécialisation : Créer des agents dédiés dans ~/.claude/agents/ :
code-reviewer : Se concentre uniquement sur la sécurité et la maintenabilité.
test-writer : Expert en couverture de tests et cas d'erreurs.
