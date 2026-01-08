# Risk Scoring Engine

Le moteur de scoring de VIGILANCE X calcule un score de risque contextuel pour chaque IP en combinant plusieurs sources de données.

---

## Vue d'Ensemble

```
                    ┌─────────────────────────────────────┐
                    │         RISK SCORING ENGINE         │
                    └─────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌───────────────┐           ┌───────────────┐             ┌───────────────┐
│  Threat Intel │           │   Blocklist   │             │  Geolocation  │
│     (40%)     │           │     (30%)     │             │     (10%)     │
└───────────────┘           └───────────────┘             └───────────────┘
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      │
                                      ▼
                            ┌───────────────┐
                            │   Freshness   │
                            │  Multiplier   │
                            │     (20%)     │
                            └───────────────┘
                                      │
                                      ▼
                            ┌───────────────┐
                            │ COMBINED SCORE│──► 0-100
                            │  Threat Level │──► Critical/High/Medium/Low
                            └───────────────┘
```

---

## Formule du Score Combiné

```
combined_score = (threat_intel × 0.40) + (blocklist × 0.30) + (freshness × 0.20) + (geolocation × 0.10)
```

C'est une **moyenne pondérée** où chaque facteur a un poids différent selon son importance :

| Facteur | Poids | Description |
|---------|-------|-------------|
| **threat_intel** | 40% | Score agrégé des 11 providers de Threat Intelligence |
| **blocklist** | 30% | Présence sur des blocklists connues |
| **freshness** | 20% | Récence de l'activité malveillante |
| **geolocation** | 10% | Niveau de risque du pays d'origine |

---

## Détail des Facteurs

### Threat Intelligence (40%)

Score agrégé provenant de 11 providers spécialisés :

| Tier | Providers | Caractéristiques |
|------|-----------|------------------|
| **Tier 1** (Gratuit) | IPSum, AlienVault OTX, ThreatFox, URLhaus, Shodan InternetDB | Illimité, toujours consulté |
| **Tier 2** (Modéré) | AbuseIPDB, GreyNoise, CrowdSec | Consulté si score > 30 |
| **Tier 3** (Limité) | VirusTotal, CriminalIP, Pulsedive | Consulté si score > 60 |

Le système de **cascade intelligent** économise vos quotas API en ne consultant les tiers supérieurs que si nécessaire.

### Blocklist (30%)

Vérification de la présence sur des listes de blocage :

- IPSum (niveaux 1-8)
- ThreatFox IOCs
- URLhaus
- Listes personnalisées

### Freshness (20%)

Ajustement basé sur la récence de l'activité malveillante. Voir [Décroissance Temporelle](#décroissance-temporelle-freshness) ci-dessous.

### Geolocation (10%)

Score de risque par pays basé sur :
- Statistiques de cyberattaques
- Présence de botnets connus
- Historique des menaces

---

## Exemple de Calcul

```
IP 185.220.101.42

threat_intel  = 75/100  (détecté par 6 providers)
blocklist     = 80/100  (présent sur 3 blocklists)
freshness     = 90/100  (activité vue il y a 2 jours)
geolocation   = 40/100  (pays à risque moyen-élevé)

combined_score = (75 × 0.40) + (80 × 0.30) + (90 × 0.20) + (40 × 0.10)
               = 30 + 24 + 18 + 4
               = 76/100

Threat Level : HIGH
```

---

## Décroissance Temporelle (Freshness)

### Formule

```
freshness_multiplier = e^(-(days_over_threshold) / decay_factor)
```

C'est une **décroissance exponentielle** qui réduit le score au fil du temps.

**Principe** : Une IP malveillante vue hier est plus dangereuse qu'une vue il y a 6 mois.

| Variable | Description |
|----------|-------------|
| `e` | Constante mathématique (~2.718) |
| `days_over_threshold` | Jours écoulés depuis la dernière activité malveillante |
| `decay_factor` | Vitesse de décroissance (défaut: 30 jours) |

### Courbe de Décroissance

```
Multiplicateur
1.0 ┤████████
0.8 ┤      ████
0.6 ┤          ████
0.4 ┤              ████
0.2 ┤                  ████████
0.0 ┼────────────────────────────► Jours
    0   15   30   45   60   90
```

### Table de Référence (decay_factor = 30)

| Jours écoulés | Calcul | Multiplicateur |
|---------------|--------|----------------|
| 0 (aujourd'hui) | e^(0/30) = e^0 | **1.00** (100%) |
| 7 jours | e^(-7/30) | **0.79** (79%) |
| 30 jours | e^(-30/30) = e^-1 | **0.37** (37%) |
| 60 jours | e^(-60/30) = e^-2 | **0.14** (14%) |
| 90 jours | e^(-90/30) = e^-3 | **0.05** (5%) |

### Exemple d'Application

```
IP détectée malveillante il y a 45 jours
Score threat_intel brut = 85/100

freshness_multiplier = e^(-45/30) = e^-1.5 = 0.22

Score ajusté = 85 × 0.22 = 18.7/100 → LOW RISK
```

### Pourquoi c'est Important

- Une IP peut changer de propriétaire
- Les botnets changent régulièrement d'infrastructure
- Évite les faux positifs sur d'anciennes menaces
- Priorise les menaces actives

---

## Niveaux de Menace

Le score combiné est traduit en niveau de menace :

| Score | Niveau | Couleur | Action Recommandée |
|-------|--------|---------|-------------------|
| 80-100 | **CRITICAL** | Rouge | Ban immédiat |
| 60-79 | **HIGH** | Orange | Ban temporaire / Investigation |
| 40-59 | **MEDIUM** | Jaune | Monitoring renforcé |
| 20-39 | **LOW** | Bleu | Surveillance standard |
| 0-19 | **MINIMAL** | Vert | Aucune action |

---

## Intégration avec Detect2Ban

Le Risk Scoring Engine alimente directement le système Active Response :

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Event     │────►│    Risk     │────►│  Detect2Ban │
│   Detected  │     │   Scoring   │     │   Engine    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                    │
                           ▼                    ▼
                    ┌─────────────┐     ┌─────────────┐
                    │ Score: 87   │     │  BAN IP     │
                    │ Level: CRIT │     │  on Sophos  │
                    └─────────────┘     └─────────────┘
```

### Policies Automatiques

| Condition | Action |
|-----------|--------|
| Score >= 80 + IP récidiviste | Ban permanent |
| Score >= 80 | Ban temporaire (24h) |
| Score >= 60 + attaque active | Ban temporaire (12h) |
| Score >= 60 | Alerte + monitoring |

---

## API Endpoints

### Vérifier le Score d'une IP

```bash
curl -X GET "https://VIGILANCE_IP/api/v1/threats/risk/185.220.101.42" \
  -H "Authorization: Bearer TOKEN"
```

**Réponse :**
```json
{
  "ip": "185.220.101.42",
  "combined_score": 76,
  "threat_level": "high",
  "factors": {
    "threat_intel": 75,
    "blocklist": 80,
    "freshness": 90,
    "geolocation": 40
  },
  "freshness_multiplier": 0.95,
  "last_seen": "2026-01-06T14:32:00Z",
  "sources": ["abuseipdb", "virustotal", "greynoise", "ipsum"],
  "recommendation": "temporary_ban"
}
```

### Vérification Batch

```bash
curl -X POST "https://VIGILANCE_IP/api/v1/threats/batch" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ips": ["185.220.101.42", "45.33.32.156", "8.8.8.8"]}'
```

---

## Configuration

### Variables d'Environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `SCORING_DECAY_FACTOR` | 30 | Jours pour la décroissance (plus élevé = plus lent) |
| `SCORING_THREAT_WEIGHT` | 0.40 | Poids du facteur Threat Intel |
| `SCORING_BLOCKLIST_WEIGHT` | 0.30 | Poids du facteur Blocklist |
| `SCORING_FRESHNESS_WEIGHT` | 0.20 | Poids du facteur Freshness |
| `SCORING_GEO_WEIGHT` | 0.10 | Poids du facteur Geolocation |

### Ajuster les Poids

Pour un environnement où la géolocalisation est plus importante :

```bash
# deploy/.env
SCORING_GEO_WEIGHT=0.25
SCORING_FRESHNESS_WEIGHT=0.15
```

> **Note** : La somme des poids doit toujours égaler 1.0

---

## Voir Aussi

- [Architecture](Architecture.md) - Vue d'ensemble du système
- [Configuration](Configuration.md) - Variables d'environnement
- [Troubleshooting](Troubleshooting.md) - Diagnostic des problèmes
