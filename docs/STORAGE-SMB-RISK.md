# VIGILANCE X - Analyse des Risques: Migration Logs vers SMB

> **Version**: 1.0 | **Date**: 2026-01-12
> **Statut**: Preparation pour tests

---

## 1. Architecture Actuelle

### Flux d'Ingestion

```
[Sophos XGS] --UDP/TCP--> [Vector] --HTTP--> [ClickHouse]
     |                        |                    |
   Syslog              Parse & Transform      events table
  514/1514                                   (225 MB, 3.4M rows)
```

### Stockage Actuel

| Composant | Type | Taille | Retention |
|-----------|------|--------|-----------|
| ClickHouse events | Analytique | 225 MB | Illimitee |
| ClickHouse blocklists | Reference | 13 MB | - |
| Docker volumes | Local | ~500 MB | - |
| **Total** | - | **~750 MB** | - |

---

## 2. Architecture Cible (SMB)

### Flux Propose

```
[Sophos XGS] --UDP/TCP--> [Vector] --HTTP--> [ClickHouse] (temps reel)
                              |
                              +--file--> [Local Buffer] --SMB--> [NAS/SMB Share]
                                                                  (archivage)
```

### Strategie Recommandee

| Destination | Usage | Donnees |
|-------------|-------|---------|
| ClickHouse | Temps reel, analytics, dashboards | Events structures |
| SMB Share | Archivage long terme, compliance | Raw logs compresses |

**Important**: Ne PAS remplacer ClickHouse par SMB. Utiliser SMB comme archivage supplementaire.

---

## 3. Matrice des Risques

### 3.1 Risques Techniques

| Risque | Probabilite | Impact | Score | Mitigation |
|--------|-------------|--------|-------|------------|
| **Latence SMB** elevee | Haute | Moyen | 6 | Buffer local, batch writes |
| **SMB indisponible** | Moyenne | Haut | 6 | Queue locale avec retry |
| **Perte de logs** pendant deconnexion | Moyenne | Critique | 8 | Buffer persistant sur disque |
| **Saturation reseau** | Basse | Moyen | 3 | Compression gzip, batching |
| **Timeout SMB** pendant pic | Moyenne | Moyen | 4 | Pool de connexions |

### 3.2 Risques Securite

| Risque | Probabilite | Impact | Score | Mitigation |
|--------|-------------|--------|-------|------------|
| **Credentials SMB en clair** | - | Haut | - | Chiffrement AES dans config |
| **Interception reseau** | Basse | Moyen | 3 | SMB3 avec encryption |
| **Acces non autorise share** | Basse | Haut | 4 | ACLs strictes, compte dedie |

### 3.3 Risques Operationnels

| Risque | Probabilite | Impact | Score | Mitigation |
|--------|-------------|--------|-------|------------|
| **Espace disque SMB sature** | Moyenne | Haut | 6 | Monitoring + alertes |
| **Performance degradee UI** | Basse | Moyen | 2 | SMB async, pas sur chemin critique |
| **Complexite debug** | Moyenne | Bas | 2 | Logs detailles, status endpoint |

---

## 4. Score de Risque Global

| Categorie | Score Moyen | Statut |
|-----------|-------------|--------|
| Technique | 5.4/10 | Acceptable avec mitigations |
| Securite | 3.5/10 | Acceptable |
| Operationnel | 3.3/10 | Acceptable |
| **Global** | **4.1/10** | **Risque Modere** |

---

## 5. Prerequisites Tests

### 5.1 Infrastructure

- [ ] Share SMB accessible depuis serveur VGX
- [ ] Compte service dedie (lecture/ecriture)
- [ ] Test connectivite: `smbclient //host/share -U user`
- [ ] Verification permissions: create/write/delete

### 5.2 Configuration Test

```bash
# Variables requises
SMB_HOST=10.x.x.x
SMB_SHARE=vigilancex_logs
SMB_USER=vigilancex_svc
SMB_PASSWORD=***
SMB_DOMAIN=WORKGROUP  # ou domaine AD
```

### 5.3 Volumes Estimes

| Periode | Logs/jour | Taille brute | Taille compressee |
|---------|-----------|--------------|-------------------|
| Actuel | ~100k | ~50 MB | ~5 MB |
| Prevu | ~500k | ~250 MB | ~25 MB |
| Max | ~2M | ~1 GB | ~100 MB |

**Retention 90 jours**: ~2.25 GB - 9 GB compressee

---

## 6. Plan d'Implementation

### Phase 1: Preparation (AUJOURD'HUI)

1. Interface StorageProvider (abstraction)
2. SMB Client Go (github.com/hirochachacha/go-smb2)
3. Section Settings UI (Storage)
4. Endpoints API configuration

### Phase 2: Tests (DEMAIN)

1. Test connexion SMB
2. Test ecriture fichier simple
3. Test batch write avec compression
4. Test retry sur echec connexion

### Phase 3: Integration (Apres validation)

1. Archivage raw_logs depuis backend
2. Rotation des fichiers (daily)
3. Monitoring espace disque
4. Alertes sur echecs

---

## 7. Rollback Plan

En cas de probleme:

1. Desactiver SMB dans Settings (toggle)
2. Les logs continuent vers ClickHouse (pas d'impact)
3. Buffer local conserve jusqu'a resolution

**Impact utilisateur**: ZERO (SMB est supplementaire, pas critique)

---

## 8. Decision

| Option | Recommandation |
|--------|----------------|
| Continuer implementation | OUI - Risque acceptable |
| Prerequis | Valider acces SMB avant tests |
| Strategie | Archive supplementaire, pas remplacement |

---

*Document genere par Claude Code - Analyse preparatoire*
