---
name: gitgo
description: Execute the VIGILANCE X full release workflow. Use when user says "gitgo", wants to release a new version, push to all remotes, or create GitHub releases. Handles version bumping, commits, multi-remote sync, and release tags.
allowed-tools: Read, Grep, Glob, Bash, Edit
---

# GitGo - VIGILANCE X Release Workflow

## Overview

This Skill executes the complete release workflow for VIGILANCE X, handling:
- Version increment across all required files
- Git commit and push to private repo (origin)
- Sync to public repos (removing internal docs)
- GitHub release creation on both repos

## Step 0 - Version Bump (OBLIGATOIRE)

**Determine version increment type:**
- **BUGFIX**: Bug corrections → increment Z (e.g., 3.57.105 → 3.57.106)
- **FEATURE**: New features → increment YY, reset Z to 100 (e.g., 3.57.105 → 3.58.100)
- **MAJOR**: Major changes (rare, explicit request only) → increment X, reset YY.Z

**Files to update (ALL REQUIRED):**

| File | Location | Pattern |
|------|----------|---------|
| `Dashboard.tsx` | `frontend/src/pages/Dashboard.tsx` ~line 24 | `INSTALLED_VERSION = 'X.YY.Z'` |
| `Settings.tsx` | `frontend/src/pages/Settings.tsx` ~line 2381 | `VIGILANCE X vX.YY.Z` |
| `Login.tsx` | `frontend/src/pages/Login.tsx` ~line 192 | `VIGILANCE X vX.YY.Z` |
| `LicenseActivation.tsx` | `frontend/src/pages/LicenseActivation.tsx` ~line 450 | `VIGILANCE X vX.YY.Z` |
| `CLAUDE.md` | Root `/opt/vigilanceX/CLAUDE.md` header | Version + date |

**Commands to find current version:**
```bash
grep -n "INSTALLED_VERSION" frontend/src/pages/Dashboard.tsx
grep -rn "VIGILANCE X v3\." frontend/src/pages/ | head -10
```

## Step 1 - Commit and Push to Private Repo

```bash
# Check status
git status

# Add all changes
git add .

# Commit with version
git commit -m "feat(vX.YY.Z): description of changes"
# OR for bugfix:
git commit -m "fix(vX.YY.Z): description of fix"

# Push to origin (private)
git push origin main
```

## Step 2 - Sync to Public Repo (vigilanceX-SOC)

**FILES INTERDITS SUR REPO PUBLIC:**
- `CLAUDE.md` - Process internes
- `TECHNICAL_REFERENCE.md` - Reference technique
- `CHANGELOG.md` - Details implementation
- `docs/` - Documentation interne
- `BUGFIXSESSION/`, `FEATURESPROMPT/` - Sessions debug
- `.github/` - Workflows CI/CD
- `.claude/` - Configuration Claude Code (skills, settings)
- `backups/` - Donnees sensibles

```bash
# Create temporary branch
git checkout -b public-sync

# Remove ALL internal files from git tracking (CRITICAL - do not skip any!)
git rm --cached CLAUDE.md TECHNICAL_REFERENCE.md CHANGELOG.md 2>/dev/null || true
git rm -r --cached docs/ 2>/dev/null || true
git rm -r --cached BUGFIXSESSION/ 2>/dev/null || true
git rm -r --cached FEATURESPROMPT/ 2>/dev/null || true
git rm -r --cached .github/ 2>/dev/null || true
git rm -r --cached .claude/ 2>/dev/null || true
git rm -r --cached backups/ 2>/dev/null || true

# Commit removal
git commit -m "chore: Remove internal docs for public release" --allow-empty

# Force push to public
git push public public-sync:main --force

# Return to main and cleanup
git checkout -f main
git branch -d public-sync 2>/dev/null || true
```

## Step 3 - Sync to Forgejo

```bash
# Push to private Forgejo
git push forgejo main

# Repeat Step 2 for forgejo-soc (public)
git checkout -b forgejo-public-sync

# Remove ALL internal files from git tracking (CRITICAL - do not skip any!)
git rm --cached CLAUDE.md TECHNICAL_REFERENCE.md CHANGELOG.md 2>/dev/null || true
git rm -r --cached docs/ 2>/dev/null || true
git rm -r --cached BUGFIXSESSION/ 2>/dev/null || true
git rm -r --cached FEATURESPROMPT/ 2>/dev/null || true
git rm -r --cached .github/ 2>/dev/null || true
git rm -r --cached .claude/ 2>/dev/null || true
git rm -r --cached backups/ 2>/dev/null || true

git commit -m "chore: Remove internal docs for public release" --allow-empty
git push forgejo-soc forgejo-public-sync:main --force
git checkout -f main
git branch -d forgejo-public-sync 2>/dev/null || true
```

## Step 4 - Create GitHub Releases

```bash
# Create and push tag
git tag vX.YY.Z
git push origin vX.YY.Z
git push public vX.YY.Z

# Create releases
gh release create vX.YY.Z --repo kr1s57/vigilanceX --title "VIGILANCE X vX.YY.Z" --notes "Release vX.YY.Z"
gh release create vX.YY.Z --repo kr1s57/vigilanceX-SOC --title "VIGILANCE X vX.YY.Z" --notes "Release vX.YY.Z"
```

## Checklist Final

- [ ] Version updated in 4 frontend files
- [ ] CLAUDE.md header updated
- [ ] CHANGELOG.md entry added
- [ ] Committed to origin (private)
- [ ] Synced to public (without internal docs)
- [ ] Synced to Forgejo repos
- [ ] Tags created and pushed
- [ ] GitHub releases created

## Error Recovery

If any step fails:
1. Check git status
2. Resolve conflicts if any
3. Resume from failed step
4. Never force push to main on private repos
