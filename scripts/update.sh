#!/bin/bash
# ============================================
# VIGILANCE X - Update Script
# Usage: ./update.sh
# ============================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="/opt/vigilanceX"

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}       VIGILANCE X - Update Script${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# Check current version
CURRENT_VERSION=$(grep "Version" $BASE_DIR/CLAUDE.md | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
echo -e "Current version: ${YELLOW}$CURRENT_VERSION${NC}"
echo ""

# Step 1: Backup
echo -e "${YELLOW}[1/6] Creating backup...${NC}"
$SCRIPT_DIR/backup.sh
echo ""

# Step 2: Check for updates
echo -e "${YELLOW}[2/6] Checking for updates...${NC}"
cd $BASE_DIR
git fetch origin

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo -e "${GREEN}Already up to date!${NC}"
    exit 0
fi

echo "Updates available:"
git log --oneline HEAD..origin/main
echo ""

# Step 3: Pull changes
echo -e "${YELLOW}[3/6] Pulling latest code...${NC}"
git pull origin main
echo ""

# Step 4: Show new version
NEW_VERSION=$(grep "Version" $BASE_DIR/CLAUDE.md | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
echo -e "New version: ${GREEN}$NEW_VERSION${NC}"
echo ""

# Step 5: Check for new migrations
echo -e "${YELLOW}[4/6] Checking for new migrations...${NC}"
MIGRATIONS_DIR="$BASE_DIR/docker/clickhouse/migrations"
if [ -d "$MIGRATIONS_DIR" ]; then
    echo "Available migrations:"
    ls -la $MIGRATIONS_DIR/*.sql 2>/dev/null || echo "No migrations found"
fi
echo ""

# Ask for migration
read -p "Apply migrations? (y/n): " APPLY_MIGRATIONS
if [ "$APPLY_MIGRATIONS" = "y" ]; then
    echo "Applying all migrations..."
    for migration in $MIGRATIONS_DIR/*.sql; do
        if [ -f "$migration" ]; then
            echo "  Applying: $(basename $migration)"
            docker exec -i vigilance_clickhouse clickhouse-client < "$migration" 2>/dev/null || true
        fi
    done
fi
echo ""

# Step 6: Rebuild and restart
echo -e "${YELLOW}[5/6] Rebuilding containers...${NC}"
cd $BASE_DIR/docker
docker compose build --no-cache frontend backend
echo ""

echo -e "${YELLOW}[6/6] Restarting services...${NC}"
docker compose up -d
echo ""

# Wait for services
echo "Waiting for services to be healthy..."
sleep 10

# Verify
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}           Update Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
docker compose ps
echo ""

# Health check
echo "Health check:"
curl -s http://localhost:8080/health | jq . 2>/dev/null || echo "API not ready yet"
echo ""

echo -e "Version: ${GREEN}$NEW_VERSION${NC}"
echo -e "Please verify in the web interface: Settings > About"
