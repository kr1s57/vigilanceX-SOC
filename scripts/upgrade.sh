#!/bin/bash
# VIGILANCE X - Simple Upgrade Script
# Usage: ./upgrade.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   VIGILANCE X - Upgrade Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Detect installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VGX_DIR="$(dirname "$SCRIPT_DIR")"

# Check if we're in the right directory
if [ ! -f "$VGX_DIR/docker/docker-compose.yml" ]; then
    echo -e "${RED}Error: Cannot find docker-compose.yml${NC}"
    echo "Please run this script from the vigilanceX directory"
    exit 1
fi

cd "$VGX_DIR"

echo -e "${YELLOW}[1/5] Fetching latest version...${NC}"
git fetch origin

# Get current and latest versions
CURRENT=$(cat VERSION 2>/dev/null || echo "unknown")
git checkout origin/main -- VERSION 2>/dev/null || true
LATEST=$(cat VERSION 2>/dev/null || echo "unknown")
git checkout HEAD -- VERSION 2>/dev/null || true

echo "  Current version: $CURRENT"
echo "  Latest version:  $LATEST"
echo ""

if [ "$CURRENT" = "$LATEST" ]; then
    echo -e "${GREEN}Already up to date!${NC}"
    read -p "Force reinstall anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

echo -e "${YELLOW}[2/5] Pulling latest code...${NC}"
git reset --hard origin/main

echo -e "${YELLOW}[3/5] Stopping services...${NC}"
cd docker
docker compose down --remove-orphans 2>/dev/null || true

echo -e "${YELLOW}[4/5] Rebuilding containers...${NC}"
docker compose build --no-cache

echo -e "${YELLOW}[5/5] Starting services...${NC}"
docker compose up -d

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Upgrade complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Wait for health checks
echo "Waiting for services to be healthy..."
sleep 10

docker compose ps

echo ""
echo -e "${GREEN}VIGILANCE X is now running version $LATEST${NC}"
echo "Access the dashboard at: http://$(hostname -I | awk '{print $1}'):3000"
