#!/bin/bash
# ============================================
# VIGILANCE X - Backup Script
# Usage: ./backup.sh
# ============================================

set -e

BACKUP_DIR="/opt/vigilanceX/backups"
DATE=$(date +%Y%m%d_%H%M%S)
REDIS_PASS="V1g1l@nc3X_R3d1s!"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] Starting VIGILANCE X backup...${NC}"

# Create backup directory
mkdir -p $BACKUP_DIR

# ClickHouse Backup
echo -e "${YELLOW}[1/3] Backing up ClickHouse...${NC}"
docker exec vigilance_clickhouse tar czf /tmp/ch_backup.tar.gz -C /var/lib/clickhouse .
docker cp vigilance_clickhouse:/tmp/ch_backup.tar.gz $BACKUP_DIR/clickhouse_$DATE.tar.gz
docker exec vigilance_clickhouse rm /tmp/ch_backup.tar.gz
echo "      ClickHouse backup: clickhouse_$DATE.tar.gz"

# Redis Backup
echo -e "${YELLOW}[2/3] Backing up Redis...${NC}"
docker exec vigilance_redis redis-cli -a "$REDIS_PASS" BGSAVE 2>/dev/null || true
sleep 2
docker cp vigilance_redis:/data/dump.rdb $BACKUP_DIR/redis_$DATE.rdb 2>/dev/null || echo "      Redis has no data to backup"
echo "      Redis backup: redis_$DATE.rdb"

# Cleanup old backups (keep last 7)
echo -e "${YELLOW}[3/3] Cleaning old backups...${NC}"
cd $BACKUP_DIR
ls -t clickhouse_*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm -f
ls -t redis_*.rdb 2>/dev/null | tail -n +8 | xargs -r rm -f

echo ""
echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] Backup completed!${NC}"
echo ""
echo "Backup location: $BACKUP_DIR"
ls -lh $BACKUP_DIR
