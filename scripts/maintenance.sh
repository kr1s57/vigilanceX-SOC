#!/bin/bash
# ============================================
# VIGILANCE X - Maintenance Script
# ============================================
# This script performs periodic maintenance tasks
# Run via cron: 0 3 * * 0 /opt/vigilanceX/scripts/maintenance.sh
#
# Recommended crontab entry (weekly cleanup on Sunday 3:00 AM):
#   0 3 * * 0 /opt/vigilanceX/scripts/maintenance.sh >> /var/log/vigilancex-maintenance.log 2>&1
# ============================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')] [MAINTENANCE]"

echo "$LOG_PREFIX Starting VIGILANCE X maintenance..."

# ============================================
# 1. Docker Build Cache Cleanup
# ============================================
echo "$LOG_PREFIX Cleaning Docker build cache (older than 7 days)..."
docker builder prune -a -f --filter "until=168h" 2>/dev/null || true

# ============================================
# 2. Docker System Cleanup (unused images, containers, volumes)
# ============================================
echo "$LOG_PREFIX Cleaning unused Docker resources..."
docker system prune -f --filter "until=168h" 2>/dev/null || true

# ============================================
# 3. Docker Logs Cleanup (truncate container logs > 100MB)
# ============================================
echo "$LOG_PREFIX Checking Docker container logs..."
for container in $(docker ps -q); do
    log_file=$(docker inspect --format='{{.LogPath}}' "$container" 2>/dev/null)
    if [ -n "$log_file" ] && [ -f "$log_file" ]; then
        log_size=$(stat -c%s "$log_file" 2>/dev/null || echo 0)
        if [ "$log_size" -gt 104857600 ]; then  # 100MB
            echo "$LOG_PREFIX Truncating log for container $container ($(numfmt --to=iec $log_size))"
            truncate -s 0 "$log_file"
        fi
    fi
done

# ============================================
# 4. Report disk usage
# ============================================
echo "$LOG_PREFIX Current disk usage:"
df -h / | tail -1

echo "$LOG_PREFIX Docker disk usage:"
docker system df

echo "$LOG_PREFIX Maintenance completed successfully."
