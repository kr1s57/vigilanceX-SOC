#!/bin/bash
#
# backup-to-forgejo.sh - Backup Git repos to local Forgejo instance
#
# Usage: ./backup-to-forgejo.sh [--all|--vigilancex|--vigilancekey]
#
# Forgejo Server: 10.56.121.100 (via SSH tunnel)
# Repos: vigilanceX, vigilanceX-SOC, vigilanceKey
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VIGILANCEX_DIR="/opt/vigilanceX"
VIGILANCEKEY_SERVER="root@10.56.126.126"
VIGILANCEKEY_PATH="/opt/vigilanceKey"
TMP_DIR="/tmp/forgejo-backup-$$"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check SSH connection to Forgejo
check_forgejo_connection() {
    log_info "Testing Forgejo SSH connection..."
    # Forgejo returns specific message on successful auth (no shell access)
    if ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no forgejo 2>&1 | grep -q "successfully authenticated"; then
        log_success "Forgejo SSH connection OK"
        return 0
    else
        log_error "Cannot connect to Forgejo. Check SSH config."
        return 1
    fi
}

# Backup vigilanceX
backup_vigilancex() {
    log_info "Backing up vigilanceX..."
    cd "$VIGILANCEX_DIR"

    if git remote | grep -q "^forgejo$"; then
        git push forgejo main --tags 2>&1 | while read line; do echo "  $line"; done
        log_success "vigilanceX pushed to Forgejo"
    else
        log_error "Remote 'forgejo' not configured for vigilanceX"
        return 1
    fi
}

# Backup vigilanceX-SOC (same repo, different remote)
backup_vigilancex_soc() {
    log_info "Backing up vigilanceX-SOC..."
    cd "$VIGILANCEX_DIR"

    if git remote | grep -q "^forgejo-soc$"; then
        git push forgejo-soc main --tags 2>&1 | while read line; do echo "  $line"; done
        log_success "vigilanceX-SOC pushed to Forgejo"
    else
        log_warn "Remote 'forgejo-soc' not configured, skipping"
    fi
}

# Backup vigilanceKey (via temporary clone)
backup_vigilancekey() {
    log_info "Backing up vigilanceKey..."

    # Create temp directory
    mkdir -p "$TMP_DIR"
    cd "$TMP_DIR"

    # Clone from vigilanceKey server
    log_info "Cloning vigilanceKey from $VIGILANCEKEY_SERVER..."
    if git clone "$VIGILANCEKEY_SERVER:$VIGILANCEKEY_PATH" vigilanceKey 2>&1 | while read line; do echo "  $line"; done; then
        cd vigilanceKey

        # Add forgejo remote if not exists
        git remote add forgejo forgejo:itsadm/vigilanceKey.git 2>/dev/null || true

        # Push to Forgejo
        git push forgejo main --tags 2>&1 | while read line; do echo "  $line"; done
        log_success "vigilanceKey pushed to Forgejo"
    else
        log_error "Failed to clone vigilanceKey"
        return 1
    fi

    # Cleanup
    cd /
    rm -rf "$TMP_DIR"
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all           Backup all repos (default)"
    echo "  --vigilancex    Backup vigilanceX and vigilanceX-SOC only"
    echo "  --vigilancekey  Backup vigilanceKey only"
    echo "  --check         Test Forgejo connection only"
    echo "  -h, --help      Show this help"
    echo ""
    echo "Forgejo Server: 10.56.121.100"
    echo "SSH Config: Uses 'forgejo' host alias with ProxyJump"
}

# Cleanup on exit
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# Main
main() {
    echo ""
    echo "=========================================="
    echo "  VIGILANCE X - Forgejo Backup Script"
    echo "=========================================="
    echo ""

    # Check connection first
    check_forgejo_connection || exit 1
    echo ""

    case "${1:-all}" in
        --all|all)
            backup_vigilancex
            echo ""
            backup_vigilancex_soc
            echo ""
            backup_vigilancekey
            ;;
        --vigilancex)
            backup_vigilancex
            echo ""
            backup_vigilancex_soc
            ;;
        --vigilancekey)
            backup_vigilancekey
            ;;
        --check)
            log_success "Connection check passed"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac

    echo ""
    echo "=========================================="
    log_success "Backup completed at $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
}

main "$@"
