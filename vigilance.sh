#!/bin/bash
#
# VIGILANCE X - Management Script
# Version: 3.1.0
# Copyright (c) 2024-2026 VigilanceX. All rights reserved.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="${SCRIPT_DIR}/deploy"
CONFIG_DIR="${SCRIPT_DIR}/config"
BACKUP_DIR="${SCRIPT_DIR}/backups"
COMPOSE_FILE="${DEPLOY_DIR}/docker-compose.yml"
VERSION_FILE="${SCRIPT_DIR}/VERSION"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           VIGILANCE X - SOC Platform                      ║"
    echo "║           Management Script v3.1.0                        ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Get Docker Compose command (v1 or v2)
get_compose_cmd() {
    if docker compose version &> /dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose &> /dev/null; then
        echo "docker-compose"
    else
        log_error "Docker Compose not found!"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        log_info "Visit: https://docs.docker.com/engine/install/"
        exit 1
    fi

    # Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    # Docker Compose
    local compose_cmd=$(get_compose_cmd)
    if [ -z "$compose_cmd" ]; then
        log_error "Docker Compose is not installed."
        exit 1
    fi

    # Check Docker version
    local docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1)
    if [ "$docker_version" -lt 20 ] 2>/dev/null; then
        log_warn "Docker version 20+ recommended. Current: $(docker version --format '{{.Server.Version}}')"
    fi

    log_success "All prerequisites met."
}

# Check if .env file exists
check_env_file() {
    if [ ! -f "${DEPLOY_DIR}/.env" ]; then
        if [ -f "${DEPLOY_DIR}/config.template" ]; then
            log_warn "Configuration file not found."
            log_info "Creating .env from template..."
            cp "${DEPLOY_DIR}/config.template" "${DEPLOY_DIR}/.env"
            log_warn "Please edit ${DEPLOY_DIR}/.env with your configuration."
            log_info "Required settings:"
            echo "  - CLICKHOUSE_PASSWORD"
            echo "  - REDIS_PASSWORD"
            echo "  - JWT_SECRET (run: openssl rand -hex 32)"
            echo "  - SOPHOS_HOST, SOPHOS_PASSWORD"
            echo "  - LICENSE_KEY (from VigilanceX support)"
            exit 1
        else
            log_error "Configuration template not found."
            exit 1
        fi
    fi
}

# Load .env file
load_env() {
    if [ -f "${DEPLOY_DIR}/.env" ]; then
        set -a
        source "${DEPLOY_DIR}/.env"
        set +a
    fi
}

# ============================================
# INSTALL Command
# ============================================
cmd_install() {
    show_banner
    log_info "Installing VIGILANCE X..."

    check_prerequisites
    check_env_file
    load_env

    local compose_cmd=$(get_compose_cmd)

    # Pull images
    log_info "Pulling Docker images from GitHub Container Registry..."
    cd "${DEPLOY_DIR}"
    $compose_cmd pull

    # Start services
    log_info "Starting services..."
    $compose_cmd up -d

    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 10

    # Check status
    $compose_cmd ps

    echo ""
    log_success "VIGILANCE X installed successfully!"
    echo ""
    log_info "Access the dashboard at: https://localhost"
    log_info "Default credentials: admin / VigilanceX2024!"
    log_warn "Please change the default password after first login!"
    echo ""
    log_info "To activate your license, visit: https://localhost/license"
}

# ============================================
# UPDATE Command
# ============================================
cmd_update() {
    show_banner
    log_info "Updating VIGILANCE X..."

    check_prerequisites
    load_env

    local compose_cmd=$(get_compose_cmd)

    # Create backup before update
    log_info "Creating backup before update..."
    cmd_backup

    # Pull latest repo changes (if git)
    if [ -d "${SCRIPT_DIR}/.git" ]; then
        log_info "Pulling latest configuration from repository..."
        git -C "${SCRIPT_DIR}" pull origin main 2>/dev/null || log_warn "Could not pull from git."
    fi

    # Pull new images
    log_info "Pulling new Docker images..."
    cd "${DEPLOY_DIR}"
    $compose_cmd pull

    # Restart services with new images
    log_info "Restarting services with new images..."
    $compose_cmd up -d

    # Cleanup old images
    log_info "Cleaning up old Docker images..."
    docker image prune -f

    # Show current version
    if [ -f "${VERSION_FILE}" ]; then
        local version=$(cat "${VERSION_FILE}")
        log_success "VIGILANCE X updated to v${version}"
    else
        log_success "VIGILANCE X updated successfully!"
    fi

    # Show status
    $compose_cmd ps
}

# ============================================
# BACKUP Command
# ============================================
cmd_backup() {
    log_info "Creating database backup..."
    load_env

    # Create backup directory
    mkdir -p "${BACKUP_DIR}"

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    # Backup ClickHouse data
    log_info "Backing up ClickHouse data..."
    if docker ps --format '{{.Names}}' | grep -q "vigilance_clickhouse"; then
        docker exec vigilance_clickhouse clickhouse-client \
            --user "${CLICKHOUSE_USER:-vigilance}" \
            --password "${CLICKHOUSE_PASSWORD}" \
            --query "BACKUP DATABASE vigilance_x TO Disk('backups', 'backup_${TIMESTAMP}')" 2>/dev/null || {
            # Fallback: volume backup
            log_warn "ClickHouse BACKUP command not available, backing up volume..."
            docker run --rm \
                -v vigilance_clickhouse_data:/data:ro \
                -v "${BACKUP_DIR}:/backup" \
                alpine tar czf "/backup/clickhouse_${TIMESTAMP}.tar.gz" -C /data .
        }
    else
        log_warn "ClickHouse container not running, skipping."
    fi

    # Backup Redis data
    log_info "Backing up Redis data..."
    if docker ps --format '{{.Names}}' | grep -q "vigilance_redis"; then
        docker exec vigilance_redis redis-cli -a "${REDIS_PASSWORD}" BGSAVE 2>/dev/null || true
        sleep 2
        docker run --rm \
            -v vigilance_redis_data:/data:ro \
            -v "${BACKUP_DIR}:/backup" \
            alpine tar czf "/backup/redis_${TIMESTAMP}.tar.gz" -C /data .
    else
        log_warn "Redis container not running, skipping."
    fi

    # Backup license data
    log_info "Backing up license data..."
    if docker volume ls --format '{{.Name}}' | grep -q "vigilance_backend_data"; then
        docker run --rm \
            -v vigilance_backend_data:/data:ro \
            -v "${BACKUP_DIR}:/backup" \
            alpine tar czf "/backup/license_${TIMESTAMP}.tar.gz" -C /data . 2>/dev/null || true
    fi

    log_success "Backup created in: ${BACKUP_DIR}"
    ls -lh "${BACKUP_DIR}"/*_${TIMESTAMP}.tar.gz 2>/dev/null || true

    # Cleanup old backups (keep last 7)
    log_info "Cleaning up old backups (keeping last 7)..."
    ls -t "${BACKUP_DIR}"/*.tar.gz 2>/dev/null | tail -n +22 | xargs -r rm -f
}

# ============================================
# RESTORE Command
# ============================================
cmd_restore() {
    local backup_file="$1"

    if [ -z "$backup_file" ]; then
        log_info "Available backups:"
        ls -lht "${BACKUP_DIR}"/*.tar.gz 2>/dev/null || log_warn "No backups found."
        echo ""
        log_info "Usage: ./vigilance.sh restore <backup_file>"
        exit 1
    fi

    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi

    log_warn "This will restore data from: $backup_file"
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Restore cancelled."
        exit 0
    fi

    log_info "Restoring from backup..."
    # Implementation depends on backup type
    log_warn "Manual restore required. Extract backup and copy to volume."
}

# ============================================
# START Command
# ============================================
cmd_start() {
    log_info "Starting VIGILANCE X..."
    load_env
    local compose_cmd=$(get_compose_cmd)
    cd "${DEPLOY_DIR}"
    $compose_cmd up -d
    log_success "Services started."
    $compose_cmd ps
}

# ============================================
# STOP Command
# ============================================
cmd_stop() {
    log_info "Stopping VIGILANCE X..."
    local compose_cmd=$(get_compose_cmd)
    cd "${DEPLOY_DIR}"
    $compose_cmd down
    log_success "Services stopped."
}

# ============================================
# RESTART Command
# ============================================
cmd_restart() {
    log_info "Restarting VIGILANCE X..."
    load_env
    local compose_cmd=$(get_compose_cmd)
    cd "${DEPLOY_DIR}"
    $compose_cmd restart
    log_success "Services restarted."
    $compose_cmd ps
}

# ============================================
# STATUS Command
# ============================================
cmd_status() {
    log_info "VIGILANCE X Status:"
    local compose_cmd=$(get_compose_cmd)
    cd "${DEPLOY_DIR}"
    $compose_cmd ps

    echo ""
    log_info "Disk usage:"
    docker system df 2>/dev/null || true

    if [ -f "${VERSION_FILE}" ]; then
        echo ""
        log_info "Version: $(cat ${VERSION_FILE})"
    fi
}

# ============================================
# LOGS Command
# ============================================
cmd_logs() {
    local service="${1:-}"
    local compose_cmd=$(get_compose_cmd)
    cd "${DEPLOY_DIR}"

    if [ -n "${service}" ]; then
        log_info "Showing logs for: ${service}"
        $compose_cmd logs -f "${service}"
    else
        log_info "Showing logs for all services (Ctrl+C to exit)"
        $compose_cmd logs -f
    fi
}

# ============================================
# VERIFY Command (Image signatures)
# ============================================
cmd_verify() {
    log_info "Verifying Docker image signatures with Cosign..."

    if ! command -v cosign &> /dev/null; then
        log_warn "Cosign not installed. Install with:"
        echo "  curl -sSL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign"
        echo "  chmod +x /usr/local/bin/cosign"
        exit 1
    fi

    local images=(
        "ghcr.io/kr1s57/vigilancex-api"
        "ghcr.io/kr1s57/vigilancex-frontend"
        "ghcr.io/kr1s57/vigilancex-detect2ban"
    )

    for image in "${images[@]}"; do
        log_info "Verifying: ${image}"
        if cosign verify "${image}" 2>/dev/null; then
            log_success "${image} - Signature valid"
        else
            log_error "${image} - Signature verification failed!"
        fi
    done
}

# ============================================
# HELP Command
# ============================================
cmd_help() {
    show_banner
    cat << EOF
Usage: ./vigilance.sh <command> [options]

Commands:
  install       Install VIGILANCE X (first-time setup)
  update        Update to latest version (with automatic backup)
  backup        Create database backup
  restore       Restore from backup
  start         Start all services
  stop          Stop all services
  restart       Restart all services
  status        Show service status
  logs [svc]    Show logs (optionally for specific service)
  verify        Verify Docker image signatures
  help          Show this help message

Services:
  clickhouse    Analytics database
  redis         Cache server
  vector        Log ingestion
  backend       API server
  detect2ban    Detection engine
  frontend      Web dashboard
  nginx         Reverse proxy

Examples:
  ./vigilance.sh install           # First-time installation
  ./vigilance.sh update            # Update with automatic backup
  ./vigilance.sh logs backend      # View backend logs
  ./vigilance.sh status            # Check service status
  ./vigilance.sh backup            # Manual backup

Support:
  Email: support@vigilancex.io
  Docs:  https://docs.vigilancex.io

EOF
}

# ============================================
# Main
# ============================================
case "${1:-help}" in
    install)  cmd_install ;;
    update)   cmd_update ;;
    backup)   cmd_backup ;;
    restore)  cmd_restore "${2:-}" ;;
    start)    cmd_start ;;
    stop)     cmd_stop ;;
    restart)  cmd_restart ;;
    status)   cmd_status ;;
    logs)     cmd_logs "${2:-}" ;;
    verify)   cmd_verify ;;
    help|--help|-h|*)
        cmd_help
        ;;
esac
