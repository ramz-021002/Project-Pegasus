#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$PROJECT_DIR/cleanup.log"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

log() {
    echo "[$TIMESTAMP] $*" | tee -a "$LOG_FILE"
}

log "========== Pegasus nightly cleanup started =========="

# ── 1. Stop all services and destroy named volumes ────────────────────────────
log "Stopping services and removing Docker volumes..."
cd "$PROJECT_DIR"
docker compose down -v --remove-orphans 2>&1 | tee -a "$LOG_FILE"
log "Docker volumes cleared."

# ── 2. Remove quarantined samples ─────────────────────────────────────────────
log "Clearing quarantine directory..."
find "$PROJECT_DIR/quarantine" \
    -mindepth 1 \
    ! -name '.gitkeep' \
    -exec rm -rf {} + 2>/dev/null || true
log "Quarantine cleared."

# ── 3. Remove packet captures ─────────────────────────────────────────────────
log "Clearing packet captures..."
find "$PROJECT_DIR/captures" \
    -mindepth 1 \
    -name '*.pcap' \
    -delete 2>/dev/null || true
log "Packet captures cleared."

# ── 4. Prune dangling Docker resources ────────────────────────────────────────
log "Pruning dangling Docker containers/images/networks..."
docker system prune -f 2>&1 | tee -a "$LOG_FILE"
log "Docker prune complete."

# ── 5. Restart services for a fresh start ─────────────────────────────────────
log "Restarting services..."
docker compose up -d 2>&1 | tee -a "$LOG_FILE"
log "Services started."

log "========== Pegasus nightly cleanup finished =========="
