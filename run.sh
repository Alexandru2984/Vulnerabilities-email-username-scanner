#!/usr/bin/env bash
set -euo pipefail

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ─── Check dependencies ───
info "Checking dependencies..."

command -v docker >/dev/null 2>&1 || fail "docker is not installed. Install it from https://docs.docker.com/get-docker/"
command -v cargo  >/dev/null 2>&1 || fail "cargo is not installed. Install Rust from https://rustup.rs/"

ok "docker and cargo found."

# ─── Setup .env if missing ───
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        warn ".env not found — copied from .env.example. Edit it with your settings."
    else
        fail ".env and .env.example are both missing."
    fi
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

# Warn about default API key
if grep -q "changeme_generate_a_secure_key" .env 2>/dev/null; then
    warn "You're using the default API_KEY. Generate a secure one for production:"
    echo -e "       ${CYAN}openssl rand -hex 32${NC}"
    echo ""
fi

# ─── Start PostgreSQL ───
info "Starting PostgreSQL via Docker Compose..."

if docker compose ps --format '{{.State}}' postgres 2>/dev/null | grep -q "running"; then
    ok "PostgreSQL is already running."
else
    docker compose up -d postgres
    info "Waiting for PostgreSQL to be ready..."

    MAX_WAIT=30
    WAITED=0
    until docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-recon_user}" -d "${POSTGRES_DB:-recon_db}" >/dev/null 2>&1; do
        sleep 1
        WAITED=$((WAITED + 1))
        if [ "$WAITED" -ge "$MAX_WAIT" ]; then
            fail "PostgreSQL did not become ready within ${MAX_WAIT}s."
        fi
    done
    ok "PostgreSQL is ready. (waited ${WAITED}s)"
fi

# ─── Build & Run the Rust app ───
echo ""
info "Building and starting Recon Agent..."
if [[ "${DATABASE_URL:-}" == *"@postgres:"* ]]; then
    export DATABASE_URL="${DATABASE_URL/@postgres:5432/@127.0.0.1:5454}"
    info "Using local DATABASE_URL for cargo run."
fi
echo -e "────────────────────────────────────────────"
echo -e "  ${GREEN}Dashboard:${NC}  http://localhost:${PORT:-8088}"
echo -e "  ${GREEN}Health:${NC}     http://localhost:${PORT:-8088}/api/health"
echo -e "  ${GREEN}Ready:${NC}      http://localhost:${PORT:-8088}/api/ready"
echo -e "  ${GREEN}Stop:${NC}       Ctrl+C"
echo -e "────────────────────────────────────────────"
echo ""

cargo run
