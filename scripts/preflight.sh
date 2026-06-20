#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

ok() {
    printf '[OK] %s\n' "$*"
}

require_int_range() {
    local name="$1"
    local value="$2"
    local min="$3"
    local max="$4"

    case "$value" in
        ''|*[!0-9]*)
            fail "$name must be an integer between $min and $max."
            ;;
    esac
    [ "$value" -ge "$min" ] || fail "$name must be at least $min."
    [ "$value" -le "$max" ] || fail "$name must be at most $max."
}

[ -f .env ] || fail ".env is missing. Copy .env.example and set production values."

set -a
# shellcheck disable=SC1091
source .env
set +a

[ "${API_KEY:-}" != "" ] || fail "API_KEY is missing."
[ "${API_KEY}" != "changeme_generate_a_secure_key" ] || fail "API_KEY is still the default placeholder."
[ "${#API_KEY}" -ge 32 ] || fail "API_KEY must be at least 32 characters."

[ "${POSTGRES_PASSWORD:-}" != "" ] || fail "POSTGRES_PASSWORD is missing."
[ "${POSTGRES_PASSWORD}" != "recon_password" ] || fail "POSTGRES_PASSWORD is still the old default."
[ "${POSTGRES_PASSWORD}" != "change_me_generate_a_strong_database_password" ] || fail "POSTGRES_PASSWORD is still the example placeholder."

[ "${DATABASE_URL:-}" != "" ] || fail "DATABASE_URL is missing."

MAX_CONCURRENT_SCANS_VALUE="${MAX_CONCURRENT_SCANS:-3}"
require_int_range "MAX_CONCURRENT_SCANS" "$MAX_CONCURRENT_SCANS_VALUE" 1 64

DB_MAX_CONNECTIONS_VALUE="${DB_MAX_CONNECTIONS:-10}"
DB_MIN_CONNECTIONS_VALUE="${DB_MIN_CONNECTIONS:-2}"
DB_ACQUIRE_TIMEOUT_SECS_VALUE="${DB_ACQUIRE_TIMEOUT_SECS:-5}"
DB_IDLE_TIMEOUT_SECS_VALUE="${DB_IDLE_TIMEOUT_SECS:-300}"

require_int_range "DB_MAX_CONNECTIONS" "$DB_MAX_CONNECTIONS_VALUE" 1 64
require_int_range "DB_MIN_CONNECTIONS" "$DB_MIN_CONNECTIONS_VALUE" 0 64
[ "$DB_MIN_CONNECTIONS_VALUE" -le "$DB_MAX_CONNECTIONS_VALUE" ] || fail "DB_MIN_CONNECTIONS cannot be greater than DB_MAX_CONNECTIONS."
require_int_range "DB_ACQUIRE_TIMEOUT_SECS" "$DB_ACQUIRE_TIMEOUT_SECS_VALUE" 1 60
require_int_range "DB_IDLE_TIMEOUT_SECS" "$DB_IDLE_TIMEOUT_SECS_VALUE" 30 3600

command -v docker >/dev/null 2>&1 || fail "docker is not installed."
docker compose config >/dev/null

ok "Environment and compose configuration look deployable."
