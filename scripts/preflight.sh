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
case "$MAX_CONCURRENT_SCANS_VALUE" in
    ''|*[!0-9]*)
        fail "MAX_CONCURRENT_SCANS must be an integer between 1 and 64."
        ;;
esac
[ "$MAX_CONCURRENT_SCANS_VALUE" -ge 1 ] || fail "MAX_CONCURRENT_SCANS must be at least 1."
[ "$MAX_CONCURRENT_SCANS_VALUE" -le 64 ] || fail "MAX_CONCURRENT_SCANS must be at most 64."

command -v docker >/dev/null 2>&1 || fail "docker is not installed."
docker compose config >/dev/null

ok "Environment and compose configuration look deployable."
