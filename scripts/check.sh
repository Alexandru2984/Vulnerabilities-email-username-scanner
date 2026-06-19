#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

cleanup_target=0
if [ "${CARGO_TARGET_DIR:-}" = "" ]; then
    CARGO_TARGET_DIR="$(mktemp -d /tmp/recon-cargo-target.XXXXXX)"
    cleanup_target=1
    export CARGO_TARGET_DIR
fi

cleanup() {
    if [ "$cleanup_target" -eq 1 ]; then
        rm -rf "$CARGO_TARGET_DIR"
    fi
}
trap cleanup EXIT

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo audit --ignore RUSTSEC-2023-0071
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-dummy}" docker compose config >/dev/null
