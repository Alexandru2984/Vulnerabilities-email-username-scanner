.PHONY: fmt fmt-check clippy test audit docker-config docker-build preflight check

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	CARGO_TARGET_DIR=$${CARGO_TARGET_DIR:-/tmp/recon-cargo-target} cargo clippy --locked --all-targets -- -D warnings

test:
	CARGO_TARGET_DIR=$${CARGO_TARGET_DIR:-/tmp/recon-cargo-target} cargo test --locked

audit:
	cargo audit --ignore RUSTSEC-2023-0071

docker-config:
	APP_ENV_FILE=.env.example POSTGRES_PASSWORD=dummy docker compose config >/dev/null

docker-build:
	docker build .

preflight:
	./scripts/preflight.sh

check:
	./scripts/check.sh
