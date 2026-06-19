# Production Runbook

This project is intended to run behind a local reverse proxy on the VPS, with Cloudflare in front.

## Required Secrets

Set these in `.env` before deploying:

- `API_KEY`: random value, at least 32 characters.
- `POSTGRES_PASSWORD`: random database password.
- `DATABASE_URL`: for Docker Compose, use host `postgres`; for local `cargo run`, `run.sh` rewrites it to `127.0.0.1:5454`.

Generate secrets with:

```bash
openssl rand -hex 32
```

## Preflight

Run:

```bash
./scripts/preflight.sh
```

The script validates required secrets and `docker compose config` without printing secret values.

## Deploy

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8088/api/ready
```

Only `127.0.0.1:8088` should be exposed locally. Public access should go through Nginx and Cloudflare.

## Nginx

Use `deploy/nginx-cloudflare.conf.example` as a starting point. Replace:

- `scan.example.com`
- certificate paths
- local upstream port, if you change `APP_BIND_PORT`

## Cloudflare

Recommended settings:

- Enable Cloudflare Access or another edge auth layer for the dashboard.
- Add a rate limit for `/api/scan`.
- Keep TLS mode strict.
- Keep the origin service bound to `127.0.0.1`.

## Operations

Useful commands:

```bash
docker compose logs -f app
docker compose logs -f postgres
docker compose exec postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > backup.sql
```

Health endpoints:

- `/api/health`: process liveness.
- `/api/ready`: database readiness.
