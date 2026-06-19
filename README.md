# Autonomous Bug Bounty Recon Agent

A modular and extensible reconnaissance system built in **Rust**. It asynchronously scans a target domain, email, or username, correlates findings from various plugins, and stores results in PostgreSQL.

## Features
- **Concurrent Engine:** Built on Tokio to run multiple reconnaissance plugins simultaneously.
- **PostgreSQL Storage:** Reliable data persistence with SQLx.
- **REST API:** Axum-powered endpoints to start scans and view results.
- **Dashboard:** Clean, vanilla JavaScript dark-mode frontend with API key authentication.
- **Recon Plugins:** Gathers DNS, subdomain, HTTP, security header, robots.txt, tech stack, port, breach, and username footprint findings.
- **Hardened Security:** SSRF protection with post-DNS IP validation, API key auth, input validation, body size limits, scan timeouts, error sanitization, and graceful shutdown.

## Architecture
- `src/core/` - The async scheduler, worker engine, SSRF validation, and input sanitization.
- `src/plugins/` - Independent reconnaissance modules (11 plugins).
- `src/api/` - HTTP router, auth middleware, and handlers.

## Quick Start

The fastest way to run everything:
```bash
./run.sh
```

This script will:
1. Check that `docker` and `cargo` are installed
2. Create `.env` from `.env.example` if missing
3. Start PostgreSQL via Docker Compose (with readiness check)
4. Build and run the Rust application

### Manual Setup

#### Prerequisites
- Rust (Cargo)
- Docker & Docker Compose (for PostgreSQL)

#### 1. Setup the Database
```bash
docker compose up -d
```

#### 2. Configure Environment
```bash
cp .env.example .env
```
Edit `.env` to set your `DATABASE_URL` and generate a strong `API_KEY`:
```bash
openssl rand -hex 32
```
Also set a strong `POSTGRES_PASSWORD` when using Docker Compose. `MAX_CONCURRENT_SCANS`
defaults to `3` and prevents unbounded background scan workers.

#### 3. Run the Agent
```bash
cargo run
```

Before deploying with Docker Compose, run:
```bash
./scripts/preflight.sh
```

#### 4. Access the Dashboard
Open your browser and navigate to:
```
http://localhost:8088
```
Enter your API key, then input a target (e.g., `example.com`) and start scanning!

## Plugins (11)

| Plugin | Target Type | Description |
|---|---|---|
| `subdomain_crtsh` | Domain | Subdomain enumeration via Certificate Transparency |
| `dns_info` | Domain/Email | DNS records (A, AAAA, MX, TXT) |
| `http_probe` | Domain | HTTP/HTTPS probing, WAF detection, title extraction |
| `tech_stack_detector` | Domain | Technology stack detection (CMS, frameworks, servers) |
| `sensitive_files_fuzzer` | Domain | Fuzzing for exposed sensitive files |
| `port_scanner` | Domain | Common port scanning (13 ports) |
| `ip_info` | Domain | IP geolocation and intelligence |
| `security_headers` | Domain | Security headers audit (HSTS, CSP, X-Frame-Options, etc.) |
| `robots_txt` | Domain | Robots.txt analysis for hidden paths |
| `email_breach_xon` | Email | Email breach checking via XposedOrNot |
| `username_footprint` | Username/Email | Username footprinting across 1000+ platforms (Sherlock) |

## Adding New Plugins
1. Create a new file in `src/plugins/`.
2. Implement the `async_trait` `Plugin` trait (include `resolved_ip` parameter).
3. Register the plugin in `src/plugins/mod.rs` inside `get_all_plugins()`.

## Security
- **SSRF Protection:** Post-DNS-resolution IP validation, cloud metadata blocking, DNS rebinding prevention.
- **Authentication:** API key via `X-API-Key` header on all protected endpoints.
- **Input Validation:** Regex allowlists per target type, schema/path traversal blocking.
- **DoS Prevention:** Concurrency limits, body size limits, scan timeouts (5 min).
- **Production Guardrails:** Bounded background scan workers, readiness checks, DB constraints, and security headers.
- **Error Sanitization:** Generic messages to clients, detailed errors only in server logs.
- **Graceful Shutdown:** Handles SIGINT/SIGTERM for clean resource cleanup.

## Production Notes

- Keep the container bound to `127.0.0.1` and expose it through Nginx/Cloudflare.
- Protect the dashboard with Cloudflare Access or another edge auth layer; the API key is still stored in browser session storage.
- Keep third-party scripts out of the dashboard by default; the production CSP only allows same-origin scripts, styles, and API calls.
- Generate both `API_KEY` and `POSTGRES_PASSWORD` with strong random values.
- Use `/api/health` for liveness and `/api/ready` for readiness/DB checks.
- Keep `target/` out of deploy/build contexts; `.dockerignore` excludes Rust build artifacts and local secrets.
- See `docs/PRODUCTION.md` and `deploy/nginx-cloudflare.conf.example` for VPS deployment notes.

## Quality Gates

Local checks mirror CI:

```bash
make check
POSTGRES_PASSWORD=dummy docker compose config
```

`make check` creates a temporary Cargo target directory under `/tmp` and removes it when the checks finish. For one-off Rust checks, you can still choose an explicit target directory:

```bash
CARGO_TARGET_DIR=/tmp/recon-cargo-target cargo clippy --locked --all-targets -- -D warnings
CARGO_TARGET_DIR=/tmp/recon-cargo-target cargo test --locked
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | No | Health check |
| `GET` | `/api/ready` | No | Readiness check, including database |
| `POST` | `/api/scan` | Yes | Start a new scan |
| `GET` | `/api/scans/{id}` | Yes | Get scan status |
| `GET` | `/api/scans/{id}/results` | Yes | Get scan findings |
