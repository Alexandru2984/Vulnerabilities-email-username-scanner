# Security Policy

## Supported Version

Security fixes are tracked on the `main` branch.

## Reporting a Vulnerability

Do not open public issues for exploitable findings. Report privately with:

- affected endpoint or component
- reproduction steps
- expected impact
- relevant logs or request samples, with secrets redacted

## Operational Baseline

Production deployments should keep the app bound to `127.0.0.1`, place Nginx and Cloudflare in front of it, require a strong `API_KEY`, and run `./scripts/preflight.sh` before each deploy.

Never commit `.env`, database dumps, API keys, or scan output containing third-party secrets.
