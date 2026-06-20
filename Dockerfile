# Build Stage
FROM rust:1.96.0-slim AS builder

WORKDIR /usr/src/recon-agent

# Install pkg-config and openssl (required for reqwest and sqlx)
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --locked --release

# Runtime Stage
FROM debian:trixie-slim

WORKDIR /app

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/recon-agent/target/release/antigravity_loose /app/recon-agent
COPY --from=builder /usr/src/recon-agent/frontend /app/frontend
COPY --from=builder /usr/src/recon-agent/migrations /app/migrations

# Create unprivileged user
RUN useradd -m -s /bin/bash appuser && \
    chown -R appuser:appuser /app
USER appuser

# Environment variables should be injected at runtime via docker-compose or orchestrator.
# DO NOT bake credentials into the image.
ENV PORT=8088
ENV HOST=0.0.0.0

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/api/ready" || exit 1

CMD ["./recon-agent"]
