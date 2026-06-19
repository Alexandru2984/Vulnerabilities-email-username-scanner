mod api;
mod core;
mod db;
mod models;
mod plugins;
mod reports;

use anyhow::Context;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_API_KEY: &str = "changeme_generate_a_secure_key";
const MIN_API_KEY_LEN: usize = 32;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Setup structured logging with env-filter support
    // Use RUST_LOG env var to control log levels (default: info)
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(filter).init();

    info!(
        "Starting Autonomous Bug Bounty Recon Agent v{}...",
        env!("CARGO_PKG_VERSION")
    );

    validate_api_key_config()?;

    // Initialize Database
    let pool = db::init_db().await?;
    info!("Connected to PostgreSQL and ran migrations.");

    // Setup Router
    let app = api::create_router(pool);

    // Start Server
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8088".to_string());
    let port_num = parse_port(&port)?;
    let addr = format!("{}:{}", host, port_num);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on {}", addr);

    // Graceful shutdown on SIGINT (Ctrl+C) and SIGTERM
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shut down gracefully.");

    Ok(())
}

fn validate_api_key_config() -> anyhow::Result<()> {
    let api_key = std::env::var("API_KEY")
        .map_err(|_| anyhow::anyhow!("API_KEY must be set before starting the server."))?;
    validate_api_key_value(api_key.trim())
}

fn validate_api_key_value(api_key: &str) -> anyhow::Result<()> {
    if api_key.is_empty() {
        anyhow::bail!("API_KEY cannot be empty.");
    }

    if api_key == DEFAULT_API_KEY {
        anyhow::bail!("Refusing to start with the default API_KEY. Generate a strong random key.");
    }

    if api_key.len() < MIN_API_KEY_LEN {
        anyhow::bail!("API_KEY must be at least {MIN_API_KEY_LEN} characters.");
    }

    Ok(())
}

fn parse_port(port: &str) -> anyhow::Result<u16> {
    port.parse::<u16>()
        .with_context(|| format!("PORT must be a valid TCP port, got '{port}'"))
}

/// Wait for shutdown signals (SIGINT / SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received SIGINT, shutting down..."); },
        _ = terminate => { info!("Received SIGTERM, shutting down..."); },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_validation_rejects_unsafe_values() {
        assert!(validate_api_key_value("").is_err());
        assert!(validate_api_key_value(DEFAULT_API_KEY).is_err());
        assert!(validate_api_key_value("short").is_err());
        assert!(validate_api_key_value("0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn port_parser_accepts_valid_tcp_ports_only() {
        assert_eq!(parse_port("8088").unwrap(), 8088);
        assert_eq!(parse_port("65535").unwrap(), 65535);
        assert!(parse_port("0x1f90").is_err());
        assert!(parse_port("70000").is_err());
    }
}
