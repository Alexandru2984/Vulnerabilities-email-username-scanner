mod api;
mod core;
mod db;
mod models;
mod plugins;
mod reports;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Setup structured logging with env-filter support
    // Use RUST_LOG env var to control log levels (default: info)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("Starting Autonomous Bug Bounty Recon Agent v{}...", env!("CARGO_PKG_VERSION"));

    // Validate critical environment
    if std::env::var("API_KEY").unwrap_or_default() == "changeme_generate_a_secure_key" {
        warn!("⚠️  Using default API key! Set a strong API_KEY in .env for production.");
    }

    // Initialize Database
    let pool = db::init_db().await?;
    info!("Connected to PostgreSQL and ran migrations.");

    // Setup Router
    let app = api::create_router(pool);

    // Start Server
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let port_num: u16 = port.parse().expect("PORT must be a valid number");
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
