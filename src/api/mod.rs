use crate::core::Engine;
use crate::models::{Finding, Scan};
use axum::{
    extract::{Path, State, Request},
    http::{StatusCode, HeaderMap},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{error, warn};
use uuid::Uuid;

struct AppState {
    engine: Arc<Engine>,
    pool: PgPool,
    api_key: String,
}

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
}

#[derive(Serialize)]
struct ScanResponse {
    scan_id: Uuid,
    message: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn create_router(pool: PgPool) -> Router {
    let engine = Arc::new(Engine::new(pool.clone()));
    
    // Read API key from environment — required for production
    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| {
        warn!("API_KEY not set! Using default key. Set API_KEY in .env for production.");
        "changeme_generate_a_secure_key".to_string()
    });

    let state = Arc::new(AppState { engine, pool, api_key });

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/health", get(health_check));

    // Protected API routes (require API key)
    let protected_routes = Router::new()
        .route("/scan", post(start_scan))
        .route("/scans/{id}", get(get_scan_status))
        .route("/scans/{id}/results", get(get_scan_results))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(RequestBodyLimitLayer::new(1024)); // Max 1KB request body

    let api_routes = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(10)); // Max 10 concurrent API requests

    // Serve frontend static files
    let frontend_service = ServeDir::new("frontend")
        .not_found_service(ServeFile::new("frontend/index.html"));

    Router::new()
        .nest("/api", api_routes)
        .fallback_service(frontend_service)
        .layer(CorsLayer::new()) // Default: restrictive same-origin only
        .layer(TraceLayer::new_for_http())
}

/// API key authentication middleware.
/// Checks for X-API-Key header on all protected routes.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    match headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        Some(key) if key == state.api_key => {
            next.run(request).await
        }
        Some(_) => {
            warn!("Invalid API key provided");
            (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Invalid API key.".to_string(),
            })).into_response()
        }
        None => {
            (StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                error: "Missing X-API-Key header.".to_string(),
            })).into_response()
        }
    }
}

/// Health check endpoint — public, no auth required
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Handler to start a scan — sanitizes all error messages
async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.target.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: "Target cannot be empty.".to_string(),
        })));
    }

    match state.engine.start_scan(payload.target.clone()).await {
        Ok(scan_id) => Ok(Json(ScanResponse {
            scan_id,
            message: "Scan started successfully.".to_string(),
        })),
        Err(e) => {
            let msg = e.to_string();
            // Only expose validation errors to client, not internal details
            if msg.contains("Target") || msg.contains("Invalid") || msg.contains("blocked") || msg.contains("not allowed") || msg.contains("DNS resolution") {
                Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                    error: msg,
                })))
            } else {
                // Log the real error, return generic message to client
                error!("Internal error starting scan: {}", e);
                Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: "An internal error occurred. Please try again later.".to_string(),
                })))
            }
        }
    }
}

/// Handler to get scan status
async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Scan>, (StatusCode, Json<ErrorResponse>)> {
    let scan = sqlx::query_as::<_, Scan>(
        r#"
        SELECT id, target, status, created_at, completed_at
        FROM scans
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        error!("Database error fetching scan status: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "An internal error occurred.".to_string(),
        }))
    })?;

    match scan {
        Some(s) => Ok(Json(s)),
        None => Err((StatusCode::NOT_FOUND, Json(ErrorResponse {
            error: "Scan not found.".to_string(),
        }))),
    }
}

/// Handler to get scan results
async fn get_scan_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Finding>>, (StatusCode, Json<ErrorResponse>)> {
    let findings = sqlx::query_as::<_, Finding>(
        r#"
        SELECT id, scan_id, plugin_name, finding_type, data, severity, created_at
        FROM findings
        WHERE scan_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        error!("Database error fetching scan results: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: "An internal error occurred.".to_string(),
        }))
    })?;

    Ok(Json(findings))
}
