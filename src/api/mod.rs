use crate::core::Engine;
use crate::models::{Finding, Scan};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use uuid::Uuid;

struct AppState {
    engine: Arc<Engine>,
    pool: PgPool,
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

pub fn create_router(pool: PgPool) -> Router {
    let engine = Arc::new(Engine::new(pool.clone()));
    let state = Arc::new(AppState { engine, pool });

    // API Routes
    let api_routes = Router::new()
        .route("/scan", post(start_scan))
        .route("/scans/{id}", get(get_scan_status))
        .route("/scans/{id}/results", get(get_scan_results))
        .with_state(state);

    // Serve frontend static files
    let frontend_service = ServeDir::new("frontend")
        .not_found_service(ServeFile::new("frontend/index.html"));

    Router::new()
        .nest("/api", api_routes)
        .fallback_service(frontend_service)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

// Handler to start a scan
async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    if payload.target.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Target cannot be empty".to_string()));
    }

    match state.engine.start_scan(payload.target.clone()).await {
        Ok(scan_id) => Ok(Json(ScanResponse {
            scan_id,
            message: "Scan started successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to start scan: {}", e),
        )),
    }
}

// Handler to get scan status
async fn get_scan_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Scan>, (StatusCode, String)> {
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
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match scan {
        Some(s) => Ok(Json(s)),
        None => Err((StatusCode::NOT_FOUND, "Scan not found".to_string())),
    }
}

// Handler to get scan results
async fn get_scan_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Finding>>, (StatusCode, String)> {
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
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(findings))
}
