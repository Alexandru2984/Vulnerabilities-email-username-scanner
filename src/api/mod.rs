use crate::core::Engine;
use crate::models::{Finding, Scan};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderName, REFERRER_POLICY,
            STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
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
struct ReadyResponse {
    status: String,
    database: String,
    version: String,
}

#[derive(Serialize)]
struct AuthCheckResponse {
    authenticated: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn create_router(pool: PgPool) -> Router {
    let engine = Arc::new(Engine::new(pool.clone()));

    let api_key = std::env::var("API_KEY").expect("API_KEY must be set before creating the router");

    let state = Arc::new(AppState {
        engine,
        pool,
        api_key,
    });

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check));

    // Protected API routes (require API key)
    let protected_routes = Router::new()
        .route("/auth/check", get(auth_check))
        .route("/scan", post(start_scan))
        .route("/scans/{id}", get(get_scan_status))
        .route("/scans/{id}/results", get(get_scan_results))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(1024)); // Max 1KB request body

    let api_routes = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(10)); // Max 10 concurrent API requests

    // Serve frontend static files
    let frontend_service =
        ServeDir::new("frontend").not_found_service(ServeFile::new("frontend/index.html"));

    Router::new()
        .nest("/api", api_routes)
        .fallback_service(frontend_service)
        .layer(middleware::from_fn(security_headers_middleware))
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
        Some(key) if constant_time_eq(key.as_bytes(), state.api_key.as_bytes()) => {
            next.run(request).await
        }
        Some(_) => {
            warn!("Invalid API key provided");
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid API key.".to_string(),
                }),
            )
                .into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing X-API-Key header.".to_string(),
            }),
        )
            .into_response(),
    }
}

async fn auth_check() -> Json<AuthCheckResponse> {
    Json(AuthCheckResponse {
        authenticated: true,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();

    for i in 0..max_len {
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }

    diff == 0
}

async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );

    if is_api {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store, private, max-age=0"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    } else {
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; connect-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'",
            ),
        );
    }

    response
}

/// Health check endpoint — public, no auth required
async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn readiness_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ReadyResponse>, (StatusCode, Json<ErrorResponse>)> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            error!("Database readiness check failed: {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "Service is not ready.".to_string(),
                }),
            )
        })?;

    Ok(Json(ReadyResponse {
        status: "ready".to_string(),
        database: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    }))
}

/// Handler to start a scan — sanitizes all error messages
async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.target.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Target cannot be empty.".to_string(),
            }),
        ));
    }

    match state.engine.start_scan(payload.target.clone()).await {
        Ok(scan_id) => Ok(Json(ScanResponse {
            scan_id,
            message: "Scan started successfully.".to_string(),
        })),
        Err(e) => {
            let msg = e.to_string();
            match public_start_scan_error_status(&msg) {
                Some(status) => Err((status, Json(ErrorResponse { error: msg }))),
                None => {
                    // Log the real error, return generic message to client
                    error!("Internal error starting scan: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: "An internal error occurred. Please try again later."
                                .to_string(),
                        }),
                    ))
                }
            }
        }
    }
}

fn public_start_scan_error_status(message: &str) -> Option<StatusCode> {
    if message.contains("Too many scans") {
        Some(StatusCode::TOO_MANY_REQUESTS)
    } else if message.contains("Target")
        || message.contains("Invalid")
        || message.contains("blocked")
        || message.contains("not allowed")
        || message.contains("DNS resolution")
    {
        Some(StatusCode::BAD_REQUEST)
    } else {
        None
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "An internal error occurred.".to_string(),
            }),
        )
    })?;

    match scan {
        Some(s) => Ok(Json(s)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Scan not found.".to_string(),
            }),
        )),
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "An internal error occurred.".to_string(),
            }),
        )
    })?;

    Ok(Json(findings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_values_only() {
        assert!(constant_time_eq(b"same-secret", b"same-secret"));
        assert!(!constant_time_eq(b"same-secret", b"same-secreu"));
        assert!(!constant_time_eq(b"same-secret", b"same-secret-longer"));
    }

    #[test]
    fn start_scan_capacity_errors_are_public_429() {
        assert_eq!(
            public_start_scan_error_status("Too many scans are already running. Try again later."),
            Some(StatusCode::TOO_MANY_REQUESTS)
        );
        assert_eq!(
            public_start_scan_error_status("Target resolves to a private/reserved IP address."),
            Some(StatusCode::BAD_REQUEST)
        );
        assert_eq!(public_start_scan_error_status("database exploded"), None);
    }
}
