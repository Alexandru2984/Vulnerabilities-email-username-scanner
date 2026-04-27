use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct SecurityHeadersPlugin;

/// Security headers to check and their descriptions
const SECURITY_HEADERS: &[(&str, &str, &str)] = &[
    ("strict-transport-security", "HSTS", "Enforces HTTPS connections"),
    ("content-security-policy", "CSP", "Prevents XSS and injection attacks"),
    ("x-frame-options", "X-Frame-Options", "Prevents clickjacking"),
    ("x-content-type-options", "X-Content-Type-Options", "Prevents MIME sniffing"),
    ("referrer-policy", "Referrer-Policy", "Controls referrer information"),
    ("permissions-policy", "Permissions-Policy", "Controls browser feature access"),
    ("x-xss-protection", "X-XSS-Protection", "Legacy XSS filter (deprecated but still checked)"),
];

#[async_trait]
impl Plugin for SecurityHeadersPlugin {
    fn name(&self) -> &'static str {
        "security_headers"
    }

    async fn run(&self, scan_id: Uuid, target: &str, resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()),
        };

        info!(plugin = "security_headers", domain = %domain, "Checking security headers");

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::limited(3))
            .danger_accept_invalid_certs(true)
            .build()?;

        let host_target = if let Some(ip) = resolved_ip {
            ip.to_string()
        } else {
            domain.clone()
        };

        // Check HTTPS first, fall back to HTTP
        let url = format!("https://{}", host_target);
        let request = client.get(&url).header("Host", &domain);

        let res = match request.send().await {
            Ok(r) => r,
            Err(_) => {
                let http_url = format!("http://{}", host_target);
                match client.get(&http_url).header("Host", &domain).send().await {
                    Ok(r) => r,
                    Err(_) => return Ok(()),
                }
            }
        };

        let mut present = Vec::new();
        let mut missing = Vec::new();

        for (header_name, display_name, description) in SECURITY_HEADERS {
            if let Some(value) = res.headers().get(*header_name) {
                present.push(serde_json::json!({
                    "header": display_name,
                    "value": value.to_str().unwrap_or("<non-ascii>"),
                    "description": description,
                }));
            } else {
                missing.push(serde_json::json!({
                    "header": display_name,
                    "description": description,
                }));
            }
        }

        let severity = if missing.len() >= 4 {
            FindingSeverity::High
        } else if missing.len() >= 2 {
            FindingSeverity::Medium
        } else if !missing.is_empty() {
            FindingSeverity::Low
        } else {
            FindingSeverity::Info
        };

        let finding = Finding {
            id: Uuid::new_v4(),
            scan_id,
            plugin_name: self.name().to_string(),
            finding_type: "security_headers_audit".to_string(),
            data: serde_json::json!({
                "target": domain,
                "present_headers": present,
                "missing_headers": missing,
                "score": format!("{}/{}", present.len(), SECURITY_HEADERS.len()),
            }),
            severity,
            created_at: Utc::now(),
        };
        let _ = out_chan.send(finding).await;

        Ok(())
    }
}
