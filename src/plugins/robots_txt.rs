use crate::core::{read_body_limited, MAX_BODY_SIZE};
use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct RobotsTxtPlugin;

/// Interesting path patterns that suggest hidden functionality
const INTERESTING_PATTERNS: &[&str] = &[
    "admin", "api", "login", "dashboard", "config", "backup",
    "debug", "test", "staging", "internal", "private", "secret",
    "wp-admin", "phpmyadmin", "cgi-bin", ".env", ".git",
    "graphql", "swagger", "docs", "console",
];

#[async_trait]
impl Plugin for RobotsTxtPlugin {
    fn name(&self) -> &'static str {
        "robots_txt"
    }

    async fn run(&self, scan_id: Uuid, target: &str, resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            TargetType::Email => target.split('@').last().unwrap_or(target).to_string(),
            TargetType::Username => return Ok(()),
        };

        info!(plugin = "robots_txt", domain = %domain, "Fetching robots.txt");

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

        // Try HTTPS first, fall back to HTTP
        let schemes = ["https", "http"];
        let mut body = None;

        for scheme in schemes {
            let url = format!("{}://{}/robots.txt", scheme, host_target);
            let request = client.get(&url).header("Host", &domain);

            if let Ok(res) = request.send().await
                && res.status().is_success()
                    && let Ok(text) = read_body_limited(res, MAX_BODY_SIZE).await {
                        // Quick check: does it look like a robots.txt?
                        let lower = text.to_lowercase();
                        if lower.contains("user-agent") || lower.contains("disallow") || lower.contains("sitemap") {
                            body = Some(text);
                            break;
                        }
                    }
        }

        let body = match body {
            Some(b) => b,
            None => return Ok(()),
        };

        // Parse directives
        let mut disallowed_paths = Vec::new();
        let mut sitemaps = Vec::new();
        let mut interesting_paths = Vec::new();

        for line in body.lines() {
            let line = line.trim();
            if let Some(path) = line.strip_prefix("Disallow:") {
                let path = path.trim();
                if !path.is_empty() {
                    disallowed_paths.push(path.to_string());
                    let path_lower = path.to_lowercase();
                    for pattern in INTERESTING_PATTERNS {
                        if path_lower.contains(pattern) {
                            interesting_paths.push(path.to_string());
                            break;
                        }
                    }
                }
            } else if let Some(sitemap) = line.strip_prefix("Sitemap:") {
                sitemaps.push(sitemap.trim().to_string());
            }
        }

        if disallowed_paths.is_empty() && sitemaps.is_empty() {
            return Ok(());
        }

        let severity = if !interesting_paths.is_empty() {
            FindingSeverity::Medium
        } else {
            FindingSeverity::Info
        };

        let finding = Finding {
            id: Uuid::new_v4(),
            scan_id,
            plugin_name: self.name().to_string(),
            finding_type: "robots_txt_analysis".to_string(),
            data: serde_json::json!({
                "target": domain,
                "disallowed_paths": disallowed_paths,
                "interesting_paths": interesting_paths,
                "sitemaps": sitemaps,
                "total_rules": disallowed_paths.len(),
            }),
            severity,
            created_at: Utc::now(),
        };
        let _ = out_chan.send(finding).await;

        Ok(())
    }
}
