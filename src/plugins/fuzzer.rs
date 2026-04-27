use crate::core::read_body_limited;
use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct FuzzerPlugin;

/// Max body size for fuzzer responses (1 MB — sensitive files are small)
const FUZZER_MAX_BODY: usize = 1024 * 1024;

#[async_trait]
impl Plugin for FuzzerPlugin {
    fn name(&self) -> &'static str {
        "sensitive_files_fuzzer"
    }

    async fn run(&self, scan_id: Uuid, target: &str, resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()),
        };

        info!(plugin = "fuzzer", domain = %domain, "Fuzzing sensitive file paths");
        
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .danger_accept_invalid_certs(true) // Intentional for recon
            .build()?;

        // Common sensitive paths
        let paths = vec![
            "/.env",
            "/.git/config",
            "/.DS_Store",
            "/wp-config.php.bak",
            "/swagger-ui.html",
            "/phpinfo.php",
            "/.htaccess",
        ];

        let mut exposed_files = Vec::new();

        // Use resolved IP with Host header to prevent DNS rebinding TOCTOU
        let base_url = if let Some(ip) = resolved_ip {
            format!("http://{}", ip)
        } else {
            format!("http://{}", domain)
        };

        for path in paths {
            let url = format!("{}{}", base_url, path);
            let request = client.get(&url)
                .header("Host", &domain); // Set Host header for virtual hosting

            if let Ok(res) = request.send().await
                && res.status() == reqwest::StatusCode::OK {
                    // Read body with size limit
                    if let Ok(body) = read_body_limited(res, FUZZER_MAX_BODY).await {
                        // Avoid HTML homepages (soft 404s returning 200)
                        let is_html = body.to_lowercase().contains("<html");
                        
                        if !is_html || path.contains("swagger") {
                            exposed_files.push(path.to_string());
                        }
                    }
                }
        }

        if !exposed_files.is_empty() {
            let finding = Finding {
                id: Uuid::new_v4(),
                scan_id,
                plugin_name: self.name().to_string(),
                finding_type: "exposed_files".to_string(),
                data: serde_json::json!({
                    "target": domain,
                    "exposed_paths": exposed_files,
                }),
                severity: FindingSeverity::High,
                created_at: Utc::now(),
            };
            let _ = out_chan.send(finding).await;
        }

        Ok(())
    }
}
