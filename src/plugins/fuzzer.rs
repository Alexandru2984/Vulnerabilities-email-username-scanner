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

#[async_trait]
impl Plugin for FuzzerPlugin {
    fn name(&self) -> &'static str {
        "sensitive_files_fuzzer"
    }

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()),
        };

        info!("Running FuzzerPlugin for {}", domain);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(5)) // Fast timeout for fuzzing
            .redirect(Policy::none()) // Don't follow redirects, we want true 200s
            .danger_accept_invalid_certs(true)
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
        let base_url = format!("http://{}", domain); // Probing HTTP for speed, could do HTTPS

        // This is a minimal, non-intrusive fuzzer. Runs sequentially for safety.
        for path in paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(res) = client.get(&url).send().await {
                if res.status() == 200 {
                    // Check if it's a real 200 or a soft 404 (custom error page returning 200)
                    // A simple check is to read body length. If too long, might be the homepage.
                    let content_length = res.headers().get("content-length")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    
                    // Simple heuristic: Most sensitive files are relatively small (under 10KB usually, except swagger maybe)
                    // If no content-length header, we read text.
                    if let Ok(body) = res.text().await {
                        // Avoid HTML homepages
                        let is_html = body.to_lowercase().contains("<html");
                        
                        if !is_html || path.contains("swagger") {
                            exposed_files.push(path.to_string());
                        }
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
                severity: FindingSeverity::High, // Exposed files are usually high severity
                created_at: Utc::now(),
            };
            let _ = out_chan.send(finding).await;
        }

        Ok(())
    }
}
