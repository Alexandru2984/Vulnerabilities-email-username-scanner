use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn};
use std::time::Duration;

pub struct HttpPlugin;

#[async_trait]
impl Plugin for HttpPlugin {
    fn name(&self) -> &'static str {
        "http_probe"
    }

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()), // Only run on domains
        };

        info!("Running HttpPlugin for domain {}", domain);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::limited(5))
            .danger_accept_invalid_certs(true) // For bug bounty recon, accept invalid certs
            .build()?;

        // Try HTTP and HTTPS
        let schemes = vec!["http", "https"];
        
        for scheme in schemes {
            let url = format!("{}://{}", scheme, domain);
            if let Ok(res) = client.get(&url).send().await {
                let status = res.status().as_u16();
                
                // Extract interesting headers
                let server = res.headers().get("server").and_then(|h| h.to_str().ok()).unwrap_or("unknown").to_string();
                let x_powered_by = res.headers().get("x-powered-by").and_then(|h| h.to_str().ok()).unwrap_or("unknown").to_string();
                
                // Read a bit of body for title extraction
                let mut title = String::new();
                if let Ok(body) = res.text().await {
                    if let Some(start) = body.find("<title>") {
                        if let Some(end) = body[start..].find("</title>") {
                            title = body[start + 7..start + end].to_string();
                        }
                    }
                }

                let finding = Finding {
                    id: Uuid::new_v4(),
                    scan_id,
                    plugin_name: self.name().to_string(),
                    finding_type: "http_response".to_string(),
                    data: serde_json::json!({
                        "url": url,
                        "status": status,
                        "server": server,
                        "x_powered_by": x_powered_by,
                        "title": title.trim(),
                    }),
                    severity: FindingSeverity::Info,
                    created_at: Utc::now(),
                };
                
                let _ = out_chan.send(finding).await;
            }
        }

        Ok(())
    }
}
