use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::Client;
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct IpInfoPlugin;

#[async_trait]
impl Plugin for IpInfoPlugin {
    fn name(&self) -> &'static str {
        "ip_info"
    }

    async fn run(&self, scan_id: Uuid, target: &str, resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()),
        };

        info!(plugin = "ip_info", domain = %domain, "Fetching IP intelligence");
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        // Use resolved IP if available (more accurate + prevents DNS rebinding)
        let query_target = if let Some(ip) = resolved_ip {
            ip.to_string()
        } else {
            domain.clone()
        };

        // Note: ip-api.com free tier does not support HTTPS — using HTTP with awareness.
        // For production, consider ipapi.co (HTTPS) or a paid ip-api.com plan.
        let url = format!("http://ip-api.com/json/{}", query_target);
        if let Ok(res) = client.get(&url).send().await
            && let Ok(data) = res.json::<serde_json::Value>().await
                && data.get("status").and_then(|s| s.as_str()) == Some("success") {
                    let finding = Finding {
                        id: Uuid::new_v4(),
                        scan_id,
                        plugin_name: self.name().to_string(),
                        finding_type: "ip_intelligence".to_string(),
                        data,
                        severity: FindingSeverity::Info,
                        created_at: Utc::now(),
                    };
                    let _ = out_chan.send(finding).await;
                }

        Ok(())
    }
}
