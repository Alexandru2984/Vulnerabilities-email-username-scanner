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

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()), // Only run on domains or IPs
        };

        info!("Running IpInfoPlugin for {}", domain);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let url = format!("http://ip-api.com/json/{}", domain);
        if let Ok(res) = client.get(&url).send().await {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if data.get("status").and_then(|s| s.as_str()) == Some("success") {
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
            }
        }

        Ok(())
    }
}
