use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn};
use std::time::Duration;

pub struct EmailBreachPlugin;

#[derive(Deserialize, Debug)]
struct XonResponse {
    breaches: Option<Vec<Vec<String>>>,
}

#[async_trait]
impl Plugin for EmailBreachPlugin {
    fn name(&self) -> &'static str {
        "email_breach_xon"
    }

    async fn run(&self, scan_id: Uuid, target: &str, _resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let email = match target_type {
            TargetType::Email => target.to_string(),
            _ => return Ok(()), // Only run on emails
        };

        info!(plugin = "email_breach", email = %email, "Checking breach databases");
        
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        // URL-encode the email for safe query
        let encoded_email = urlencoding::encode(&email);
        let url = format!("https://api.xposedornot.com/v1/check-email/{}", encoded_email);
        let res = client.get(&url).send().await?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            // Not found in any breaches, which is good
            return Ok(());
        }

        if !res.status().is_success() {
            warn!(status = %res.status(), "XposedOrNot API returned non-success status");
            return Ok(());
        }

        if let Ok(data) = res.json::<XonResponse>().await
            && let Some(breaches_array) = data.breaches {
                let mut flat_breaches = Vec::new();
                for breach_list in breaches_array {
                    flat_breaches.extend(breach_list);
                }

                if !flat_breaches.is_empty() {
                    let finding = Finding {
                        id: Uuid::new_v4(),
                        scan_id,
                        plugin_name: self.name().to_string(),
                        finding_type: "data_breach".to_string(),
                        data: serde_json::json!({
                            "email": email,
                            "breaches": flat_breaches,
                            "source": "XposedOrNot",
                        }),
                        severity: FindingSeverity::High,
                        created_at: Utc::now(),
                    };
                    let _ = out_chan.send(finding).await;
                }
            }

        Ok(())
    }
}
