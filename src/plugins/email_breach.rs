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

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let email = match target_type {
            TargetType::Email => target.to_string(),
            _ => return Ok(()), // Only run on emails
        };

        info!("Running EmailBreachPlugin for {}", email);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;

        let url = format!("https://api.xposedornot.com/v1/check-email/{}", email);
        let res = client.get(&url).send().await?;

        if res.status() == 404 {
            // Not found in any breaches, which is good
            return Ok(());
        }

        if !res.status().is_success() {
            warn!("XposedOrNot API returned status: {}", res.status());
            return Ok(());
        }

        if let Ok(data) = res.json::<XonResponse>().await {
            if let Some(breaches_array) = data.breaches {
                // The API returns an array of arrays of strings for some reason.
                // Usually `breaches: [["Breach1", "Breach2"]]`
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
        }

        Ok(())
    }
}
