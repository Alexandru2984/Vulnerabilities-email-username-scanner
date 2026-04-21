use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn};
use std::collections::HashSet;

pub struct CrtShPlugin;

#[derive(Deserialize, Debug)]
struct CrtShEntry {
    name_value: String,
}

#[async_trait]
impl Plugin for CrtShPlugin {
    fn name(&self) -> &'static str {
        "subdomain_crtsh"
    }

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            TargetType::Email => target.split('@').last().unwrap_or(target).to_string(),
            TargetType::Username => return Ok(()),
        };

        info!("Running CrtShPlugin for domain {}", domain);
        
        let url = format!("https://crt.sh/?q={}&output=json", domain);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let res = client.get(&url).send().await?;
        
        if !res.status().is_success() {
            warn!("Crt.sh returned non-success status: {}", res.status());
            return Ok(());
        }

        let entries: Vec<CrtShEntry> = res.json().await.unwrap_or_default();
        let mut subdomains = HashSet::new();

        for entry in entries {
            for sub in entry.name_value.split('\n') {
                let sub = sub.trim().to_lowercase();
                if !sub.is_empty() && !sub.contains('*') && sub.ends_with(&domain) {
                    subdomains.insert(sub);
                }
            }
        }

        for sub in subdomains {
            let finding = Finding {
                id: Uuid::new_v4(),
                scan_id,
                plugin_name: self.name().to_string(),
                finding_type: "subdomain".to_string(),
                data: serde_json::json!({ "subdomain": sub }),
                severity: FindingSeverity::Info,
                created_at: Utc::now(),
            };
            
            if out_chan.send(finding).await.is_err() {
                break; // Receiver dropped
            }
        }

        Ok(())
    }
}
