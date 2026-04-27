use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::Client;
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::{info, warn};
use std::time::Duration;
use serde::Deserialize;
use std::collections::HashMap;
use futures::stream::{self, StreamExt};
use std::sync::Arc;

pub struct UsernameFootprintPlugin;

#[derive(Deserialize, Debug)]
struct SherlockSite {
    url: String,
    #[serde(rename = "errorType")]
    error_type: String,
}

// Load JSON at compile time
const SHERLOCK_DATA: &str = include_str!("sherlock_data.json");

#[async_trait]
impl Plugin for UsernameFootprintPlugin {
    fn name(&self) -> &'static str {
        "username_footprint"
    }

    async fn run(&self, scan_id: Uuid, target: &str, _resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let username = match target_type {
            TargetType::Username => target.to_string(),
            TargetType::Email => target.split('@').next().unwrap_or(target).to_string(),
            TargetType::Domain => return Ok(()),
        };

        info!(plugin = "username_footprint", username = %username, "Running Sherlock username engine");
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()?;

        let client = Arc::new(client);

        let parsed_json: serde_json::Value = match serde_json::from_str(SHERLOCK_DATA) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to parse sherlock data: {}", e);
                return Ok(());
            }
        };

        let mut sites = HashMap::new();
        if let Some(map) = parsed_json.as_object() {
            for (key, val) in map {
                if let Ok(site) = serde_json::from_value::<SherlockSite>(val.clone()) {
                    sites.insert(key.clone(), site);
                }
            }
        }

        let status_code_sites: Vec<(&String, &SherlockSite)> = sites.iter()
            .filter(|(_, site)| site.error_type == "status_code")
            .collect();

        info!(count = status_code_sites.len(), "Loaded sites for checking");

        let mut tasks = Vec::new();
        for (site_name, site_data) in status_code_sites {
            let url = site_data.url.replace("{}", &username);
            let site_name = site_name.clone();
            let client = client.clone();
            let out_chan = out_chan.clone();
            let username = username.clone();
            
            tasks.push(async move {
                if let Ok(res) = client.get(&url).send().await
                    && res.status().is_success() {
                        let finding = Finding {
                            id: Uuid::new_v4(),
                            scan_id,
                            plugin_name: "username_footprint".to_string(),
                            finding_type: "social_profile".to_string(),
                            data: serde_json::json!({
                                "username": username,
                                "platform": site_name,
                                "profile_url": url,
                            }),
                            severity: FindingSeverity::Info,
                            created_at: Utc::now(),
                        };
                        let _ = out_chan.send(finding).await;
                    }
            });
        }

        let mut stream = stream::iter(tasks).buffer_unordered(50);
        while stream.next().await.is_some() {}

        Ok(())
    }
}
