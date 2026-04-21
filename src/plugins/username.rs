use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::Client;
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct UsernameFootprintPlugin;

#[async_trait]
impl Plugin for UsernameFootprintPlugin {
    fn name(&self) -> &'static str {
        "username_footprint"
    }

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let username = match target_type {
            TargetType::Username => target.to_string(),
            TargetType::Email => target.split('@').next().unwrap_or(target).to_string(),
            TargetType::Domain => return Ok(()), // Don't run on domains
        };

        info!("Running UsernameFootprintPlugin for {}", username);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()?;

        // Check GitHub
        let github_url = format!("https://github.com/{}", username);
        if let Ok(res) = client.get(&github_url).send().await {
            if res.status() == 200 {
                self.send_finding(scan_id, &username, "github", &github_url, out_chan.clone()).await;
            }
        }

        // Check Reddit
        let reddit_url = format!("https://www.reddit.com/user/{}/about.json", username);
        if let Ok(res) = client.get(&reddit_url).send().await {
            // Reddit returns 200 for valid users, 404 for missing ones
            if res.status() == 200 {
                self.send_finding(scan_id, &username, "reddit", format!("https://www.reddit.com/user/{}", username).as_str(), out_chan.clone()).await;
            }
        }

        Ok(())
    }
}

impl UsernameFootprintPlugin {
    async fn send_finding(&self, scan_id: Uuid, username: &str, platform: &str, url: &str, out_chan: mpsc::Sender<Finding>) {
        let finding = Finding {
            id: Uuid::new_v4(),
            scan_id,
            plugin_name: self.name().to_string(),
            finding_type: "social_profile".to_string(),
            data: serde_json::json!({
                "username": username,
                "platform": platform,
                "profile_url": url,
            }),
            severity: FindingSeverity::Info,
            created_at: Utc::now(),
        };
        let _ = out_chan.send(finding).await;
    }
}
