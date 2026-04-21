use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct TechStackPlugin;

#[async_trait]
impl Plugin for TechStackPlugin {
    fn name(&self) -> &'static str {
        "tech_stack_detector"
    }

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()),
        };

        info!("Running TechStackPlugin for {}", domain);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .danger_accept_invalid_certs(true)
            .build()?;

        let schemes = vec!["http", "https"];
        let mut detected_tech = Vec::new();

        for scheme in schemes {
            let url = format!("{}://{}", scheme, domain);
            if let Ok(res) = client.get(&url).send().await {
                
                // Analyze Headers
                if let Some(server) = res.headers().get("server") {
                    let s = server.to_str().unwrap_or("").to_lowercase();
                    if s.contains("nginx") { detected_tech.push("Nginx".to_string()); }
                    if s.contains("apache") { detected_tech.push("Apache".to_string()); }
                    if s.contains("iis") { detected_tech.push("IIS".to_string()); }
                }

                if let Some(x_powered_by) = res.headers().get("x-powered-by") {
                    let xp = x_powered_by.to_str().unwrap_or("").to_lowercase();
                    if xp.contains("php") { detected_tech.push("PHP".to_string()); }
                    if xp.contains("express") { detected_tech.push("Express.js".to_string()); }
                    if xp.contains("asp.net") { detected_tech.push("ASP.NET".to_string()); }
                }

                // Analyze Body
                if let Ok(body) = res.text().await {
                    let b_lower = body.to_lowercase();
                    
                    // CMS Detection
                    if b_lower.contains("wp-content") || b_lower.contains("wp-includes") {
                        detected_tech.push("WordPress".to_string());
                    }
                    if b_lower.contains("Joomla") {
                        detected_tech.push("Joomla".to_string());
                    }
                    
                    // Frontend Frameworks
                    if b_lower.contains("data-reactroot") || b_lower.contains("_react") {
                        detected_tech.push("React".to_string());
                    }
                    if b_lower.contains("data-v-") || b_lower.contains("vue.js") {
                        detected_tech.push("Vue.js".to_string());
                    }
                    if b_lower.contains("ng-app") || b_lower.contains("ng-version") {
                        detected_tech.push("Angular".to_string());
                    }
                    if b_lower.contains("next/router") || b_lower.contains("_next/static") {
                        detected_tech.push("Next.js".to_string());
                    }
                }

                if !detected_tech.is_empty() {
                    detected_tech.sort();
                    detected_tech.dedup();

                    let finding = Finding {
                        id: Uuid::new_v4(),
                        scan_id,
                        plugin_name: self.name().to_string(),
                        finding_type: "tech_stack".to_string(),
                        data: serde_json::json!({
                            "url": url,
                            "technologies": detected_tech,
                        }),
                        severity: FindingSeverity::Info,
                        created_at: Utc::now(),
                    };
                    let _ = out_chan.send(finding).await;
                    
                    // Break after first successful scheme to avoid duplicates
                    break;
                }
            }
        }

        Ok(())
    }
}
