use crate::core::read_body_limited;
use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use reqwest::{Client, redirect::Policy};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct HttpPlugin;

/// Max body to read for title extraction (2 MB)
const HTTP_MAX_BODY: usize = 2 * 1024 * 1024;

#[async_trait]
impl Plugin for HttpPlugin {
    fn name(&self) -> &'static str {
        "http_probe"
    }

    async fn run(&self, scan_id: Uuid, target: &str, resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            TargetType::Email => target.split('@').last().unwrap_or(target).to_string(),
            TargetType::Username => return Ok(()),
        };

        info!(plugin = "http_probe", domain = %domain, "Probing HTTP/HTTPS");
        
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none()) // Prevent SSRF via redirect
            .danger_accept_invalid_certs(true) // Intentional for recon — accept invalid certs
            .build()?;

        // Use resolved IP to prevent DNS rebinding TOCTOU
        let host_target = if let Some(ip) = resolved_ip {
            ip.to_string()
        } else {
            domain.clone()
        };

        let schemes = vec!["http", "https"];
        
        for scheme in schemes {
            let url = format!("{}://{}", scheme, host_target);
            let request = client.get(&url)
                .header("Host", &domain); // Host header for virtual hosting

            if let Ok(res) = request.send().await {
                let status = res.status().as_u16();
                
                // Extract interesting headers
                let server = res.headers().get("server").and_then(|h| h.to_str().ok()).unwrap_or("unknown").to_string();
                let x_powered_by = res.headers().get("x-powered-by").and_then(|h| h.to_str().ok()).unwrap_or("unknown").to_string();
                
                // WAF Detection
                let mut waf = "none".to_string();
                let server_lower = server.to_lowercase();
                if server_lower.contains("cloudflare") || res.headers().contains_key("cf-ray") {
                    waf = "Cloudflare".to_string();
                } else if server_lower.contains("awselb") {
                    waf = "AWS WAF / ELB".to_string();
                } else if server_lower.contains("imperva") || res.headers().contains_key("x-iinfo") {
                    waf = "Imperva".to_string();
                }

                // Read body with size limit for title extraction
                let mut title = String::new();
                if let Ok(body) = read_body_limited(res, HTTP_MAX_BODY).await
                    && let Some(start) = body.find("<title>")
                        && let Some(end) = body[start..].find("</title>") {
                            title = body[start + 7..start + end].to_string();
                        }

                let finding = Finding {
                    id: Uuid::new_v4(),
                    scan_id,
                    plugin_name: self.name().to_string(),
                    finding_type: "http_response".to_string(),
                    data: serde_json::json!({
                        "url": format!("{}://{}", scheme, domain),
                        "status": status,
                        "server": server,
                        "x_powered_by": x_powered_by,
                        "waf": waf,
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
