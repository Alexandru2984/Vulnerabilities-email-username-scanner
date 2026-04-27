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
    #[serde(rename = "errorMsg", default)]
    error_msg: Option<String>,
    #[serde(rename = "errorUrl", default)]
    #[allow(dead_code)]
    error_url: Option<String>,
}

/// Max body to read for false-positive detection (50 KB)
const FP_MAX_BODY: usize = 50 * 1024;

/// Common "not found" indicators in response bodies
const NOT_FOUND_INDICATORS: &[&str] = &[
    "not found",
    "doesn't exist",
    "does not exist",
    "no such user",
    "page not found",
    "user not found",
    "profile not found",
    "account not found",
    "could not be found",
    "doesn't have a profile",
    "no user named",
    "this page is not available",
    "this account doesn't exist",
    "sorry, this page",
    "nothing here",
    "hmm...this page",
    "the page you were looking for",
    "this user has not",
    "we couldn't find",
    "this page doesn't exist",
    "oops!",
    "404",
    "no results found",
    "was not found on this server",
    "account suspended",
    "account has been suspended",
    "join .* today", // Generic sign-up page
];

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
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
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

        // Phase 1: Probe with a definitely-nonexistent user to get baseline responses
        // This detects sites that return 200 for any username (soft 404)
        let probe_user = "xz__nonexistent__user__9q8w7e6r5t4y";
        let probe_results: Arc<tokio::sync::Mutex<HashMap<String, ProbeResult>>> = 
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        let status_code_sites: Vec<(String, String)> = sites.iter()
            .filter(|(_, site)| site.error_type == "status_code")
            .map(|(name, site)| (name.clone(), site.url.clone()))
            .collect();

        info!(count = status_code_sites.len(), "Loaded sites — running false-positive probes");

        // Run probes in parallel (limited concurrency)
        let probe_tasks: Vec<_> = status_code_sites.iter()
            .map(|(site_name, url_template)| {
                let probe_url = url_template.replace("{}", probe_user);
                let client = client.clone();
                let probe_results = probe_results.clone();
                let site_name = site_name.clone();

                async move {
                    if let Ok(res) = client.get(&probe_url).send().await {
                        let status = res.status().as_u16();
                        let body_len = res.bytes().await.map(|b| b.len()).unwrap_or(0);
                        probe_results.lock().await.insert(site_name, ProbeResult { status, body_len });
                    }
                }
            })
            .collect();

        let mut stream = stream::iter(probe_tasks).buffer_unordered(50);
        while stream.next().await.is_some() {}

        let probe_data = probe_results.lock().await.clone();

        // Phase 2: Check actual username with false-positive filtering
        let mut tasks = Vec::new();
        for (site_name, site_data) in &sites {
            if site_data.error_type != "status_code" {
                continue;
            }

            let url = site_data.url.replace("{}", &username);
            let site_name = site_name.clone();
            let client = client.clone();
            let out_chan = out_chan.clone();
            let username = username.clone();
            let error_msg = site_data.error_msg.clone();
            let probe_baseline = probe_data.get(&site_name).cloned();
            
            tasks.push(async move {
                let res = match client.get(&url).send().await {
                    Ok(r) => r,
                    Err(_) => return,
                };

                let status = res.status().as_u16();

                // Check 1: Must be a success status (2xx)
                if status >= 300 {
                    return;
                }

                // Read body for content-based verification
                let body = match res.bytes().await {
                    Ok(b) if b.len() <= FP_MAX_BODY => String::from_utf8_lossy(&b).to_string(),
                    _ => return,
                };

                let body_lower = body.to_lowercase();

                // Check 2: Probe-based false positive detection
                // If the probe (non-existent user) also got 200 with similar body size,
                // this site returns 200 for everyone → skip it
                if let Some(baseline) = &probe_baseline {
                    if baseline.status == status {
                        let size_diff = (body.len() as i64 - baseline.body_len as i64).unsigned_abs();
                        let threshold = (baseline.body_len as f64 * 0.05) as u64; // 5% tolerance
                        if size_diff <= threshold.max(200) {
                            return; // Same response as non-existent user → false positive
                        }
                    }
                }

                // Check 3: Content-based "not found" detection
                for indicator in NOT_FOUND_INDICATORS {
                    if body_lower.contains(indicator) {
                        return; // Page says user doesn't exist
                    }
                }

                // Check 4: If site provides an error message pattern, check for it
                if let Some(ref err_msg) = error_msg {
                    if body_lower.contains(&err_msg.to_lowercase()) {
                        return; // Error message found in body
                    }
                }

                // Check 5: Body must have some substance (not just a redirect page or empty)
                if body.len() < 500 {
                    return; // Too small — likely not a real profile page
                }

                // Passed all checks — likely a real profile
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
            });
        }

        let mut stream = stream::iter(tasks).buffer_unordered(50);
        while stream.next().await.is_some() {}

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ProbeResult {
    status: u16,
    body_len: usize,
}
