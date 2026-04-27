use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use hickory_resolver::{TokioAsyncResolver, config::*};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;

pub struct DnsPlugin;

#[async_trait]
impl Plugin for DnsPlugin {
    fn name(&self) -> &'static str {
        "dns_info"
    }

    async fn run(&self, scan_id: Uuid, target: &str, _resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            TargetType::Email => target.split('@').next_back().unwrap_or(target).to_string(),
            TargetType::Username => return Ok(()),
        };

        info!(plugin = "dns_info", domain = %domain, "Running DNS lookup");
        
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        // A Records (IPv4)
        if let Ok(lookup) = resolver.ipv4_lookup(domain.as_str()).await {
            let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
            if !ips.is_empty() {
                self.send_finding(scan_id, "A_record", serde_json::json!({ "ips": ips }), out_chan.clone()).await;
            }
        }

        // AAAA Records (IPv6)
        if let Ok(lookup) = resolver.ipv6_lookup(domain.as_str()).await {
            let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
            if !ips.is_empty() {
                self.send_finding(scan_id, "AAAA_record", serde_json::json!({ "ips": ips }), out_chan.clone()).await;
            }
        }

        // MX Records (Mail)
        if let Ok(lookup) = resolver.mx_lookup(domain.as_str()).await {
            let mxs: Vec<String> = lookup.iter().map(|mx| mx.exchange().to_string()).collect();
            if !mxs.is_empty() {
                self.send_finding(scan_id, "MX_record", serde_json::json!({ "exchanges": mxs }), out_chan.clone()).await;
            }
        }

        // TXT Records
        if let Ok(lookup) = resolver.txt_lookup(domain.as_str()).await {
            let txts: Vec<String> = lookup.iter().map(|txt| txt.to_string()).collect();
            if !txts.is_empty() {
                self.send_finding(scan_id, "TXT_record", serde_json::json!({ "texts": txts }), out_chan.clone()).await;
            }
        }

        Ok(())
    }
}

impl DnsPlugin {
    async fn send_finding(&self, scan_id: Uuid, finding_type: &str, data: serde_json::Value, out_chan: mpsc::Sender<Finding>) {
        let finding = Finding {
            id: Uuid::new_v4(),
            scan_id,
            plugin_name: self.name().to_string(),
            finding_type: finding_type.to_string(),
            data,
            severity: FindingSeverity::Info,
            created_at: Utc::now(),
        };
        let _ = out_chan.send(finding).await;
    }
}
