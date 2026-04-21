use crate::models::{Finding, FindingSeverity};
use super::{Plugin, TargetType};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::net::TcpStream;
use tokio::time::timeout;
use uuid::Uuid;
use chrono::Utc;
use tracing::info;
use std::time::Duration;

pub struct PortScannerPlugin;

#[async_trait]
impl Plugin for PortScannerPlugin {
    fn name(&self) -> &'static str {
        "port_scanner"
    }

    async fn run(&self, scan_id: Uuid, target: &str, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()> {
        let domain = match target_type {
            TargetType::Domain => target.to_string(),
            _ => return Ok(()), // Only run on domains or IPs
        };

        info!("Running PortScannerPlugin for {}", domain);
        
        let ports = vec![21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443];
        let scan_timeout = Duration::from_millis(500); // Fast timeout for basic recon

        let mut open_ports = Vec::new();

        // Warning: This scans sequentially for simplicity and safety, but can be parallelized.
        // For bug bounty recon, scanning a few ports sequentially is fine.
        for port in ports {
            let addr = format!("{}:{}", domain, port);
            if let Ok(Ok(_)) = timeout(scan_timeout, TcpStream::connect(&addr)).await {
                open_ports.push(port);
            }
        }

        if !open_ports.is_empty() {
            let finding = Finding {
                id: Uuid::new_v4(),
                scan_id,
                plugin_name: self.name().to_string(),
                finding_type: "open_ports".to_string(),
                data: serde_json::json!({
                    "target": domain,
                    "open_ports": open_ports,
                }),
                severity: FindingSeverity::Info,
                created_at: Utc::now(),
            };
            let _ = out_chan.send(finding).await;
        }

        Ok(())
    }
}
