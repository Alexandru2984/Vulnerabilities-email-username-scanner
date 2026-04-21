use crate::models::{Finding, Scan, ScanStatus};
use crate::plugins::{get_all_plugins, TargetType};
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, instrument};
use uuid::Uuid;

pub struct Engine {
    pool: PgPool,
}

impl Engine {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[instrument(skip(self))]
    pub async fn start_scan(&self, target: String) -> anyhow::Result<Uuid> {
        // SSRF protection (String checks + DNS Resolution)
        if !is_safe_target(&target).await {
            return Err(anyhow::anyhow!("Invalid target: Internal or reserved IPs are not allowed"));
        }

        let scan_id = Uuid::new_v4();

        // 1. Create Scan record
        sqlx::query(
            r#"
            INSERT INTO scans (id, target, status, created_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(scan_id)
        .bind(&target)
        .bind("running")
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        info!("Started scan {} for target {}", scan_id, target);

        // 2. Spawn worker to process this scan asynchronously
        let pool_clone = self.pool.clone();
        tokio::spawn(async move {
            Self::run_plugins(scan_id, target, pool_clone).await;
        });

        Ok(scan_id)
    }

    async fn run_plugins(scan_id: Uuid, target: String, pool: PgPool) {
        let plugins = get_all_plugins();
        let (tx, mut rx) = mpsc::channel::<Finding>(100);

        let target_type = classify_target(&target);

        info!("Target {} classified as {:?}", target, target_type);

        let target_arc = Arc::new(target);

        // Spawn each plugin
        let mut handles = vec![];
        for plugin in plugins {
            let tx_clone = tx.clone();
            let target_clone = target_arc.clone();
            let scan_id_clone = scan_id;
            
            let handle = tokio::spawn(async move {
                if let Err(e) = plugin.run(scan_id_clone, &target_clone, target_type, tx_clone).await {
                    error!("Plugin {} failed: {}", plugin.name(), e);
                }
            });
            handles.push(handle);
        }

        // Drop original tx so receiver will close when all clones are dropped
        drop(tx);

        // Process findings
        while let Some(finding) = rx.recv().await {
            // Save finding to DB
            let res = sqlx::query(
                r#"
                INSERT INTO findings (id, scan_id, plugin_name, finding_type, data, severity, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(finding.id)
            .bind(finding.scan_id)
            .bind(&finding.plugin_name)
            .bind(&finding.finding_type)
            .bind(&finding.data)
            .bind(format!("{:?}", finding.severity).to_lowercase())
            .bind(finding.created_at)
            .execute(&pool)
            .await;

            if let Err(e) = res {
                error!("Failed to save finding: {}", e);
            }
        }

        // Wait for all plugins to finish (though the channel closing already means they've dropped tx)
        for handle in handles {
            let _ = handle.await;
        }

        // Update scan status to completed
        let res = sqlx::query(
            r#"
            UPDATE scans
            SET status = 'completed', completed_at = $1
            WHERE id = $2
            "#,
        )
        .bind(Utc::now())
        .bind(scan_id)
        .execute(&pool)
        .await;

        if let Err(e) = res {
            error!("Failed to mark scan {} as completed: {}", scan_id, e);
        } else {
            info!("Scan {} completed successfully", scan_id);
        }
    }
}

pub fn classify_target(target: &str) -> TargetType {
    if target.contains('@') {
        TargetType::Email
    } else if target.contains('.') && !target.contains(' ') {
        TargetType::Domain
    } else {
        TargetType::Username
    }
}

pub async fn is_safe_target(target: &str) -> bool {
    let t_lower = target.to_lowercase();
    if t_lower.contains("localhost") || t_lower.contains("127.0.0.1") || t_lower.contains("169.254") || t_lower.contains("::1") || t_lower.contains("0.0.0.0") || t_lower.starts_with("10.") || t_lower.starts_with("192.168.") || t_lower.starts_with("172.") {
        return false;
    }

    let target_type = classify_target(target);
    if target_type == TargetType::Domain {
        // Resolve DNS to prevent DNS rebinding SSRF
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", target)).await {
            for addr in addrs {
                let ip = addr.ip();
                if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                    return false;
                }
                if let std::net::IpAddr::V4(ipv4) = ip {
                    if ipv4.is_private() || ipv4.is_link_local() || ipv4.is_broadcast() {
                        return false;
                    }
                }
            }
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_target() {
        assert_eq!(classify_target("user@example.com"), TargetType::Email);
        assert_eq!(classify_target("example.com"), TargetType::Domain);
        assert_eq!(classify_target("192.168.1.1"), TargetType::Domain); // IP handled as domain for networking
        assert_eq!(classify_target("john_doe"), TargetType::Username);
    }

    #[tokio::test]
    async fn test_is_safe_target() {
        // String checks
        assert_eq!(is_safe_target("localhost").await, false);
        assert_eq!(is_safe_target("127.0.0.1").await, false);
        assert_eq!(is_safe_target("10.0.0.1").await, false);
        assert_eq!(is_safe_target("169.254.169.254").await, false);

        // Valid external target
        assert_eq!(is_safe_target("google.com").await, true);
        assert_eq!(is_safe_target("user@yahoo.com").await, true);
        assert_eq!(is_safe_target("johndoe").await, true);
    }
}
