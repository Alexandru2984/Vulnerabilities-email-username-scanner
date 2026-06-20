use crate::models::Finding;
use crate::plugins::{TargetType, get_all_plugins};
use chrono::Utc;
use futures::StreamExt;
use regex::Regex;
use sqlx::PgPool;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

/// Maximum response body size plugins are allowed to read (5 MB)
pub const MAX_BODY_SIZE: usize = 5 * 1024 * 1024;

/// Global scan timeout (5 minutes)
const SCAN_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_MAX_CONCURRENT_SCANS: usize = 3;
const MAX_ALLOWED_CONCURRENT_SCANS: usize = 64;
const MAX_CONCURRENT_SCANS_ENV: &str = "MAX_CONCURRENT_SCANS";

pub struct Engine {
    pool: PgPool,
    scan_slots: Arc<Semaphore>,
}

impl Engine {
    pub fn new(pool: PgPool) -> Self {
        let max_concurrent_scans = configured_max_concurrent_scans()
            .expect("MAX_CONCURRENT_SCANS must be validated before router startup");

        Self {
            pool,
            scan_slots: Arc::new(Semaphore::new(max_concurrent_scans)),
        }
    }

    #[instrument(skip(self))]
    pub async fn start_scan(&self, target: String) -> anyhow::Result<Uuid> {
        // Step 1: Validate input format
        let target = target.trim().to_string();
        validate_target(&target)?;

        let permit =
            self.scan_slots.clone().try_acquire_owned().map_err(|_| {
                anyhow::anyhow!("Too many scans are already running. Try again later.")
            })?;

        // Step 2: SSRF protection — resolve DNS and validate the resolved IP
        let resolved_ip = is_safe_target(&target).await?;

        let scan_id = Uuid::new_v4();

        // Step 3: Create Scan record
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

        info!(scan_id = %scan_id, target = %target, "Started scan");

        // Step 4: Spawn worker with global timeout
        let pool_clone = self.pool.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(
                SCAN_TIMEOUT,
                Self::run_plugins(scan_id, target.clone(), resolved_ip, pool_clone.clone()),
            )
            .await;

            match result {
                Ok(()) => {
                    // Plugins finished normally
                }
                Err(_elapsed) => {
                    warn!(scan_id = %scan_id, "Scan timed out after {:?}", SCAN_TIMEOUT);
                    let res = sqlx::query(
                        r#"
                        UPDATE scans
                        SET status = 'failed', completed_at = $1
                        WHERE id = $2 AND status = 'running'
                        "#,
                    )
                    .bind(Utc::now())
                    .bind(scan_id)
                    .execute(&pool_clone)
                    .await;

                    if let Err(e) = res {
                        error!(scan_id = %scan_id, "Failed to mark timed-out scan as failed: {}", e);
                    }
                }
            }
        });

        Ok(scan_id)
    }

    async fn run_plugins(scan_id: Uuid, target: String, resolved_ip: Option<IpAddr>, pool: PgPool) {
        let plugins = get_all_plugins();
        let (tx, mut rx) = mpsc::channel::<Finding>(100);

        let target_type = classify_target(&target);

        info!(target = %target, target_type = ?target_type, "Target classified");

        let target_arc = Arc::new(target);

        // Spawn each plugin
        let mut handles = vec![];
        for plugin in plugins {
            let tx_clone = tx.clone();
            let target_clone = target_arc.clone();
            let scan_id_clone = scan_id;
            let ip_clone = resolved_ip;

            let handle = tokio::spawn(async move {
                if let Err(e) = plugin
                    .run(
                        scan_id_clone,
                        &target_clone,
                        ip_clone,
                        target_type,
                        tx_clone,
                    )
                    .await
                {
                    error!(plugin = plugin.name(), "Plugin failed: {}", e);
                }
            });
            handles.push(handle);
        }

        // Drop original tx so receiver will close when all clones are dropped
        drop(tx);

        // Process findings
        while let Some(finding) = rx.recv().await {
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

        // Wait for all plugins to finish
        for handle in handles {
            let _ = handle.await;
        }

        // Update scan status to completed
        let res = sqlx::query(
            r#"
            UPDATE scans
            SET status = 'completed', completed_at = $1
            WHERE id = $2 AND status = 'running'
            "#,
        )
        .bind(Utc::now())
        .bind(scan_id)
        .execute(&pool)
        .await;

        if let Err(e) = res {
            error!(scan_id = %scan_id, "Failed to mark scan as completed: {}", e);
        } else {
            info!(scan_id = %scan_id, "Scan completed successfully");
        }
    }
}

pub fn configured_max_concurrent_scans() -> anyhow::Result<usize> {
    match std::env::var(MAX_CONCURRENT_SCANS_ENV) {
        Ok(value) => parse_max_concurrent_scans(&value),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_MAX_CONCURRENT_SCANS),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow::anyhow!(
            "{MAX_CONCURRENT_SCANS_ENV} must be valid UTF-8."
        )),
    }
}

fn parse_max_concurrent_scans(value: &str) -> anyhow::Result<usize> {
    let parsed = value.trim().parse::<usize>().map_err(|_| {
        anyhow::anyhow!("{MAX_CONCURRENT_SCANS_ENV} must be an integer between 1 and {MAX_ALLOWED_CONCURRENT_SCANS}.")
    })?;

    if !(1..=MAX_ALLOWED_CONCURRENT_SCANS).contains(&parsed) {
        anyhow::bail!(
            "{MAX_CONCURRENT_SCANS_ENV} must be between 1 and {MAX_ALLOWED_CONCURRENT_SCANS}."
        );
    }

    Ok(parsed)
}

/// Classify the target into Domain, Email, or Username
pub fn classify_target(target: &str) -> TargetType {
    if target.contains('@') {
        TargetType::Email
    } else if target.contains('.') && !target.contains(' ') {
        TargetType::Domain
    } else {
        TargetType::Username
    }
}

/// Strictly validate target input format using regex allowlists.
/// Blocks control characters, schema prefixes, path traversal, and unicode abuse.
pub fn validate_target(target: &str) -> anyhow::Result<()> {
    // Enforce maximum length
    if target.len() > 255 {
        return Err(anyhow::anyhow!(
            "Target too long. Maximum length is 255 characters."
        ));
    }

    if target.is_empty() {
        return Err(anyhow::anyhow!("Target cannot be empty."));
    }

    // Block control characters, newlines, tabs, null bytes
    if target.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(anyhow::anyhow!(
            "Target contains invalid control characters."
        ));
    }

    // Block schema prefixes
    let lower = target.to_lowercase();
    let blocked_schemas = [
        "://",
        "file:",
        "javascript:",
        "data:",
        "ftp:",
        "gopher:",
        "ldap:",
    ];
    for schema in blocked_schemas {
        if lower.contains(schema) {
            return Err(anyhow::anyhow!("Target contains blocked schema prefix."));
        }
    }

    // Block path traversal
    if target.contains("..") || target.contains('/') || target.contains('\\') {
        return Err(anyhow::anyhow!(
            "Target contains path traversal characters."
        ));
    }

    let target_type = classify_target(target);

    match target_type {
        TargetType::Domain => {
            // Allow either a valid domain name or an IPv4 address
            let domain_re = Regex::new(
                r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
            ).unwrap();
            let ipv4_re = Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$").unwrap();
            if !domain_re.is_match(target) && !ipv4_re.is_match(target) {
                return Err(anyhow::anyhow!(
                    "Invalid domain/IP format. Provide a valid domain name or IPv4 address."
                ));
            }
            // Extra validation for IPs: each octet must be 0-255
            if ipv4_re.is_match(target) {
                let valid_octets = target
                    .split('.')
                    .all(|o| o.parse::<u16>().is_ok_and(|n| n <= 255));
                if !valid_octets {
                    return Err(anyhow::anyhow!("Invalid IP address: octets must be 0-255."));
                }
            }
        }
        TargetType::Email => {
            let email_re =
                Regex::new(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$").unwrap();
            if !email_re.is_match(target) {
                return Err(anyhow::anyhow!("Invalid email format."));
            }
        }
        TargetType::Username => {
            let username_re = Regex::new(r"^[a-zA-Z0-9_.\-]{1,64}$").unwrap();
            if !username_re.is_match(target) {
                return Err(anyhow::anyhow!(
                    "Invalid username format. Only alphanumeric, underscore, dot, and hyphen are allowed (max 64 chars)."
                ));
            }
        }
    }

    Ok(())
}

/// Cloud metadata hostnames that must always be blocked
const BLOCKED_HOSTNAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "kubernetes.default.svc",
    "instance-data",
];

/// Check if an IPv4 address is in a dangerous/internal range
fn is_dangerous_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()   // 169.254.0.0/16 (AWS metadata lives here)
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_unspecified()  // 0.0.0.0
        || ip.is_multicast()    // 224.0.0.0/4
        || is_cgnat(ip)         // 100.64.0.0/10
        || is_documentation(ip) // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        || is_benchmarking(ip)  // 198.18.0.0/15
        || is_reserved_ipv4(ip) // other non-global special-use ranges
}

/// Check for CGNAT range (100.64.0.0/10)
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// Check for documentation/test ranges
fn is_documentation(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 192.0.2.0/24
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
    // 198.51.100.0/24
    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
    // 203.0.113.0/24
    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

/// Check for benchmarking range (198.18.0.0/15)
fn is_benchmarking(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

/// Check for additional special-use IPv4 ranges that should not be scanned from prod.
fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 192.0.0.0/24 IETF protocol assignments, 192.88.99.0/24 6to4 relay,
    // and 240.0.0.0/4 reserved for future use.
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || octets[0] >= 240
}

/// Check if an IPv6 address is dangerous
fn is_dangerous_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()         // ::1
        || ip.is_unspecified()   // ::
        || ip.is_multicast()     // ff00::/8
        || is_ipv6_ula(ip)       // fc00::/7 (Unique Local Address)
        || is_ipv6_link_local(ip) // fe80::/10
        || is_ipv6_documentation(ip) // 2001:db8::/32
        || is_ipv4_mapped_dangerous(ip) // ::ffff:127.0.0.1 etc.
}

/// Check for IPv6 ULA (fc00::/7)
fn is_ipv6_ula(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xFE00) == 0xFC00
}

/// Check for IPv6 link-local (fe80::/10)
fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xFFC0) == 0xFE80
}

/// Check for IPv6 documentation range (2001:db8::/32)
fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn validate_resolved_addrs(
    addrs: &[std::net::SocketAddr],
    blocked_message: &str,
) -> anyhow::Result<()> {
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("Target did not resolve to any IP address."));
    }

    for addr in addrs {
        let ip = addr.ip();
        let is_dangerous = match ip {
            IpAddr::V4(v4) => is_dangerous_ipv4(v4),
            IpAddr::V6(v6) => is_dangerous_ipv6(v6),
        };
        if is_dangerous {
            return Err(anyhow::anyhow!(blocked_message.to_string()));
        }
    }

    Ok(())
}

/// Check if an IPv4-mapped IPv6 address (::ffff:x.x.x.x) maps to a dangerous IPv4
fn is_ipv4_mapped_dangerous(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        is_dangerous_ipv4(ipv4)
    } else {
        false
    }
}

/// SSRF protection: validates the target is safe to scan.
/// For domains and email domains: resolves DNS and validates the resolved IP is public.
/// Returns the resolved IP for use by plugins (prevents DNS rebinding TOCTOU).
///
/// Security model:
/// - Pre-resolution: block known dangerous hostnames
/// - Post-resolution: validate ALL resolved IPs are public
/// - Fail-closed: DNS resolution failure = blocked
pub async fn is_safe_target(target: &str) -> anyhow::Result<Option<IpAddr>> {
    let target_type = classify_target(target);

    let hostname = match target_type {
        TargetType::Domain => Some(target),
        TargetType::Email => target.split('@').next_back(),
        TargetType::Username => None,
    };

    let Some(hostname) = hostname else {
        // Username targets don't need DNS validation.
        return Ok(None);
    };

    let hostname_lower = hostname.to_lowercase();

    // Block known cloud metadata hostnames before DNS resolution.
    for blocked_hostname in BLOCKED_HOSTNAMES {
        if hostname_lower == *blocked_hostname
            || hostname_lower.ends_with(&format!(".{}", blocked_hostname))
        {
            return Err(anyhow::anyhow!(
                "Target hostname is blocked (cloud metadata)."
            ));
        }
    }

    // Resolve DNS and fail closed for both domain and email-domain targets.
    match tokio::net::lookup_host(format!("{}:80", hostname)).await {
        Ok(addrs) => {
            let all_addrs: Vec<_> = addrs.collect();
            let blocked_message = match target_type {
                TargetType::Domain => {
                    "Target resolves to a private/reserved IP address. Scanning internal targets is not allowed."
                }
                TargetType::Email => "Email domain resolves to a private/reserved IP. Not allowed.",
                TargetType::Username => unreachable!("username targets returned before DNS lookup"),
            };
            validate_resolved_addrs(&all_addrs, blocked_message)?;

            // Return the first safe IP for plugins to use (prevents TOCTOU).
            Ok(Some(all_addrs[0].ip()))
        }
        Err(e) => {
            if target_type == TargetType::Email {
                Err(anyhow::anyhow!(
                    "DNS resolution failed for email domain: {}",
                    e
                ))
            } else {
                Err(anyhow::anyhow!("DNS resolution failed for target: {}", e))
            }
        }
    }
}

/// Read response body with a size limit to prevent memory exhaustion DoS.
/// Returns the body as a string, or an error if it exceeds max_size.
pub async fn read_body_limited(
    response: reqwest::Response,
    max_size: usize,
) -> anyhow::Result<String> {
    let content_length = response.content_length().unwrap_or(0) as usize;
    if content_length > max_size {
        return Err(anyhow::anyhow!(
            "Response body too large: {} bytes (max: {})",
            content_length,
            max_size
        ));
    }

    let mut stream = response.bytes_stream();
    let mut body = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > max_size {
            return Err(anyhow::anyhow!(
                "Response body too large: {} bytes (max: {})",
                body.len() + chunk.len(),
                max_size
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_target() {
        assert_eq!(classify_target("user@example.com"), TargetType::Email);
        assert_eq!(classify_target("example.com"), TargetType::Domain);
        assert_eq!(classify_target("john_doe"), TargetType::Username);
    }

    #[test]
    fn test_validate_target_valid() {
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("sub.example.com").is_ok());
        assert!(validate_target("user@example.com").is_ok());
        assert!(validate_target("john_doe").is_ok());
        assert!(validate_target("john.doe").is_ok());
        assert!(validate_target("john-doe").is_ok());
    }

    #[test]
    fn test_parse_max_concurrent_scans() {
        assert_eq!(parse_max_concurrent_scans("1").unwrap(), 1);
        assert_eq!(parse_max_concurrent_scans("64").unwrap(), 64);
        assert_eq!(parse_max_concurrent_scans(" 3 ").unwrap(), 3);
        assert!(parse_max_concurrent_scans("0").is_err());
        assert!(parse_max_concurrent_scans("65").is_err());
        assert!(parse_max_concurrent_scans("abc").is_err());
    }

    #[test]
    fn test_validate_target_blocked() {
        // Control characters
        assert!(validate_target("evil\x00.com").is_err());
        assert!(validate_target("evil\n.com").is_err());
        assert!(validate_target("evil\r.com").is_err());

        // Schema injection
        assert!(validate_target("file:///etc/passwd").is_err());
        assert!(validate_target("javascript:alert(1)").is_err());
        assert!(validate_target("http://evil.com").is_err());

        // Path traversal
        assert!(validate_target("../../etc/passwd").is_err());
        assert!(validate_target("evil.com/path").is_err());

        // Too long
        assert!(validate_target(&"a".repeat(256)).is_err());

        // Empty
        assert!(validate_target("").is_err());
    }

    #[test]
    fn test_dangerous_ipv4() {
        assert!(is_dangerous_ipv4(Ipv4Addr::new(127, 0, 0, 1))); // loopback
        assert!(is_dangerous_ipv4(Ipv4Addr::new(10, 0, 0, 1))); // private
        assert!(is_dangerous_ipv4(Ipv4Addr::new(172, 16, 0, 1))); // private
        assert!(is_dangerous_ipv4(Ipv4Addr::new(192, 168, 1, 1))); // private
        assert!(is_dangerous_ipv4(Ipv4Addr::new(169, 254, 169, 254))); // link-local (AWS metadata)
        assert!(is_dangerous_ipv4(Ipv4Addr::new(0, 0, 0, 0))); // unspecified
        assert!(is_dangerous_ipv4(Ipv4Addr::new(100, 64, 0, 1))); // CGNAT
        assert!(is_dangerous_ipv4(Ipv4Addr::new(100, 127, 255, 255))); // CGNAT upper bound
        assert!(is_dangerous_ipv4(Ipv4Addr::new(198, 18, 0, 1))); // benchmarking
        assert!(is_dangerous_ipv4(Ipv4Addr::new(192, 0, 0, 8))); // IETF protocol assignments
        assert!(is_dangerous_ipv4(Ipv4Addr::new(240, 0, 0, 1))); // reserved

        // Public IPs should NOT be dangerous
        assert!(!is_dangerous_ipv4(Ipv4Addr::new(8, 8, 8, 8))); // Google DNS
        assert!(!is_dangerous_ipv4(Ipv4Addr::new(1, 1, 1, 1))); // Cloudflare
        assert!(!is_dangerous_ipv4(Ipv4Addr::new(172, 1, 1, 1))); // Public (NOT in 172.16/12)
        assert!(!is_dangerous_ipv4(Ipv4Addr::new(100, 63, 255, 255))); // Below CGNAT range
    }

    #[test]
    fn test_dangerous_ipv6() {
        assert!(is_dangerous_ipv6(Ipv6Addr::LOCALHOST)); // ::1
        assert!(is_dangerous_ipv6(Ipv6Addr::UNSPECIFIED)); // ::

        // ULA
        assert!(is_dangerous_ipv6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_dangerous_ipv6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        )));

        // Link-local
        assert!(is_dangerous_ipv6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));

        // Documentation
        assert!(is_dangerous_ipv6(Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
        )));

        // IPv4-mapped dangerous
        assert!(is_dangerous_ipv6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001
        ))); // ::ffff:127.0.0.1

        // Public IPv6 should NOT be dangerous
        assert!(!is_dangerous_ipv6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x800, 0, 0, 0, 0x200e
        ))); // Google
    }

    #[tokio::test]
    async fn test_is_safe_target_blocked_hostnames() {
        assert!(is_safe_target("metadata.google.internal").await.is_err());
        assert!(
            is_safe_target("user@metadata.google.internal")
                .await
                .is_err()
        );
        assert!(is_safe_target("kubernetes.default.svc").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_target_username_skips_dns() {
        assert!(is_safe_target("johndoe").await.is_ok());
    }
}
