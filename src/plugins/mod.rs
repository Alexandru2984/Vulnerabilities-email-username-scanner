use crate::models::Finding;
use async_trait::async_trait;
use tokio::sync::mpsc;
use uuid::Uuid;

pub mod dns;
pub mod email_breach;
pub mod fuzzer;
pub mod http;
pub mod ip_info;
pub mod port_scanner;
pub mod robots_txt;
pub mod security_headers;
pub mod subdomain;
pub mod tech_stack;
pub mod username;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetType {
    Domain,
    Email,
    Username,
}

#[async_trait]
pub trait Plugin: Send + Sync {
    /// Name of the plugin
    fn name(&self) -> &'static str;

    /// Runs the plugin against a target and streams findings to the channel.
    /// `resolved_ip` is the DNS-resolved IP from SSRF validation — plugins MUST use
    /// this IP for network connections instead of re-resolving the domain to prevent
    /// DNS rebinding TOCTOU attacks.
    async fn run(&self, scan_id: Uuid, target: &str, resolved_ip: Option<std::net::IpAddr>, target_type: TargetType, out_chan: mpsc::Sender<Finding>) -> anyhow::Result<()>;
}

/// Helper function to register all available plugins
pub fn get_all_plugins() -> Vec<Box<dyn Plugin>> {
    vec![
        Box::new(subdomain::CrtShPlugin),
        Box::new(dns::DnsPlugin),
        Box::new(http::HttpPlugin),
        Box::new(email_breach::EmailBreachPlugin),
        Box::new(username::UsernameFootprintPlugin),
        Box::new(port_scanner::PortScannerPlugin),
        Box::new(ip_info::IpInfoPlugin),
        Box::new(tech_stack::TechStackPlugin),
        Box::new(fuzzer::FuzzerPlugin),
        Box::new(security_headers::SecurityHeadersPlugin),
        Box::new(robots_txt::RobotsTxtPlugin),
    ]
}
