mod icmp;
mod ping;
mod stats;

use anyhow::Result;
use clap::Parser;
use std::net::{IpAddr, ToSocketAddrs};
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "High-frequency ping tool for network monitoring",
    long_about = "A high-frequency ping tool that sends 100 ICMP packets per second to monitor network latency and packet loss. Supports both IPv4 and IPv6 addresses."
)]
struct Args {
    /// Target address to ping (IP address or hostname)
    target: String,

    /// Output file path for logging ping statistics
    ///
    /// When specified, ping statistics will be written to the file in addition to console output.
    /// Each line contains one second of statistics. Maximum file size is 10MB.
    #[arg(short = 'o', long = "output", help = "Write ping statistics to file (max 10MB)")]
    output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Resolve target address
    let target_ip = resolve_address(&args.target).await?;

    println!("PING {} ({}): 每秒发送100个包 [{}]",
        args.target,
        target_ip,
        if target_ip.is_ipv6() { "IPv6" } else { "IPv4" }
    );

    // Create and start ping session
    let session = ping::PingSession::new(target_ip, args.output)?;

    if let Err(e) = session.start().await {
        eprintln!("Ping session failed: {}", e);

        #[cfg(windows)]
        if e.to_string().contains("permission") || e.to_string().contains("access") {
            eprintln!("Error: Permission denied. Please run as Administrator on Windows.");
        }

        return Err(e);
    }

    Ok(())
}

async fn resolve_address(target: &str) -> Result<IpAddr> {
    // Try to parse as IP address first
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try to resolve hostname
    let addrs: Vec<_> = tokio::task::spawn_blocking({
        let target = target.to_string();
        move || {
            (target.as_str(), 0)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>())
        }
    })
    .await??;

    if addrs.is_empty() {
        anyhow::bail!("Unable to resolve address: {}", target);
    }

    // Prefer IPv4 over IPv6
    for addr in &addrs {
        if addr.is_ipv4() {
            return Ok(addr.ip());
        }
    }

    // Fallback to IPv6
    Ok(addrs[0].ip())
}
