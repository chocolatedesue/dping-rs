mod icmp;
mod ping;
mod stats;

use anyhow::Result;
use clap::Parser;
use std::net::{IpAddr, ToSocketAddrs};
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target address to ping
    target: String,
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
    let session = ping::PingSession::new(target_ip);
    
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
