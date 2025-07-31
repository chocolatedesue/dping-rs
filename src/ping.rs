use crate::icmp::IcmpPacket;
use crate::stats::RttStats;
use anyhow::{Result, Context};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

const PACKETS_PER_SECOND: u64 = 100;
const PACKET_INTERVAL_MS: u64 = 1000 / PACKETS_PER_SECOND;
const PROCESS_ID: u16 = 12345;

pub struct PingSession {
    target: IpAddr,
    is_ipv6: bool,
    sequence: Arc<AtomicU16>,
    running: Arc<AtomicBool>,
}

impl PingSession {
    pub fn new(target: IpAddr) -> Self {
        let is_ipv6 = target.is_ipv6();
        Self {
            target,
            is_ipv6,
            sequence: Arc::new(AtomicU16::new(1)),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!(
            "Starting ping to {} ({})",
            self.target,
            if self.is_ipv6 { "IPv6" } else { "IPv4" }
        );

        // Create channels for communication
        let (rtt_tx, rtt_rx) = mpsc::unbounded_channel();

        // Create socket
        let socket = self.create_socket()?;
        let socket = Arc::new(socket);

        // Start sender task
        let sender_socket = socket.clone();
        let sender_running = self.running.clone();
        let sender_sequence = self.sequence.clone();
        let sender_is_ipv6 = self.is_ipv6;
        let sender_target = self.target;
        let sender_task = tokio::spawn(async move {
            Self::sender_task(
                sender_socket,
                sender_running,
                sender_sequence,
                sender_is_ipv6,
                sender_target,
            )
            .await
        });

        // Start receiver task
        let receiver_socket = socket.clone();
        let receiver_running = self.running.clone();
        let receiver_is_ipv6 = self.is_ipv6;
        let receiver_task = tokio::spawn(async move {
            Self::receiver_task(receiver_socket, receiver_running, receiver_is_ipv6, rtt_tx).await
        });

        // Start reporter task
        let reporter_running = self.running.clone();
        let reporter_task = tokio::spawn(async move {
            Self::reporter_task(reporter_running, rtt_rx).await
        });

        // Wait for Ctrl+C
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        // Signal all tasks to stop
        self.running.store(false, Ordering::SeqCst);

        // Wait for tasks to complete
        let _ = tokio::join!(sender_task, receiver_task, reporter_task);

        info!("Ping session completed");
        Ok(())
    }

    fn create_socket(&self) -> Result<Socket> {
        let domain = if self.is_ipv6 {
            Domain::IPV6
        } else {
            Domain::IPV4
        };

        let protocol = if self.is_ipv6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };

        let socket = Socket::new(domain, Type::RAW, Some(protocol))
            .context("Failed to create raw socket")?;

        // Set socket to non-blocking
        socket.set_nonblocking(true)?;

        Ok(socket)
    }

    async fn sender_task(
        socket: Arc<Socket>,
        running: Arc<AtomicBool>,
        sequence: Arc<AtomicU16>,
        is_ipv6: bool,
        target: IpAddr,
    ) {
        let mut interval = interval(Duration::from_millis(PACKET_INTERVAL_MS));
        
        while running.load(Ordering::SeqCst) {
            interval.tick().await;

            let seq = sequence.fetch_add(1, Ordering::SeqCst);
            let packet = IcmpPacket::new_echo_request(PROCESS_ID, seq, is_ipv6);
            let data = packet.to_bytes();

            let addr = SocketAddr::new(target, 0);
            
            match socket.send_to(&data, &addr.into()) {
                Ok(_) => {
                    debug!("Sent packet with sequence {}", seq);
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("Failed to send packet: {}", e);
                    }
                }
            }
        }
    }

    async fn receiver_task(
        socket: Arc<Socket>,
        running: Arc<AtomicBool>,
        is_ipv6: bool,
        rtt_tx: mpsc::UnboundedSender<Duration>,
    ) {
        let mut buffer = [MaybeUninit::new(0u8); 1024];

        while running.load(Ordering::SeqCst) {
            match socket.recv(&mut buffer) {
                Ok(n) => {
                    // Convert MaybeUninit to initialized bytes
                    let data: Vec<u8> = buffer[..n]
                        .iter()
                        .map(|b| unsafe { b.assume_init() })
                        .collect();

                    if let Some((_, rtt)) = IcmpPacket::from_bytes(&data, is_ipv6) {
                        if rtt < Duration::from_secs(1) {
                            let _ = rtt_tx.send(rtt);
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("Failed to receive packet: {}", e);
                    }
                    // Small delay to prevent busy waiting
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    }

    async fn reporter_task(
        running: Arc<AtomicBool>,
        mut rtt_rx: mpsc::UnboundedReceiver<Duration>,
    ) {
        let mut interval = interval(Duration::from_secs(1));
        
        while running.load(Ordering::SeqCst) {
            interval.tick().await;

            let mut stats = RttStats::new();
            
            // Collect all RTT samples from the past second
            while let Ok(rtt) = rtt_rx.try_recv() {
                stats.add_sample(rtt);
            }

            let sent = PACKETS_PER_SECOND;
            let received = stats.count;
            let loss = if sent > 0 {
                ((sent as i64 - received as i64) as f64 / sent as f64) * 100.0
            } else {
                0.0
            };

            let now = chrono::Local::now();
            println!(
                "[{}] Sent:{} Recv:{} Loss:{:.1}% | RTT min/avg/max: {:.1}/{:.1}/{:.1}ms",
                now.format("%H:%M:%S"),
                sent,
                received,
                loss.max(0.0),
                stats.min_ms(),
                stats.average_ms(),
                stats.max_ms()
            );
        }
    }
}
