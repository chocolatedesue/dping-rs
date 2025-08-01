use crate::icmp::IcmpPacket;
use crate::stats::RttStats;
use anyhow::{Result, Context};
use socket2::{Domain, Protocol, Socket, Type};
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

const PROCESS_ID: u16 = 12345;
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const MIN_WAIT_TIMEOUT: Duration = Duration::from_secs(2); // 最小等待超时时间

pub struct PingSession {
    target: IpAddr,
    is_ipv6: bool,
    packets_per_report: u64,
    interval_ms: u64,
    sequence: Arc<AtomicU16>,
    running: Arc<AtomicBool>,
    output_file: Option<Arc<Mutex<std::fs::File>>>,
    file_size: Arc<Mutex<u64>>,
    max_rtt: Arc<Mutex<Duration>>, // 跟踪最大 RTT 用于动态调整等待时间
}

impl PingSession {
    pub fn new(target: IpAddr, packets_per_report: u64, interval_ms: u64, output_path: Option<String>) -> Result<Self> {
        let is_ipv6 = target.is_ipv6();

        let (output_file, file_size) = if let Some(path) = output_path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("Failed to open output file: {}", path))?;

            let size = file.metadata()
                .map(|m| m.len())
                .unwrap_or(0);

            (Some(Arc::new(Mutex::new(file))), Arc::new(Mutex::new(size)))
        } else {
            (None, Arc::new(Mutex::new(0)))
        };

        Ok(Self {
            target,
            is_ipv6,
            packets_per_report,
            interval_ms,
            sequence: Arc::new(AtomicU16::new(1)),
            running: Arc::new(AtomicBool::new(true)),
            output_file,
            file_size,
            max_rtt: Arc::new(Mutex::new(Duration::from_millis(100))), // 初始最大 RTT 100ms
        })
    }

    /// 写入启动日志到文件（如果启用了文件输出）
    pub fn write_startup_log(&self, target_name: &str) -> Result<()> {
        if let Some(ref file_arc) = self.output_file {
            let now = chrono::Local::now();
            let startup_line = format!(
                "[{}] === PING {} ({}) started: 间隔{}ms发包，每{}个包统计一次 [{}] ===",
                now.format("%H:%M:%S"),
                target_name,
                self.target,
                self.interval_ms,
                self.packets_per_report,
                if self.is_ipv6 { "IPv6" } else { "IPv4" }
            );

            if let (Ok(mut file), Ok(mut size)) = (file_arc.try_lock(), self.file_size.try_lock()) {
                let line_with_newline = format!("{}\n", startup_line);
                let line_bytes = line_with_newline.as_bytes();

                // Check if writing this line would exceed the file size limit
                if *size + line_bytes.len() as u64 <= MAX_FILE_SIZE {
                    if let Ok(_) = file.write_all(line_bytes) {
                        if let Ok(_) = file.flush() {
                            *size += line_bytes.len() as u64;
                        }
                    }
                } else {
                    warn!("Output file size limit ({}MB) reached, skipping startup log write", MAX_FILE_SIZE / 1024 / 1024);
                }
            }
        }
        Ok(())
    }

    /// 写入关闭日志到文件（如果启用了文件输出）
    pub fn write_shutdown_log(&self) -> Result<()> {
        if let Some(ref file_arc) = self.output_file {
            let now = chrono::Local::now();
            let shutdown_line = format!(
                "[{}] === PING session ended ===",
                now.format("%H:%M:%S")
            );

            if let (Ok(mut file), Ok(mut size)) = (file_arc.try_lock(), self.file_size.try_lock()) {
                let line_with_newline = format!("{}\n", shutdown_line);
                let line_bytes = line_with_newline.as_bytes();

                // Check if writing this line would exceed the file size limit
                if *size + line_bytes.len() as u64 <= MAX_FILE_SIZE {
                    if let Ok(_) = file.write_all(line_bytes) {
                        if let Ok(_) = file.flush() {
                            *size += line_bytes.len() as u64;
                        }
                    }
                } else {
                    warn!("Output file size limit ({}MB) reached, skipping shutdown log write", MAX_FILE_SIZE / 1024 / 1024);
                }
            }
        }
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        info!(
            "Starting ping to {} ({})",
            self.target,
            if self.is_ipv6 { "IPv6" } else { "IPv4" }
        );

        // Create channels for communication
        let (rtt_tx, rtt_rx) = mpsc::unbounded_channel();
        let (packet_sent_tx, packet_sent_rx) = mpsc::unbounded_channel();

        // Create socket
        let socket = self.create_socket()?;
        let socket = Arc::new(socket);

        // Start sender task
        let sender_socket = socket.clone();
        let sender_running = self.running.clone();
        let sender_sequence = self.sequence.clone();
        let sender_is_ipv6 = self.is_ipv6;
        let sender_target = self.target;
        let sender_interval_ms = self.interval_ms;
        let sender_task = tokio::spawn(async move {
            Self::sender_task(
                sender_socket,
                sender_running,
                sender_sequence,
                sender_is_ipv6,
                sender_target,
                sender_interval_ms,
                packet_sent_tx,
            )
            .await
        });

        // Start receiver task
        let receiver_socket = socket.clone();
        let receiver_running = self.running.clone();
        let receiver_is_ipv6 = self.is_ipv6;
        let receiver_max_rtt = self.max_rtt.clone();
        let receiver_task = tokio::spawn(async move {
            Self::receiver_task(receiver_socket, receiver_running, receiver_is_ipv6, rtt_tx, receiver_max_rtt).await
        });

        // Start reporter task
        let reporter_running = self.running.clone();
        let reporter_output_file = self.output_file.clone();
        let reporter_file_size = self.file_size.clone();
        let reporter_packets_per_report = self.packets_per_report;
        let reporter_task = tokio::spawn(async move {
            Self::reporter_task(reporter_running, rtt_rx, packet_sent_rx, reporter_output_file, reporter_file_size, reporter_packets_per_report).await
        });

        // Wait for Ctrl+C
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");

        // Signal all tasks to stop
        self.running.store(false, Ordering::SeqCst);

        // Wait for tasks to complete
        let _ = tokio::join!(sender_task, receiver_task, reporter_task);

        // Write shutdown log to file if file output is enabled
        self.write_shutdown_log()?;

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
        interval_ms: u64,
        packet_sent_tx: mpsc::UnboundedSender<()>,
    ) {
        let mut interval = interval(Duration::from_millis(interval_ms));

        while running.load(Ordering::SeqCst) {
            interval.tick().await;

            let seq = sequence.fetch_add(1, Ordering::SeqCst);
            let packet = IcmpPacket::new_echo_request(PROCESS_ID, seq, is_ipv6);
            let data = packet.to_bytes();

            let addr = SocketAddr::new(target, 0);

            match socket.send_to(&data, &addr.into()) {
                Ok(_) => {
                    debug!("Sent packet with sequence {}", seq);
                    // Notify that a packet was sent
                    let _ = packet_sent_tx.send(());
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("Failed to send packet: {}", e);
                    }
                    // Still count as sent for statistics purposes
                    let _ = packet_sent_tx.send(());
                }
            }
        }
    }

    async fn receiver_task(
        socket: Arc<Socket>,
        running: Arc<AtomicBool>,
        is_ipv6: bool,
        rtt_tx: mpsc::UnboundedSender<Duration>,
        max_rtt: Arc<Mutex<Duration>>,
    ) {
        let mut buffer = [MaybeUninit::new(0u8); 1024];

        while running.load(Ordering::SeqCst) {
            // 计算动态等待超时时间: max(2s, 2 * MAX_RTT)
            let wait_timeout = {
                let current_max_rtt = max_rtt.lock().unwrap();
                let dynamic_timeout = *current_max_rtt * 2;
                std::cmp::max(MIN_WAIT_TIMEOUT, dynamic_timeout)
            };

            // 使用 tokio::time::timeout 来实现等待超时
            match tokio::time::timeout(wait_timeout, async {
                loop {
                    match socket.recv(&mut buffer) {
                        Ok(n) => {
                            // Convert MaybeUninit to initialized bytes
                            let data: Vec<u8> = buffer[..n]
                                .iter()
                                .map(|b| unsafe { b.assume_init() })
                                .collect();

                            if let Some((_, rtt)) = IcmpPacket::from_bytes(&data, is_ipv6) {
                                if rtt < Duration::from_secs(5) { // 放宽 RTT 限制到 5 秒
                                    // 更新最大 RTT
                                    {
                                        let mut current_max_rtt = max_rtt.lock().unwrap();
                                        if rtt > *current_max_rtt {
                                            *current_max_rtt = rtt;
                                        }
                                    }
                                    let _ = rtt_tx.send(rtt);
                                }
                            }
                            return;
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                warn!("Failed to receive packet: {}", e);
                                return;
                            }
                            // 短暂延迟避免忙等待
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                }
            }).await {
                Ok(_) => {
                    // 成功接收到包
                }
                Err(_) => {
                    // 超时，这是正常的，继续下一轮接收
                    debug!("Receive timeout after {:?}", wait_timeout);
                }
            }
        }
    }

    async fn reporter_task(
        running: Arc<AtomicBool>,
        mut rtt_rx: mpsc::UnboundedReceiver<Duration>,
        mut packet_sent_rx: mpsc::UnboundedReceiver<()>,
        output_file: Option<Arc<Mutex<std::fs::File>>>,
        file_size: Arc<Mutex<u64>>,
        packets_per_report: u64,
    ) {
        let mut stats = RttStats::new();
        let mut packets_sent_count = 0u64;
        let mut is_first_batch = true; // 标记是否为第一批统计

        while running.load(Ordering::SeqCst) {
            // Wait for packets to be sent and collect RTT responses
            while packets_sent_count < packets_per_report && running.load(Ordering::SeqCst) {
                tokio::select! {
                    // A packet was sent
                    sent_result = packet_sent_rx.recv() => {
                        match sent_result {
                            Some(_) => {
                                packets_sent_count += 1;
                            }
                            None => {
                                // Sender channel closed, exit
                                return;
                            }
                        }
                    }
                    // An RTT response was received
                    rtt_result = rtt_rx.recv() => {
                        match rtt_result {
                            Some(rtt) => {
                                // 只有非第一批才记录统计数据
                                if !is_first_batch {
                                    stats.add_sample(rtt);
                                }
                            }
                            None => {
                                // RTT channel closed, but continue processing sent packets
                            }
                        }
                    }
                }
            }

            // Check if we should stop before outputting statistics
            if !running.load(Ordering::SeqCst) {
                break;
            }

            // Collect any remaining RTT samples that might have arrived
            while let Ok(rtt) = rtt_rx.try_recv() {
                // 只有非第一批才记录统计数据
                if !is_first_batch {
                    stats.add_sample(rtt);
                }
            }

            // 如果是第一批，跳过统计输出，只收集 RTT 数据用于初始化
            if is_first_batch {
                info!("First batch completed, skipping statistics (warming up)");
                is_first_batch = false;
                // 重置计数器，但不输出统计
                stats = RttStats::new();
                packets_sent_count = 0;
                continue;
            }

            // Generate statistics report
            let sent = packets_per_report;
            let received = stats.count;
            let loss = if sent > 0 {
                ((sent as i64 - received as i64) as f64 / sent as f64) * 100.0
            } else {
                0.0
            };

            let now = chrono::Local::now();
            let output_line = format!(
                "[{}] Sent:{} Recv:{} Loss:{:.1}% | RTT min/avg/max: {:.1}/{:.1}/{:.1}ms",
                now.format("%H:%M:%S"),
                sent,
                received,
                loss.max(0.0),
                stats.min_ms(),
                stats.average_ms(),
                stats.max_ms()
            );

            // Print to console
            println!("{}", output_line);

            // Write to file if specified
            if let Some(ref file_arc) = output_file {
                if let (Ok(mut file), Ok(mut size)) = (file_arc.try_lock(), file_size.try_lock()) {
                    let line_with_newline = format!("{}\n", output_line);
                    let line_bytes = line_with_newline.as_bytes();

                    // Check if writing this line would exceed the file size limit
                    if *size + line_bytes.len() as u64 <= MAX_FILE_SIZE {
                        if let Ok(_) = file.write_all(line_bytes) {
                            if let Ok(_) = file.flush() {
                                *size += line_bytes.len() as u64;
                            }
                        }
                    } else {
                        warn!("Output file size limit ({}MB) reached, skipping file write", MAX_FILE_SIZE / 1024 / 1024);
                    }
                }
            }

            // Reset for next report
            stats = RttStats::new();
            packets_sent_count = 0;
        }
    }
}
