# dping-rs

A high-frequency ping tool for network monitoring written in Rust. This tool sends 100 ICMP packets per second to monitor network latency and packet loss in real-time.

## Features

- **High-frequency pinging**: Sends 100 ICMP packets per second
- **Real-time statistics**: Displays min/avg/max RTT and packet loss every second
- **IPv4 and IPv6 support**: Works with both IP versions
- **File output**: Optional logging to file with size limit (10MB max)
- **Graceful shutdown**: Handles Ctrl+C signal properly
- **Cross-platform**: Works on Linux, macOS, and Windows

## Installation

### Prerequisites

- Rust 1.70 or later
- Raw socket permissions (requires root/administrator privileges)

### Build from source

```bash
git clone <repository-url>
cd dping-rs
cargo build --release
```

The binary will be available at `target/release/dping-rs`.

## Usage

### Basic usage

```bash
# Ping an IP address
sudo ./target/release/dping-rs 8.8.8.8

# Ping a hostname
sudo ./target/release/dping-rs google.com

# Ping IPv6 address
sudo ./target/release/dping-rs 2001:4860:4860::8888
```

### With file output

```bash
# Save statistics to file
sudo ./target/release/dping-rs 8.8.8.8 -o ping_results.log

# Or using long form
sudo ./target/release/dping-rs 8.8.8.8 --output ping_results.log
```

### Help

```bash
./target/release/dping-rs --help
```

## Output Format

The tool displays statistics every second in the following format:

```
[HH:MM:SS] Sent:100 Recv:98 Loss:2.0% | RTT min/avg/max: 12.3/15.7/23.1ms
```

Where:
- `HH:MM:SS`: Current time
- `Sent`: Number of packets sent in the last second (always 100)
- `Recv`: Number of packets received in the last second
- `Loss`: Packet loss percentage
- `RTT min/avg/max`: Minimum, average, and maximum round-trip time in milliseconds

### Example Output

```
PING 8.8.8.8 (8.8.8.8): 每秒发送100个包 [IPv4]
[14:30:15] Sent:100 Recv:100 Loss:0.0% | RTT min/avg/max: 12.1/15.3/18.7ms
[14:30:16] Sent:100 Recv:99 Loss:1.0% | RTT min/avg/max: 11.8/15.1/19.2ms
[14:30:17] Sent:100 Recv:100 Loss:0.0% | RTT min/avg/max: 12.3/15.7/17.9ms
^CShutting down...
Ping session completed
```

## File Output

When using the `-o` option:
- Statistics are written to both console and file
- Each line in the file represents one second of statistics
- File size is limited to 10MB to prevent disk space issues
- File is created if it doesn't exist, or appended to if it exists

## Permissions

This tool requires raw socket permissions to send ICMP packets:

### Linux/macOS
```bash
sudo ./target/release/dping-rs <target>
```

### Windows
Run as Administrator in Command Prompt or PowerShell.

## Technical Details

- **Packet rate**: 100 packets per second (10ms interval)
- **Packet size**: 32 bytes payload with timestamp
- **Statistics interval**: 1 second
- **First second**: Skipped to avoid inaccurate initial statistics
- **Graceful shutdown**: Stops cleanly on Ctrl+C without printing incomplete statistics

## Architecture

The application uses a multi-task async architecture:

1. **Sender Task**: Sends ICMP packets at 100 Hz using a precise timer
2. **Receiver Task**: Continuously receives and processes ICMP replies
3. **Reporter Task**: Collects statistics every second and outputs results

### Key Components

- **ICMP Module** (`src/icmp.rs`): Handles ICMP packet creation and parsing
- **Ping Module** (`src/ping.rs`): Core ping logic and task coordination
- **Stats Module** (`src/stats.rs`): RTT statistics calculation
- **Main Module** (`src/main.rs`): CLI interface and application entry point

### Performance Characteristics

- **Memory usage**: Low, typically under 10MB
- **CPU usage**: Minimal, designed for continuous monitoring
- **Accuracy**: Nanosecond-precision timestamps for RTT measurement
- **Scalability**: Single target, high-frequency monitoring

## Dependencies

- `tokio`: Async runtime
- `clap`: Command-line argument parsing
- `anyhow`: Error handling
- `chrono`: Date and time handling
- `socket2`: Raw socket operations
- `bytes`: Byte manipulation
- `tracing`: Logging framework

## License

[Add your license here]

## Contributing

[Add contributing guidelines here]

## Comparison with Go Version

This Rust implementation provides the same functionality as the original Go version:
- Same packet rate (100 pps)
- Same output format
- Same statistics calculation
- Same graceful shutdown behavior
- Additional file output feature

## Configuration

The tool uses hardcoded constants that can be modified in the source code:

- `PACKETS_PER_SECOND`: 100 (in `src/ping.rs`)
- `MAX_FILE_SIZE`: 10MB (in `src/ping.rs`)
- `PROCESS_ID`: 12345 (in `src/ping.rs`)

## Advanced Usage

### Continuous Monitoring

For long-term monitoring, consider using with system tools:

```bash
# Run in background with nohup
nohup sudo ./target/release/dping-rs 8.8.8.8 -o /var/log/ping.log &

# Use with systemd (create a service file)
# Monitor with log rotation
```

### Log Analysis

The output format is designed for easy parsing:

```bash
# Extract loss percentage
grep "Loss:" ping.log | awk '{print $5}' | sed 's/Loss://' | sed 's/%//'

# Extract average RTT
grep "RTT" ping.log | awk -F'/' '{print $2}'
```

## Troubleshooting

### Permission Denied
Make sure to run with `sudo` on Linux/macOS or as Administrator on Windows.

### Network Unreachable
Check your network connection and ensure the target address is reachable.

### File Write Errors
Ensure you have write permissions to the output directory and sufficient disk space.

### High CPU Usage
This is normal for high-frequency pinging. The tool is optimized but sending 100 packets/second requires some CPU resources.
