use bytes::{BytesMut, BufMut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ICMP packet types
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

/// ICMP packet structure
#[derive(Debug, Clone)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    #[allow(dead_code)]
    pub checksum: u16,
    pub id: u16,
    pub sequence: u16,
    pub data: Vec<u8>,
}

impl IcmpPacket {
    /// Create a new ICMP Echo Request packet
    pub fn new_echo_request(id: u16, sequence: u16, is_ipv6: bool) -> Self {
        let icmp_type = if is_ipv6 {
            ICMPV6_ECHO_REQUEST
        } else {
            ICMP_ECHO_REQUEST
        };

        // Create payload with timestamp
        let mut data = vec![0u8; 32];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        data[0..8].copy_from_slice(&timestamp.to_be_bytes());
        
        // Fill remaining data with pattern
        for (i, byte) in data[8..].iter_mut().enumerate() {
            *byte = (i + 8) as u8;
        }

        Self {
            icmp_type,
            code: 0,
            checksum: 0,
            id,
            sequence,
            data,
        }
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = BytesMut::with_capacity(8 + self.data.len());
        
        packet.put_u8(self.icmp_type);
        packet.put_u8(self.code);
        packet.put_u16(0); // Checksum will be calculated later
        packet.put_u16(self.id);
        packet.put_u16(self.sequence);
        packet.extend_from_slice(&self.data);

        let mut bytes = packet.to_vec();
        let checksum = calculate_checksum(&bytes);
        bytes[2..4].copy_from_slice(&checksum.to_be_bytes());

        bytes
    }

    /// Parse ICMP packet from bytes
    pub fn from_bytes(data: &[u8], is_ipv6: bool) -> Option<(Self, Duration)> {
        if data.len() < 8 {
            return None;
        }

        let mut offset = 0;

        // For IPv4, skip IP header
        if !is_ipv6 {
            if data.len() < 28 { // IP header (20) + ICMP header (8)
                return None;
            }
            let ip_header_len = ((data[0] & 0xf) as usize) * 4;
            if data.len() < ip_header_len + 8 {
                return None;
            }
            offset = ip_header_len;
        }

        let icmp_data = &data[offset..];
        if icmp_data.len() < 8 {
            return None;
        }

        let icmp_type = icmp_data[0];
        let expected_reply_type = if is_ipv6 {
            ICMPV6_ECHO_REPLY
        } else {
            ICMP_ECHO_REPLY
        };

        if icmp_type != expected_reply_type {
            return None;
        }

        let code = icmp_data[1];
        let checksum = u16::from_be_bytes([icmp_data[2], icmp_data[3]]);
        let id = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
        let sequence = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);

        let payload = if icmp_data.len() > 8 {
            icmp_data[8..].to_vec()
        } else {
            vec![]
        };

        // Calculate RTT if timestamp is available
        let rtt = if payload.len() >= 8 {
            let timestamp_bytes: [u8; 8] = payload[0..8].try_into().ok()?;
            let timestamp = u64::from_be_bytes(timestamp_bytes);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            
            if timestamp > 0 && timestamp <= now {
                let rtt_nanos = now - timestamp;
                if rtt_nanos < 5_000_000_000 { // Less than 5 seconds
                    Duration::from_nanos(rtt_nanos)
                } else {
                    Duration::from_micros(50) // Fallback for localhost
                }
            } else {
                Duration::from_micros(100) // Fallback
            }
        } else {
            Duration::from_micros(100) // Fallback
        };

        let packet = Self {
            icmp_type,
            code,
            checksum,
            id,
            sequence,
            data: payload,
        };

        Some((packet, rtt))
    }
}

/// Calculate ICMP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Sum all 16-bit words
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    
    // Add carry bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    !(sum as u16)
}
