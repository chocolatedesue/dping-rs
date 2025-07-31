use std::time::Duration;

/// RTT statistics for a time interval
#[derive(Debug, Clone, Default)]
pub struct RttStats {
    pub min: Duration,
    pub max: Duration,
    pub total: Duration,
    pub count: usize,
}

impl RttStats {
    pub fn new() -> Self {
        Self {
            min: Duration::from_secs(u64::MAX), // Initialize with max value
            max: Duration::ZERO,
            total: Duration::ZERO,
            count: 0,
        }
    }

    pub fn add_sample(&mut self, rtt: Duration) {
        if self.count == 0 {
            self.min = rtt;
        } else if rtt < self.min {
            self.min = rtt;
        }
        
        if rtt > self.max {
            self.max = rtt;
        }
        
        self.total += rtt;
        self.count += 1;
    }

    pub fn average(&self) -> Duration {
        if self.count == 0 {
            Duration::ZERO
        } else {
            self.total / self.count as u32
        }
    }

    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.min = Duration::from_secs(u64::MAX);
        self.max = Duration::ZERO;
        self.total = Duration::ZERO;
        self.count = 0;
    }

    pub fn min_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.min.as_secs_f64() * 1000.0
        }
    }

    pub fn max_ms(&self) -> f64 {
        self.max.as_secs_f64() * 1000.0
    }

    pub fn average_ms(&self) -> f64 {
        self.average().as_secs_f64() * 1000.0
    }
}
