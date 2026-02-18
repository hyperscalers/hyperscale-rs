//! Network traffic analysis for bandwidth estimation.
//!
//! This module provides tools for analyzing network traffic during simulations
//! to estimate bandwidth requirements for running validator nodes.
//!
//! # Features
//!
//! - Per-message-type statistics (count, bytes, rates)
//! - Per-node traffic breakdown (upload/download)
//! - Human-readable bandwidth estimates (Mbps, GB/hour, TB/month)
//! - Recommended connection requirements
//!
//! # Example
//!
//! ```ignore
//! use hyperscale_network_memory::NetworkTrafficAnalyzer;
//!
//! let analyzer = NetworkTrafficAnalyzer::new();
//!
//! // Record messages as they're sent
//! analyzer.record_message("BlockHeader", 1024, 1056, 0, 1);
//!
//! // Generate report at end of simulation
//! let report = analyzer.generate_report(Duration::from_secs(60), 10);
//! report.print_summary();
//! ```

use crate::NodeIndex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Duration;

/// Network traffic analyzer for bandwidth estimation.
///
/// Tracks all network messages during simulation to provide detailed
/// bandwidth analysis and real-world deployment recommendations.
///
/// Uses atomic operations for counters to allow efficient recording
/// without lock contention.
#[derive(Debug)]
pub struct NetworkTrafficAnalyzer {
    /// Stats per message type.
    by_message_type: RwLock<HashMap<String, MessageTypeStats>>,

    /// Stats per node.
    by_node: RwLock<HashMap<NodeIndex, NodeTrafficStats>>,

    /// Total messages sent.
    total_messages: AtomicU64,

    /// Total bytes sent (payload only).
    total_payload_bytes: AtomicU64,

    /// Total bytes sent (including framing overhead estimate).
    total_wire_bytes: AtomicU64,
}

impl Default for NetworkTrafficAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkTrafficAnalyzer {
    /// Create a new traffic analyzer.
    pub fn new() -> Self {
        Self {
            by_message_type: RwLock::new(HashMap::new()),
            by_node: RwLock::new(HashMap::new()),
            total_messages: AtomicU64::new(0),
            total_payload_bytes: AtomicU64::new(0),
            total_wire_bytes: AtomicU64::new(0),
        }
    }

    /// Record a message being sent.
    ///
    /// # Arguments
    ///
    /// * `msg_type` - The message type name (e.g., "BlockHeader", "StateProvision")
    /// * `payload_size` - Size of the message payload in bytes
    /// * `wire_size` - Size on the wire including framing overhead
    /// * `from` - Sender node index
    /// * `to` - Receiver node index
    pub fn record_message(
        &self,
        msg_type: &str,
        payload_size: usize,
        wire_size: usize,
        from: NodeIndex,
        to: NodeIndex,
    ) {
        // Update totals (atomic operations)
        self.total_messages.fetch_add(1, Ordering::Relaxed);
        self.total_payload_bytes
            .fetch_add(payload_size as u64, Ordering::Relaxed);
        self.total_wire_bytes
            .fetch_add(wire_size as u64, Ordering::Relaxed);

        // Update per-message-type stats
        {
            let mut by_type = self.by_message_type.write().unwrap();
            by_type
                .entry(msg_type.to_string())
                .or_default()
                .record(payload_size as u64, wire_size as u64);
        }

        // Update per-node stats (sender and receiver)
        {
            let mut by_node = self.by_node.write().unwrap();
            by_node
                .entry(from)
                .or_default()
                .record_sent(msg_type, wire_size as u64);
            by_node
                .entry(to)
                .or_default()
                .record_received(msg_type, wire_size as u64);
        }
    }

    /// Get current totals without generating a full report.
    pub fn totals(&self) -> (u64, u64, u64) {
        (
            self.total_messages.load(Ordering::Relaxed),
            self.total_payload_bytes.load(Ordering::Relaxed),
            self.total_wire_bytes.load(Ordering::Relaxed),
        )
    }

    /// Generate a bandwidth report.
    ///
    /// # Arguments
    ///
    /// * `duration` - Total simulation duration
    /// * `num_nodes` - Number of nodes in the simulation
    pub fn generate_report(&self, duration: Duration, num_nodes: usize) -> BandwidthReport {
        let total_messages = self.total_messages.load(Ordering::Relaxed);
        let total_bytes = self.total_wire_bytes.load(Ordering::Relaxed);
        let duration_secs = duration.as_secs_f64();

        // Build per-message-type reports
        let by_type = self.by_message_type.read().unwrap();
        let mut by_message_type: Vec<MessageTypeReport> = by_type
            .iter()
            .map(|(msg_type, stats)| {
                let pct_of_messages = if total_messages > 0 {
                    (stats.count as f64 / total_messages as f64) * 100.0
                } else {
                    0.0
                };
                let pct_of_bandwidth = if total_bytes > 0 {
                    (stats.wire_bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };

                MessageTypeReport {
                    msg_type: msg_type.clone(),
                    count: stats.count,
                    pct_of_messages,
                    total_bytes: stats.wire_bytes,
                    pct_of_bandwidth,
                    avg_size_bytes: stats.avg_size(),
                    min_size_bytes: stats.min_size,
                    max_size_bytes: stats.max_size,
                    messages_per_sec: if duration_secs > 0.0 {
                        stats.count as f64 / duration_secs
                    } else {
                        0.0
                    },
                    bytes_per_sec: if duration_secs > 0.0 {
                        stats.wire_bytes as f64 / duration_secs
                    } else {
                        0.0
                    },
                }
            })
            .collect();

        // Sort by bandwidth consumption (descending)
        by_message_type.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

        // Build per-node reports
        let by_node_lock = self.by_node.read().unwrap();
        let mut by_node: HashMap<NodeIndex, NodeBandwidthReport> = HashMap::new();

        for (&node_id, stats) in by_node_lock.iter() {
            let total_bps = if duration_secs > 0.0 {
                (stats.bytes_sent + stats.bytes_received) as f64 / duration_secs
            } else {
                0.0
            };
            let upload_bps = if duration_secs > 0.0 {
                stats.bytes_sent as f64 / duration_secs
            } else {
                0.0
            };
            let download_bps = if duration_secs > 0.0 {
                stats.bytes_received as f64 / duration_secs
            } else {
                0.0
            };

            by_node.insert(
                node_id,
                NodeBandwidthReport {
                    node_id,
                    messages_sent: stats.messages_sent,
                    messages_received: stats.messages_received,
                    bytes_sent: stats.bytes_sent,
                    bytes_received: stats.bytes_received,
                    total_bytes: stats.bytes_sent + stats.bytes_received,
                    total_bps,
                    upload_bps,
                    download_bps,
                },
            );
        }

        // Calculate aggregate stats
        let total_network_bps = if duration_secs > 0.0 {
            total_bytes as f64 / duration_secs
        } else {
            0.0
        };

        let (avg_node_bps, avg_node_upload_bps, avg_node_download_bps, max_node_bps, min_node_bps) =
            if !by_node.is_empty() {
                let total_upload: f64 = by_node.values().map(|n| n.upload_bps).sum();
                let total_download: f64 = by_node.values().map(|n| n.download_bps).sum();
                let max = by_node
                    .values()
                    .map(|n| n.total_bps)
                    .fold(0.0f64, |a, b| a.max(b));
                let min = by_node
                    .values()
                    .map(|n| n.total_bps)
                    .fold(f64::MAX, |a, b| a.min(b));
                let avg_total = (total_upload + total_download) / num_nodes as f64;

                (
                    avg_total,
                    total_upload / num_nodes as f64,
                    total_download / num_nodes as f64,
                    max,
                    if min == f64::MAX { 0.0 } else { min },
                )
            } else {
                (0.0, 0.0, 0.0, 0.0, 0.0)
            };

        // Calculate human-readable estimates
        let avg_node_mbps = avg_node_bps * 8.0 / 1_000_000.0; // bytes/sec -> Mbps
        let avg_node_gb_per_hour = avg_node_bps * 3600.0 / 1_000_000_000.0;
        let avg_node_gb_per_day = avg_node_gb_per_hour * 24.0;
        let avg_node_tb_per_month = avg_node_gb_per_day * 30.0 / 1000.0;

        let recommended_connection = if avg_node_mbps < 1.0 {
            "1 Mbps (basic broadband)".to_string()
        } else if avg_node_mbps < 10.0 {
            "10 Mbps (standard broadband)".to_string()
        } else if avg_node_mbps < 50.0 {
            "50 Mbps (fast broadband)".to_string()
        } else if avg_node_mbps < 100.0 {
            "100 Mbps (fiber)".to_string()
        } else if avg_node_mbps < 500.0 {
            "500 Mbps (fast fiber)".to_string()
        } else {
            format!("{:.0} Mbps (datacenter)", avg_node_mbps.ceil())
        };

        let estimates = BandwidthEstimates {
            avg_node_mbps,
            avg_node_gb_per_hour,
            avg_node_gb_per_day,
            avg_node_tb_per_month,
            recommended_connection,
        };

        let aggregate = AggregateBandwidth {
            total_network_bps,
            avg_node_bps,
            avg_node_upload_bps,
            avg_node_download_bps,
            max_node_bps,
            min_node_bps,
            estimates,
        };

        BandwidthReport {
            duration,
            num_nodes,
            total_messages,
            total_bytes,
            by_message_type,
            by_node,
            aggregate,
        }
    }
}

/// Statistics for a single message type.
#[derive(Debug, Default, Clone)]
pub struct MessageTypeStats {
    /// Number of messages.
    pub count: u64,
    /// Total payload bytes.
    pub payload_bytes: u64,
    /// Total wire bytes (including framing).
    pub wire_bytes: u64,
    /// Minimum message size.
    pub min_size: u64,
    /// Maximum message size.
    pub max_size: u64,
    /// Sum of sizes (for average calculation).
    size_sum: u64,
}

impl MessageTypeStats {
    /// Record a message of this type.
    pub fn record(&mut self, payload_size: u64, wire_size: u64) {
        self.count += 1;
        self.payload_bytes += payload_size;
        self.wire_bytes += wire_size;
        self.size_sum += wire_size;

        if self.count == 1 {
            self.min_size = wire_size;
            self.max_size = wire_size;
        } else {
            self.min_size = self.min_size.min(wire_size);
            self.max_size = self.max_size.max(wire_size);
        }
    }

    /// Get average message size.
    pub fn avg_size(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.size_sum / self.count
        }
    }
}

/// Per-node traffic statistics.
#[derive(Debug, Default, Clone)]
pub struct NodeTrafficStats {
    /// Messages sent by this node.
    pub messages_sent: u64,
    /// Messages received by this node.
    pub messages_received: u64,
    /// Bytes sent (wire format).
    pub bytes_sent: u64,
    /// Bytes received (wire format).
    pub bytes_received: u64,
    /// Breakdown by message type: (sent_count, recv_count, sent_bytes, recv_bytes).
    pub by_type: HashMap<String, (u64, u64, u64, u64)>,
}

impl NodeTrafficStats {
    /// Record a message sent by this node.
    pub fn record_sent(&mut self, msg_type: &str, wire_size: u64) {
        self.messages_sent += 1;
        self.bytes_sent += wire_size;

        let entry = self.by_type.entry(msg_type.to_string()).or_default();
        entry.0 += 1;
        entry.2 += wire_size;
    }

    /// Record a message received by this node.
    pub fn record_received(&mut self, msg_type: &str, wire_size: u64) {
        self.messages_received += 1;
        self.bytes_received += wire_size;

        let entry = self.by_type.entry(msg_type.to_string()).or_default();
        entry.1 += 1;
        entry.3 += wire_size;
    }
}

/// Bandwidth report for a simulation.
#[derive(Debug, Clone)]
pub struct BandwidthReport {
    /// Simulation duration.
    pub duration: Duration,
    /// Number of nodes.
    pub num_nodes: usize,
    /// Total messages sent.
    pub total_messages: u64,
    /// Total bytes sent.
    pub total_bytes: u64,
    /// Per-message-type breakdown (sorted by bandwidth).
    pub by_message_type: Vec<MessageTypeReport>,
    /// Per-node breakdown.
    pub by_node: HashMap<NodeIndex, NodeBandwidthReport>,
    /// Aggregate bandwidth statistics.
    pub aggregate: AggregateBandwidth,
}

impl BandwidthReport {
    /// Print a summary of the bandwidth report.
    pub fn print_summary(&self) {
        println!();
        println!("================== NETWORK TRAFFIC ANALYSIS ==================");
        println!(
            "Simulation Duration:    {:.2}s",
            self.duration.as_secs_f64()
        );
        println!("Number of Nodes:        {}", self.num_nodes);
        println!("Total Messages:         {}", self.total_messages);
        println!(
            "Total Bandwidth:        {} ({:.2} MB)",
            format_bytes(self.total_bytes),
            self.total_bytes as f64 / 1_000_000.0
        );
        println!();

        println!("=================== AGGREGATE BANDWIDTH ======================");
        println!(
            "Total Network:          {}/s",
            format_bytes(self.aggregate.total_network_bps as u64)
        );
        println!(
            "Avg Per-Node:           {}/s",
            format_bytes(self.aggregate.avg_node_bps as u64)
        );
        println!(
            "  - Upload:             {}/s",
            format_bytes(self.aggregate.avg_node_upload_bps as u64)
        );
        println!(
            "  - Download:           {}/s",
            format_bytes(self.aggregate.avg_node_download_bps as u64)
        );
        println!(
            "Max Node:               {}/s",
            format_bytes(self.aggregate.max_node_bps as u64)
        );
        println!(
            "Min Node:               {}/s",
            format_bytes(self.aggregate.min_node_bps as u64)
        );
        println!();

        println!("================ REAL-WORLD ESTIMATES (per node) =============");
        println!(
            "Bandwidth:              {:.2} Mbps",
            self.aggregate.estimates.avg_node_mbps
        );
        println!(
            "Hourly:                 {:.2} GB/hour",
            self.aggregate.estimates.avg_node_gb_per_hour
        );
        println!(
            "Daily:                  {:.2} GB/day",
            self.aggregate.estimates.avg_node_gb_per_day
        );
        println!(
            "Monthly:                {:.3} TB/month",
            self.aggregate.estimates.avg_node_tb_per_month
        );
        println!(
            "Recommended Connection: {}",
            self.aggregate.estimates.recommended_connection
        );
        println!();

        println!("================ BANDWIDTH BY MESSAGE TYPE ====================");
        println!(
            "{:<24} {:>10} {:>7} {:>12} {:>7} {:>10}",
            "Message Type", "Count", "Msg%", "Bytes", "BW%", "Avg Size"
        );
        println!("{}", "-".repeat(74));

        for report in &self.by_message_type {
            println!(
                "{:<24} {:>10} {:>6.1}% {:>12} {:>6.1}% {:>10}",
                report.msg_type,
                report.count,
                report.pct_of_messages,
                format_bytes(report.total_bytes),
                report.pct_of_bandwidth,
                format_bytes(report.avg_size_bytes),
            );
        }
        println!("================================================================");
    }

    /// Print per-node details (top N nodes by bandwidth).
    pub fn print_node_details(&self, top_n: usize) {
        println!();
        println!("================== PER-NODE BREAKDOWN =========================");

        let mut nodes: Vec<_> = self.by_node.values().collect();
        nodes.sort_by(|a, b| {
            b.total_bytes
                .partial_cmp(&a.total_bytes)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for stats in nodes.iter().take(top_n) {
            println!();
            println!("Node {}:", stats.node_id);
            println!(
                "  Total:    {}/s (Sent: {} / Recv: {})",
                format_bytes(stats.total_bps as u64),
                format_bytes(stats.upload_bps as u64),
                format_bytes(stats.download_bps as u64),
            );
            println!(
                "  Messages: {} sent, {} received",
                stats.messages_sent, stats.messages_received
            );
        }
        println!("================================================================");
    }
}

/// Per-message-type bandwidth report.
#[derive(Debug, Clone)]
pub struct MessageTypeReport {
    /// Message type name.
    pub msg_type: String,
    /// Total count.
    pub count: u64,
    /// Percentage of total messages.
    pub pct_of_messages: f64,
    /// Total bytes.
    pub total_bytes: u64,
    /// Percentage of total bandwidth.
    pub pct_of_bandwidth: f64,
    /// Average message size.
    pub avg_size_bytes: u64,
    /// Minimum message size.
    pub min_size_bytes: u64,
    /// Maximum message size.
    pub max_size_bytes: u64,
    /// Messages per second.
    pub messages_per_sec: f64,
    /// Bytes per second.
    pub bytes_per_sec: f64,
}

/// Per-node bandwidth report.
#[derive(Debug, Clone)]
pub struct NodeBandwidthReport {
    /// Node identifier.
    pub node_id: NodeIndex,
    /// Messages sent.
    pub messages_sent: u64,
    /// Messages received.
    pub messages_received: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Total bytes (sent + received).
    pub total_bytes: u64,
    /// Total bandwidth (bytes/sec).
    pub total_bps: f64,
    /// Upload bandwidth (bytes/sec).
    pub upload_bps: f64,
    /// Download bandwidth (bytes/sec).
    pub download_bps: f64,
}

/// Aggregate bandwidth statistics.
#[derive(Debug, Clone)]
pub struct AggregateBandwidth {
    /// Total network bandwidth (bytes/sec).
    pub total_network_bps: f64,
    /// Average per-node bandwidth (bytes/sec).
    pub avg_node_bps: f64,
    /// Average per-node upload bandwidth (bytes/sec).
    pub avg_node_upload_bps: f64,
    /// Average per-node download bandwidth (bytes/sec).
    pub avg_node_download_bps: f64,
    /// Maximum per-node bandwidth (bytes/sec).
    pub max_node_bps: f64,
    /// Minimum per-node bandwidth (bytes/sec).
    pub min_node_bps: f64,
    /// Human-readable estimates.
    pub estimates: BandwidthEstimates,
}

/// Human-readable bandwidth estimates.
#[derive(Debug, Clone)]
pub struct BandwidthEstimates {
    /// Average per-node bandwidth in Mbps.
    pub avg_node_mbps: f64,
    /// Average per-node bandwidth in GB/hour.
    pub avg_node_gb_per_hour: f64,
    /// Average per-node bandwidth in GB/day.
    pub avg_node_gb_per_day: f64,
    /// Average per-node bandwidth in TB/month.
    pub avg_node_tb_per_month: f64,
    /// Recommended connection type.
    pub recommended_connection: String,
}

/// Format bytes into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_000;
    const MB: u64 = 1_000_000;
    const GB: u64 = 1_000_000_000;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_stats() {
        let mut stats = MessageTypeStats::default();

        stats.record(100, 110);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.min_size, 110);
        assert_eq!(stats.max_size, 110);
        assert_eq!(stats.avg_size(), 110);

        stats.record(200, 220);
        assert_eq!(stats.count, 2);
        assert_eq!(stats.min_size, 110);
        assert_eq!(stats.max_size, 220);
        assert_eq!(stats.avg_size(), 165);
    }

    #[test]
    fn test_traffic_analyzer_basic() {
        let analyzer = NetworkTrafficAnalyzer::new();

        analyzer.record_message("BlockHeader", 1000, 1050, 0, 1);
        analyzer.record_message("BlockHeader", 1000, 1050, 0, 2);
        analyzer.record_message("BlockVote", 200, 210, 1, 0);

        let (messages, _payload, wire) = analyzer.totals();
        assert_eq!(messages, 3);
        assert_eq!(wire, 1050 + 1050 + 210);
    }

    #[test]
    fn test_generate_report() {
        let analyzer = NetworkTrafficAnalyzer::new();

        // Simulate some traffic
        for i in 0..100 {
            analyzer.record_message("BlockHeader", 1000, 1050, 0, 1);
            analyzer.record_message("BlockVote", 200, 210, i % 4, (i + 1) % 4);
        }

        let report = analyzer.generate_report(Duration::from_secs(10), 4);

        assert_eq!(report.total_messages, 200);
        assert_eq!(report.num_nodes, 4);
        assert!(!report.by_message_type.is_empty());

        // BlockHeader should be the largest bandwidth consumer
        assert_eq!(report.by_message_type[0].msg_type, "BlockHeader");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.50 KB");
        assert_eq!(format_bytes(1_500_000), "1.50 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.50 GB");
    }
}
