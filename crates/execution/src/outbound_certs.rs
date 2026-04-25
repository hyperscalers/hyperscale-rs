//! Tracks execution certificates this shard's wave leader broadcast to
//! remote shards, re-broadcasting on a deterministic interval until the
//! local wave finalizes (proof every participating shard, including the
//! target, contributed an EC) or the [`RETENTION_HORIZON`] elapses.
//!
//! Symmetric to `OutboundProvisionTracker` in `hyperscale-provisions`:
//! that guards source→target provision delivery, this guards
//! target→source EC delivery. Without it, a single dropped gossip leaves
//! the source waiting on its 24s execution timeout + fallback fetch +
//! per-peer rotation before recovery; a sustained drop wedges the
//! cross-shard pipe.
//!
//! No new wire message: re-broadcasts reuse the existing
//! `BroadcastExecutionCertificate` action. Eviction is driven by local
//! wave finalization (the only positive signal available without an
//! explicit ACK round-trip) plus the safety horizon.
//!
//! The horizon — `MAX_VALIDITY_RANGE + WAVE_TIMEOUT` — is principled,
//! not arbitrary: a tx included at the latest possible moment within
//! its `validity_range` gets `WAVE_TIMEOUT` after that to terminate, so
//! any EC unacked past that bound references a wave no shard could
//! still be processing. Same constant covers `OutboundProvisionTracker`.
//!
//! Anchored on `WeightedTimestamp` from the committing QC so every
//! validator decides identically when to re-broadcast or evict.

use hyperscale_types::{
    ExecutionCertificate, ShardGroupId, ValidatorId, WaveId, WeightedTimestamp,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Minimum gap between re-broadcasts of the same EC to the same target.
/// Cheap (ECs are small) but bounded so we don't spam the network on a
/// genuinely down peer.
pub const REBROADCAST_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Default)]
pub struct OutboundCertMemoryStats {
    pub tracked_certificates: usize,
}

/// A single tracked outbound EC for one (wave, target_shard) destination.
struct OutboundCertEntry {
    certificate: Arc<ExecutionCertificate>,
    target_shard: ShardGroupId,
    recipients: Vec<ValidatorId>,
    /// Hard deadline past which the EC is provably useless: every tx in the
    /// wave has expired and terminated. Computed via
    /// `ExecutionCertificate::deadline()` from the wave's
    /// `vote_anchor_ts` — the BFT-authenticated wave commit time.
    deadline: WeightedTimestamp,
    last_sent_at: WeightedTimestamp,
    rebroadcast_count: u32,
}

/// One re-broadcast directive emitted on a tick.
#[derive(Debug)]
pub struct RebroadcastDirective {
    pub target_shard: ShardGroupId,
    pub certificate: Arc<ExecutionCertificate>,
    pub recipients: Vec<ValidatorId>,
}

/// Sub-state machine that retains and periodically re-broadcasts ECs
/// destined for remote shards until they ACK by finalizing the wave.
pub struct OutboundExecutionCertificateTracker {
    /// (wave_id, target_shard) → entry. One EC may be tracked once per
    /// remote target shard it was sent to.
    entries: HashMap<(WaveId, ShardGroupId), OutboundCertEntry>,
    now: WeightedTimestamp,
}

impl Default for OutboundExecutionCertificateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundExecutionCertificateTracker {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            now: WeightedTimestamp::ZERO,
        }
    }

    pub fn memory_stats(&self) -> OutboundCertMemoryStats {
        OutboundCertMemoryStats {
            tracked_certificates: self.entries.len(),
        }
    }

    /// Register an EC the wave leader just broadcast to a remote shard.
    /// Idempotent on duplicate (wave, target) — preserves the original
    /// `first_sent_at` so the safety horizon counts from the first send.
    pub fn on_broadcast(
        &mut self,
        certificate: Arc<ExecutionCertificate>,
        target_shard: ShardGroupId,
        recipients: Vec<ValidatorId>,
    ) {
        if recipients.is_empty() {
            return;
        }
        let key = (certificate.wave_id.clone(), target_shard);
        if self.entries.contains_key(&key) {
            return;
        }
        debug!(
            wave = %certificate.wave_id,
            target_shard = target_shard.0,
            recipients = recipients.len(),
            "Tracking outbound execution certificate"
        );
        let deadline = certificate.deadline();
        self.entries.insert(
            key,
            OutboundCertEntry {
                certificate,
                target_shard,
                recipients,
                deadline,
                last_sent_at: self.now,
                rebroadcast_count: 0,
            },
        );
    }

    /// Drop tracking for a wave that finalized locally. Finalization
    /// requires every participating shard's EC; remote shards' ECs only
    /// arrive once those shards executed the wave, which means they
    /// observed the same wave structure we did and almost certainly
    /// received our EC contribution (or are about to). This is the
    /// best positive signal available without an explicit ACK message.
    pub fn on_wave_finalized(&mut self, wave_id: &WaveId) {
        // A wave can have multiple target_shard entries — drop them all.
        let stale: Vec<_> = self
            .entries
            .keys()
            .filter(|(w, _)| w == wave_id)
            .cloned()
            .collect();
        for key in stale {
            if let Some(entry) = self.entries.remove(&key) {
                debug!(
                    wave = %key.0,
                    target_shard = key.1.0,
                    rebroadcasts = entry.rebroadcast_count,
                    "Evicted outbound execution certificate (wave finalized)"
                );
            }
        }
    }

    /// Tick driven from `on_block_committed`. Emits re-broadcast directives
    /// for entries past `REBROADCAST_INTERVAL`, evicts entries past the
    /// safety horizon (logged at `warn!` — same severity as the symmetric
    /// outbound-provision eviction).
    pub fn on_block_committed(&mut self, now: WeightedTimestamp) -> Vec<RebroadcastDirective> {
        self.now = now;

        let mut directives = Vec::new();
        let mut to_evict = Vec::new();

        for (key, entry) in &mut self.entries {
            if now > entry.deadline {
                to_evict.push(key.clone());
                continue;
            }
            let since_last = now.elapsed_since(entry.last_sent_at);
            if since_last >= REBROADCAST_INTERVAL {
                entry.last_sent_at = now;
                entry.rebroadcast_count += 1;
                directives.push(RebroadcastDirective {
                    target_shard: entry.target_shard,
                    certificate: Arc::clone(&entry.certificate),
                    recipients: entry.recipients.clone(),
                });
            }
        }

        for key in to_evict {
            if let Some(entry) = self.entries.remove(&key) {
                warn!(
                    wave = %key.0,
                    target_shard = key.1.0,
                    rebroadcasts = entry.rebroadcast_count,
                    past_deadline_secs = now.elapsed_since(entry.deadline).as_secs(),
                    "Evicting outbound execution certificate past deadline — \
                     wave never finalized; remote shard likely missed our EC"
                );
            }
        }

        directives
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHeight, Bls12381G2Signature, GlobalReceiptRoot, Hash, SignerBitfield,
        RETENTION_HORIZON,
    };

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn wave(local: u64, h: u64, remote: &[u64]) -> WaveId {
        WaveId {
            shard_group_id: ShardGroupId(local),
            block_height: BlockHeight(h),
            remote_shards: remote.iter().copied().map(ShardGroupId).collect(),
        }
    }

    fn cert(wave_id: WaveId) -> Arc<ExecutionCertificate> {
        Arc::new(ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::from_raw(Hash::ZERO),
            Vec::new(),
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        ))
    }

    fn vids(ids: &[u64]) -> Vec<ValidatorId> {
        ids.iter().copied().map(ValidatorId).collect()
    }

    #[test]
    fn on_broadcast_registers_entry() {
        let mut t = OutboundExecutionCertificateTracker::new();
        t.on_block_committed(ts(1_000));

        let w = wave(0, 100, &[1]);
        t.on_broadcast(cert(w.clone()), ShardGroupId(1), vids(&[4, 5, 6, 7]));
        assert_eq!(t.memory_stats().tracked_certificates, 1);
    }

    #[test]
    fn on_broadcast_skips_when_no_recipients() {
        let mut t = OutboundExecutionCertificateTracker::new();
        let w = wave(0, 100, &[1]);
        t.on_broadcast(cert(w), ShardGroupId(1), vec![]);
        assert_eq!(t.memory_stats().tracked_certificates, 0);
    }

    #[test]
    fn on_broadcast_is_idempotent_per_target() {
        let mut t = OutboundExecutionCertificateTracker::new();
        let w = wave(0, 100, &[1]);
        t.on_broadcast(cert(w.clone()), ShardGroupId(1), vids(&[4]));
        t.on_broadcast(cert(w.clone()), ShardGroupId(1), vids(&[4, 5]));
        assert_eq!(t.memory_stats().tracked_certificates, 1);
    }

    #[test]
    fn rebroadcast_emitted_after_interval_elapses() {
        let mut t = OutboundExecutionCertificateTracker::new();
        t.on_block_committed(ts(0));

        let w = wave(0, 100, &[1]);
        t.on_broadcast(cert(w), ShardGroupId(1), vids(&[4]));

        // Just before interval — no directive.
        let directives = t.on_block_committed(ts(REBROADCAST_INTERVAL.as_millis() as u64 - 1));
        assert!(directives.is_empty());

        // At interval — one directive.
        let directives = t.on_block_committed(ts(REBROADCAST_INTERVAL.as_millis() as u64));
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].target_shard, ShardGroupId(1));
        assert_eq!(directives[0].recipients, vids(&[4]));
    }

    #[test]
    fn rebroadcast_paces_at_interval() {
        let mut t = OutboundExecutionCertificateTracker::new();
        t.on_block_committed(ts(0));

        let w = wave(0, 100, &[1]);
        t.on_broadcast(cert(w), ShardGroupId(1), vids(&[4]));

        let interval_ms = REBROADCAST_INTERVAL.as_millis() as u64;
        let d1 = t.on_block_committed(ts(interval_ms));
        let d2 = t.on_block_committed(ts(interval_ms + 1));
        let d3 = t.on_block_committed(ts(interval_ms * 2));
        assert_eq!(d1.len(), 1);
        assert_eq!(d2.len(), 0);
        assert_eq!(d3.len(), 1);
    }

    #[test]
    fn safety_horizon_evicts_with_warning() {
        let mut t = OutboundExecutionCertificateTracker::new();
        t.on_block_committed(ts(1_000));

        let w = wave(0, 100, &[1]);
        t.on_broadcast(cert(w), ShardGroupId(1), vids(&[4]));

        let past = RETENTION_HORIZON + Duration::from_secs(1);
        t.on_block_committed(ts(1_000 + past.as_millis() as u64));
        assert_eq!(t.memory_stats().tracked_certificates, 0);
    }

    #[test]
    fn wave_finalization_evicts_all_targets() {
        let mut t = OutboundExecutionCertificateTracker::new();
        let w = wave(0, 100, &[1, 2]);
        t.on_broadcast(cert(w.clone()), ShardGroupId(1), vids(&[4]));
        t.on_broadcast(cert(w.clone()), ShardGroupId(2), vids(&[8]));
        assert_eq!(t.memory_stats().tracked_certificates, 2);

        t.on_wave_finalized(&w);
        assert_eq!(t.memory_stats().tracked_certificates, 0);
    }

    #[test]
    fn wave_finalization_for_other_wave_is_noop() {
        let mut t = OutboundExecutionCertificateTracker::new();
        let w1 = wave(0, 100, &[1]);
        let w2 = wave(0, 101, &[1]);
        t.on_broadcast(cert(w1), ShardGroupId(1), vids(&[4]));
        t.on_wave_finalized(&w2);
        assert_eq!(t.memory_stats().tracked_certificates, 1);
    }
}
