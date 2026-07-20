//! Per-shard settled-waves acquisition.
//!
//! When a remote shard `P` terminates at a split, a surviving counterpart
//! must learn `S_P` — the wave-ids `P` settled at or before its terminal
//! block — so the split-boundary fence can resolve cross-shard
//! `FinalizedWave`s naming `P`. It owns one acquisition per
//! past-terminal shard: a single verified fetch of `P`'s complete settled
//! window list, checked against the beacon-attested `settled_waves_root`
//! the node read from its own fold.
//!
//! Sans-io like the [`Sync`](crate::sync) FSMs: methods fold an input and
//! return [`SettledWavesAcquisitionOutput`]s the I/O glue turns into
//! network requests and a `SettledWavesReconstructed` event. A correct
//! terminal committee satisfies the root check on the first fetch; a
//! `not_found` or a list that doesn't recompute to the attested root
//! rotates the peer and retries on the next tick. Each driver self-expires
//! once the node's chain advances past `terminal_wt + RETENTION_HORIZON`,
//! beyond which the fence rejects any wave naming `P` regardless.

use std::collections::{BTreeSet, HashMap};

use hyperscale_types::network::request::GetSettledWavesRequest;
use hyperscale_types::network::response::GetSettledWavesResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, RETENTION_HORIZON, SettledWavesRoot, ShardId, ValidatorId, WaveId,
    WeightedTimestamp, settled_waves_root_from_ids,
};

/// One in-flight acquisition of a terminated shard's settled set.
struct AcquisitionDriver {
    /// Height of `P`'s terminal block — names the window end the serve
    /// reconstructs from.
    terminal_height: BlockHeight,
    /// `P`'s terminal block hash — identifies which terminal this driver
    /// targets, so a duplicate start for the same terminal is a no-op.
    terminal_block_hash: BlockHash,
    /// `P`'s terminal weighted timestamp — carried into the completion
    /// event to bound the fence's retention cutoff, and the driver's
    /// self-expiry.
    terminal_wt: WeightedTimestamp,
    /// The beacon-attested root the fetched list must recompute to.
    attested_root: SettledWavesRoot,
    /// `P`'s terminal committee, asked in rotation. Empty falls back to
    /// shard-routed peer selection.
    peers: Vec<ValidatorId>,
    /// Rotates through `peers` on each `not_found` / mismatch / failure.
    cursor: usize,
    /// Whether a fetch is outstanding — withholds duplicate fetches.
    in_flight: bool,
}

impl AcquisitionDriver {
    const fn request(&self) -> GetSettledWavesRequest {
        GetSettledWavesRequest::new(self.terminal_height, self.terminal_block_hash)
    }

    fn peer(&self) -> Option<ValidatorId> {
        if self.peers.is_empty() {
            None
        } else {
            Some(self.peers[self.cursor % self.peers.len()])
        }
    }
}

/// What the I/O glue should do after folding an input into [`SettledWavesAcquisition`].
pub enum SettledWavesAcquisitionOutput {
    /// Issue the window fetch against `shard`'s terminal committee, biased
    /// to `peer`.
    Fetch {
        /// The terminated shard being acquired.
        shard: ShardId,
        /// Preferred terminal-committee member, or `None` to route by
        /// shard alone.
        peer: Option<ValidatorId>,
        /// The window list request.
        request: GetSettledWavesRequest,
    },
    /// The fetched list verified against the attested root — `S_P` is
    /// complete.
    Complete {
        /// The terminated shard whose settled set this is.
        shard: ShardId,
        /// Wave-ids `shard` settled at or before its terminal block.
        waves: BTreeSet<WaveId>,
        /// `shard`'s terminal weighted timestamp.
        terminal_wt: WeightedTimestamp,
    },
}

/// Drives one settled-waves acquisition per past-terminal shard. One per
/// [`ShardIo`](crate::shard::ShardIo); shared across the shard's vnodes, so a
/// duplicate start for an already-targeted terminal is deduplicated.
#[derive(Default)]
pub struct SettledWavesAcquisition {
    drivers: HashMap<ShardId, AcquisitionDriver>,
}

impl SettledWavesAcquisition {
    /// An empty acquisition set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            drivers: HashMap::new(),
        }
    }

    /// True while any acquisition is unfinished — keeps the shard's
    /// `FetchTick` alive so parked acquisitions retry and expired ones
    /// drop.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.drivers.is_empty()
    }

    /// Begin (or retry) acquiring `shard`'s settled set. A start for a
    /// terminal already in flight is a no-op; one for a parked driver
    /// re-issues the fetch against the next peer; one naming a different
    /// terminal block replaces the running driver.
    pub fn start(
        &mut self,
        shard: ShardId,
        terminal_height: BlockHeight,
        terminal_block_hash: BlockHash,
        terminal_wt: WeightedTimestamp,
        attested_root: SettledWavesRoot,
        peers: Vec<ValidatorId>,
    ) -> Vec<SettledWavesAcquisitionOutput> {
        if let Some(driver) = self.drivers.get_mut(&shard)
            && driver.terminal_block_hash == terminal_block_hash
        {
            if driver.in_flight {
                return vec![];
            }
            driver.in_flight = true;
            return vec![SettledWavesAcquisitionOutput::Fetch {
                shard,
                peer: driver.peer(),
                request: driver.request(),
            }];
        }
        let driver = AcquisitionDriver {
            terminal_height,
            terminal_block_hash,
            terminal_wt,
            attested_root,
            peers,
            cursor: 0,
            in_flight: true,
        };
        let out = SettledWavesAcquisitionOutput::Fetch {
            shard,
            peer: driver.peer(),
            request: driver.request(),
        };
        self.drivers.insert(shard, driver);
        vec![out]
    }

    /// Fold a window response into `shard`'s acquisition. A list that
    /// recomputes to the attested root completes; `not_found` or a
    /// mismatch rotates the peer and parks for the next tick.
    pub fn on_response(
        &mut self,
        shard: ShardId,
        response: &GetSettledWavesResponse,
    ) -> Vec<SettledWavesAcquisitionOutput> {
        let Some(driver) = self.drivers.get_mut(&shard) else {
            return vec![];
        };
        driver.in_flight = false;
        let Some(waves) = &response.waves else {
            driver.cursor = driver.cursor.wrapping_add(1);
            return vec![];
        };
        if settled_waves_root_from_ids(waves.iter()) != driver.attested_root {
            driver.cursor = driver.cursor.wrapping_add(1);
            return vec![];
        }
        let set: BTreeSet<WaveId> = waves.iter().cloned().collect();
        let driver = self
            .drivers
            .remove(&shard)
            .expect("just matched as present");
        vec![SettledWavesAcquisitionOutput::Complete {
            shard,
            waves: set,
            terminal_wt: driver.terminal_wt,
        }]
    }

    /// A transport-level failure of the outstanding fetch. Re-arms the
    /// driver and rotates the peer; the next tick re-issues.
    pub fn on_failure(&mut self, shard: ShardId) {
        if let Some(driver) = self.drivers.get_mut(&shard) {
            driver.in_flight = false;
            driver.cursor = driver.cursor.wrapping_add(1);
        }
    }

    /// Drop acquisitions whose retention window has passed (the fence
    /// rejects naming the shard regardless), then re-issue every parked
    /// acquisition's fetch. `now_wt` is the node's current chain weighted
    /// timestamp, or `None` before the first commit.
    pub fn on_tick(
        &mut self,
        now_wt: Option<WeightedTimestamp>,
    ) -> Vec<SettledWavesAcquisitionOutput> {
        if let Some(now) = now_wt {
            self.drivers
                .retain(|_, d| now <= d.terminal_wt.plus(RETENTION_HORIZON));
        }
        let mut outputs = Vec::new();
        for (&shard, driver) in &mut self.drivers {
            if !driver.in_flight {
                driver.in_flight = true;
                outputs.push(SettledWavesAcquisitionOutput::Fetch {
                    shard,
                    peer: driver.peer(),
                    request: driver.request(),
                });
            }
        }
        outputs
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_storage::test_helpers::make_test_certified;
    use hyperscale_storage::{PendingChain, ShardChainWriter};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHash,
        BlockHeader, Bls12381G2Signature, BoundedVec, CertificateRoot, ExecutionCertificate,
        ExecutionOutcome, FinalizedWave, GlobalReceiptHash, GlobalReceiptRoot, Hash, InFlightCount,
        LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, QuorumCertificate, Round, ShardId,
        SignerBitfield, StateRoot, TransactionRoot, TxHash, TxOutcome, ValidatorId, Verifiable,
        Verified, VrfProof, WaveCertificate, WaveId, WeightedTimestamp,
        settled_waves_root_from_ids,
    };

    use super::*;
    use crate::shard::cross_shard::settled_waves_serve::serve_settled_waves_request;

    const SHARD: ShardId = ShardId::ROOT;

    fn finalized_wave(height: u64) -> Arc<Verifiable<FinalizedWave>> {
        let wave = local_wave(height);
        let ec = ExecutionCertificate::new(
            wave.clone(),
            WeightedTimestamp::from_millis(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                TxHash::from_raw(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            )],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        Arc::new(Verifiable::from(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave, vec![Arc::new(ec)])),
            vec![],
        )))
    }

    /// Commit `count` blocks (1..=count), each carrying its own settled
    /// wave, and return the storage, the terminal hash, and the attested
    /// settled-waves root over the whole window.
    fn served_chain(count: u64) -> (Arc<SimShardStorage>, BlockHash, SettledWavesRoot) {
        let storage = Arc::new(SimShardStorage::default());
        let mut parent = BlockHash::ZERO;
        let mut terminal = BlockHash::ZERO;
        for h in 1..=count {
            let certs = [finalized_wave(h)];
            let parent_qc = QuorumCertificate::new(
                parent,
                SHARD,
                BlockHeight::new(h.saturating_sub(1)),
                BlockHash::ZERO,
                Round::INITIAL,
                SignerBitfield::new(4),
                Bls12381G2Signature([0u8; 96]),
                WeightedTimestamp::from_millis(1_000 * h),
            );
            let header = BlockHeader::new(
                SHARD,
                BlockHeight::new(h),
                parent,
                parent_qc,
                ValidatorId::new(0),
                ProposerTimestamp::from_millis(1_000 * h),
                Round::INITIAL,
                false,
                StateRoot::ZERO,
                TransactionRoot::ZERO,
                *Verified::<CertificateRoot>::compute(&certs).as_ref(),
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                std::collections::BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            );
            let block = Block::Live {
                header,
                transactions: Arc::new(BoundedVec::new()),
                certificates: Arc::new(certs.to_vec().into()),
                provisions: Arc::new(BoundedVec::new()),
                ready_signals: Arc::new(BoundedVec::new()),
                equivocations: Arc::new(BoundedVec::new()),
                reshape_trigger: None,
                randomness_reveal: VrfProof::ZERO,
            };
            parent = block.hash();
            terminal = block.hash();
            storage.commit_block(
                &make_test_certified(block),
                &BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO),
            );
        }
        let root =
            settled_waves_root_from_ids((1..=count).map(local_wave).collect::<Vec<_>>().iter());
        (storage, terminal, root)
    }

    /// A cross-shard wave (non-empty `remote_shards`): the settled set
    /// commits only cross-shard waves, so a single-shard fixture would be
    /// filtered out before the merkle root.
    fn local_wave(height: u64) -> WaveId {
        WaveId::new(
            SHARD,
            BlockHeight::new(height),
            BTreeSet::from([ShardId::from_heap_index(2)]),
        )
    }

    /// One verified fetch against a served chain completes with the whole
    /// window list, and the driver drops.
    #[test]
    fn acquires_against_a_served_chain() {
        let (storage, terminal, root) = served_chain(3);
        let pending_chain = PendingChain::new(storage);

        let mut host = SettledWavesAcquisition::new();
        let mut outputs = host.start(
            SHARD,
            BlockHeight::new(3),
            terminal,
            WeightedTimestamp::from_millis(9_000),
            root,
            vec![ValidatorId::new(7)],
        );

        let mut completed = None;
        while let Some(output) = outputs.pop() {
            match output {
                SettledWavesAcquisitionOutput::Fetch { shard, request, .. } => {
                    assert_eq!(shard, SHARD);
                    let response = serve_settled_waves_request(&pending_chain, None, &request);
                    outputs.extend(host.on_response(SHARD, &response));
                }
                SettledWavesAcquisitionOutput::Complete {
                    shard,
                    waves,
                    terminal_wt,
                } => {
                    assert_eq!(shard, SHARD);
                    assert_eq!(terminal_wt, WeightedTimestamp::from_millis(9_000));
                    completed = Some(waves);
                }
            }
        }

        assert_eq!(
            completed.expect("acquisition completes"),
            BTreeSet::from([local_wave(1), local_wave(2), local_wave(3)]),
        );
        assert!(!host.has_pending(), "the driver drops on completion");
    }

    /// A list that doesn't recompute to the attested root is rejected: the
    /// peer rotates and the acquisition parks rather than recording a
    /// forged set.
    #[test]
    fn root_mismatch_parks_and_rotates() {
        let (storage, terminal, _) = served_chain(3);
        let pending_chain = PendingChain::new(storage);

        let mut host = SettledWavesAcquisition::new();
        // Attest a root the served chain cannot satisfy.
        let wrong_root = settled_waves_root_from_ids([&local_wave(99)]);
        let _ = host.start(
            SHARD,
            BlockHeight::new(3),
            terminal,
            WeightedTimestamp::from_millis(9_000),
            wrong_root,
            vec![ValidatorId::new(0), ValidatorId::new(1)],
        );
        let request = GetSettledWavesRequest::new(BlockHeight::new(3), terminal);
        let response = serve_settled_waves_request(&pending_chain, None, &request);
        let parked = host.on_response(SHARD, &response);
        assert!(parked.is_empty(), "a mismatch parks rather than completes");
        assert!(host.has_pending());

        // The tick re-arms the fetch against the rotated peer.
        let ticked = host.on_tick(Some(WeightedTimestamp::from_millis(9_100)));
        assert!(matches!(
            ticked.as_slice(),
            [SettledWavesAcquisitionOutput::Fetch { .. }]
        ));
    }

    /// A driver whose retention window has passed drops on tick.
    #[test]
    fn expires_past_the_retention_horizon() {
        let mut host = SettledWavesAcquisition::new();
        let _ = host.start(
            SHARD,
            BlockHeight::new(2),
            BlockHash::ZERO,
            WeightedTimestamp::from_millis(1_000),
            settled_waves_root_from_ids(std::iter::empty()),
            vec![],
        );
        assert!(host.has_pending());

        let past = WeightedTimestamp::from_millis(1_000)
            .plus(RETENTION_HORIZON)
            .plus(RETENTION_HORIZON);
        let outputs = host.on_tick(Some(past));
        assert!(outputs.is_empty());
        assert!(!host.has_pending(), "the expired driver drops");
    }

    /// A duplicate start for the same terminal while a fetch is in flight
    /// is a no-op; a start for a different terminal replaces the driver.
    #[test]
    fn dedupes_by_terminal_block() {
        let mut host = SettledWavesAcquisition::new();
        let root = settled_waves_root_from_ids(std::iter::empty());
        let _ = host.start(
            SHARD,
            BlockHeight::new(2),
            BlockHash::from_raw(Hash::from_bytes(b"terminal-a")),
            WeightedTimestamp::from_millis(1),
            root,
            vec![],
        );
        let dup = host.start(
            SHARD,
            BlockHeight::new(2),
            BlockHash::from_raw(Hash::from_bytes(b"terminal-a")),
            WeightedTimestamp::from_millis(1),
            root,
            vec![],
        );
        assert!(dup.is_empty(), "same terminal in flight does not re-fetch");

        let replaced = host.start(
            SHARD,
            BlockHeight::new(3),
            BlockHash::from_raw(Hash::from_bytes(b"terminal-b")),
            WeightedTimestamp::from_millis(1),
            root,
            vec![],
        );
        assert!(
            matches!(
                replaced.as_slice(),
                [SettledWavesAcquisitionOutput::Fetch { request, .. }]
                    if request.terminal_height == BlockHeight::new(3)
            ),
            "a revised terminal restarts the acquisition from the new block",
        );
    }
}
