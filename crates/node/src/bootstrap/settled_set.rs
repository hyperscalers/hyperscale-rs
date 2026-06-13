//! Sans-io builder for a terminated shard's settled-wave set.
//!
//! After shard P terminates at a split (its chain stops at the terminal
//! block B), a surviving counterpart must decide, for any cross-shard
//! wave still naming P, whether P actually settled that wave by B. The
//! answer is `S_P` — the set of P-wave-ids whose wave certificate
//! committed in P's chain at or before B.
//!
//! This builder reconstructs `S_P` verifiably by walking P's tail chain
//! backward from B: each block's [`SettledWavesReveal`] carries the
//! wave-ids of every certificate the block committed, and the builder
//!
//! 1. binds the served header to the chain — its hash must equal the
//!    hash the previous step expected (B's beacon-attested hash to
//!    start, then each accepted block's `parent_block_hash`);
//! 2. recomputes the header's `certificate_root` from the revealed
//!    wave-ids and rejects a mismatch — so the server can neither hide a
//!    settled wave (a missing leaf changes the root) nor fabricate one;
//! 3. reads each certificate's own settled wave off the verified
//!    pairs — the entry whose shard is P (the wave's `WaveId::shard_id`).
//!
//! Sans-io like [`ObserverTail`](super::observer::ObserverTail): the
//! driver owns transport, peer rotation, and — the one piece of trust
//! this core leaves out — verifying each served QC's signature against
//! P's committee. The builder checks QC-to-header linkage but not the
//! signature; a structurally complete `S_P` over QCs the driver has
//! verified is sound and complete.

use std::collections::BTreeSet;

use hyperscale_types::network::request::GetSettledWavesRequest;
use hyperscale_types::network::response::GetSettledWavesResponse;
use hyperscale_types::{
    BlockHash, BlockHeight, ShardId, WaveId, certificate_root_from_receipt_hashes,
    wave_receipt_hash,
};

/// Outcome of feeding one settled-waves response to [`SettledSetBuilder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettledOutcome {
    /// The block was verified and folded into the set; the builder
    /// advanced toward the start height.
    Accepted,
    /// The peer doesn't hold the requested height — rotate and retry.
    NotYetAvailable,
    /// The response is invalid for this walk; the driver rotates peers.
    Rejected(&'static str),
}

/// Reconstructs a terminated shard's settled-wave set by a verified
/// backward walk of its tail chain.
pub struct SettledSetBuilder {
    /// The terminated shard P whose settled set this builds.
    shard: ShardId,
    /// Oldest block to include (inclusive). The walk stops here.
    start_height: BlockHeight,
    /// Next height to fetch — descends from the terminal toward
    /// `start_height`.
    next: BlockHeight,
    /// Expected hash of `next`'s block: B's attested hash to begin, then
    /// each accepted block's `parent_block_hash`.
    expected_hash: BlockHash,
    in_flight: bool,
    settled: BTreeSet<WaveId>,
    done: bool,
}

impl SettledSetBuilder {
    /// Build `shard`'s settled set over `[start_height, terminal_height]`,
    /// anchoring the walk at the beacon-attested terminal
    /// `(terminal_height, terminal_block_hash)`.
    #[must_use]
    pub const fn new(
        shard: ShardId,
        terminal_height: BlockHeight,
        terminal_block_hash: BlockHash,
        start_height: BlockHeight,
    ) -> Self {
        Self {
            shard,
            start_height,
            next: terminal_height,
            expected_hash: terminal_block_hash,
            in_flight: false,
            settled: BTreeSet::new(),
            done: false,
        }
    }

    /// The next block fetch, when none is outstanding and the walk hasn't
    /// reached the start height.
    pub const fn next_request(&mut self) -> Option<GetSettledWavesRequest> {
        if self.done || self.in_flight {
            return None;
        }
        self.in_flight = true;
        Some(GetSettledWavesRequest::new(self.next, self.expected_hash))
    }

    /// Re-arm the outstanding fetch after a transport-level failure.
    pub const fn on_failure(&mut self) {
        self.in_flight = false;
    }

    /// Feed the response for the outstanding fetch.
    ///
    /// # Panics
    ///
    /// Panics only on an internal invariant breach — `next` would
    /// descend below `start_height` (the walk stops at `start_height`,
    /// which is at or above `GENESIS`, so `prev` always exists here).
    #[allow(clippy::too_many_lines)] // one linear verification of a single reveal
    pub fn on_response(&mut self, response: &GetSettledWavesResponse) -> SettledOutcome {
        if !self.in_flight {
            return SettledOutcome::Rejected("unsolicited settled-waves response");
        }
        self.in_flight = false;

        let Some(reveal) = &response.reveal else {
            return SettledOutcome::NotYetAvailable;
        };
        let header = reveal.certified_header.header();

        if header.shard_id() != self.shard {
            return SettledOutcome::Rejected("reveal is for a different shard");
        }
        if header.height() != self.next {
            return SettledOutcome::Rejected("reveal height does not match the requested height");
        }
        if reveal.certified_header.block_hash() != self.expected_hash {
            return SettledOutcome::Rejected("reveal does not extend the attested terminal chain");
        }
        // Bind the (driver-verified) QC to the header it certifies.
        if reveal.certified_header.qc().block_hash() != reveal.certified_header.block_hash() {
            return SettledOutcome::Rejected("qc does not commit the served header");
        }

        // Recompute the certificate root from the revealed pairs. A
        // hidden or fabricated certificate changes a leaf and fails here.
        let receipt_hashes: Vec<_> = reveal
            .certs
            .iter()
            .map(|cert| wave_receipt_hash(cert.iter()))
            .collect();
        if certificate_root_from_receipt_hashes(&receipt_hashes) != header.certificate_root() {
            return SettledOutcome::Rejected("revealed certificates do not match certificate_root");
        }

        // Each certificate's settled wave is its local EC — the unique
        // pair whose shard is P. Other pairs are remote shards' ECs.
        for cert in reveal.certs.iter() {
            let mut local = cert.iter().filter(|w| w.shard_id() == self.shard);
            let Some(wave) = local.next() else {
                return SettledOutcome::Rejected("certificate carries no local execution cert");
            };
            if local.next().is_some() {
                return SettledOutcome::Rejected(
                    "certificate carries multiple local execution certs",
                );
            }
            self.settled.insert(wave.clone());
        }

        self.expected_hash = header.parent_block_hash();
        if self.next == self.start_height {
            self.done = true;
        } else {
            self.next = self
                .next
                .prev()
                .expect("next > start_height ≥ GENESIS, so prev exists");
        }
        SettledOutcome::Accepted
    }

    /// Whether the walk reached the start height.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.done
    }

    /// The settled-wave set assembled so far — complete once
    /// [`Self::is_complete`].
    #[must_use]
    pub const fn settled(&self) -> &BTreeSet<WaveId> {
        &self.settled
    }

    /// Consume the builder and return the settled-wave set.
    #[must_use]
    pub fn into_settled(self) -> BTreeSet<WaveId> {
        self.settled
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use hyperscale_types::network::response::{GetSettledWavesResponse, SettledWavesReveal};
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, BlockHash, BlockHeader, BlockHeight,
        Bls12381G2Signature, CertificateRoot, CertifiedBlockHeader, ChainOrigin,
        ExecutionCertificate, ExecutionOutcome, FinalizedWave, GlobalReceiptHash,
        GlobalReceiptRoot, Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, QuorumCertificate, Round, ShardId, SignerBitfield, StateRoot,
        TransactionRoot, TxHash, TxOutcome, ValidatorId, Verifiable, Verified, WaveCertificate,
        WaveId, WeightedTimestamp,
    };

    use super::*;

    const SHARD: ShardId = ShardId::ROOT;

    /// A wave certificate whose local EC is on `SHARD`, plus an optional
    /// remote EC on another shard — the realistic cross-shard shape.
    fn finalized_wave(height: u64, remote: Option<ShardId>) -> Arc<Verifiable<FinalizedWave>> {
        let local_wave = WaveId::new(SHARD, BlockHeight::new(height), BTreeSet::new());
        let mut ecs = vec![Arc::new(ec(local_wave.clone()))];
        if let Some(remote) = remote {
            let remote_wave = WaveId::new(remote, BlockHeight::new(height), BTreeSet::new());
            ecs.push(Arc::new(ec(remote_wave)));
        }
        let wc = WaveCertificate::new(local_wave, ecs);
        Arc::new(Verifiable::from(FinalizedWave::new(Arc::new(wc), vec![])))
    }

    fn ec(wave_id: WaveId) -> ExecutionCertificate {
        ExecutionCertificate::new(
            wave_id,
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
        )
    }

    /// A header at `height` extending `parent`, carrying the certificate
    /// root computed from `certs`.
    fn header(
        height: u64,
        parent: BlockHash,
        certs: &[Arc<Verifiable<FinalizedWave>>],
    ) -> BlockHeader {
        BlockHeader::new(
            SHARD,
            BlockHeight::new(height),
            parent,
            QuorumCertificate::genesis(SHARD, ChainOrigin::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(1_000 * height),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            *Verified::<CertificateRoot>::compute(certs).as_ref(),
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
        )
    }

    /// Build a reveal for `header` exposing `certs` (each as its EC
    /// wave-ids), with a QC whose `block_hash` matches the header.
    fn reveal(header: BlockHeader, certs: &[Arc<Verifiable<FinalizedWave>>]) -> SettledWavesReveal {
        let block_hash = header.hash();
        let cert_lists: Vec<_> = certs
            .iter()
            .map(|fw| fw.certificate().ec_wave_ids().into())
            .collect();
        let base = QuorumCertificate::genesis(SHARD, ChainOrigin::ROOT);
        let qc = QuorumCertificate::new(
            block_hash,
            base.shard_id(),
            base.height(),
            base.parent_block_hash(),
            base.round(),
            base.signers().clone(),
            base.aggregated_signature(),
            WeightedTimestamp::ZERO,
        );
        SettledWavesReveal {
            certified_header: CertifiedBlockHeader::new(header, Verifiable::from(qc)),
            certs: cert_lists.into(),
        }
    }

    fn local_wave(height: u64) -> WaveId {
        WaveId::new(SHARD, BlockHeight::new(height), BTreeSet::new())
    }

    /// A two-block chain B-1 ← B reconstructs to both blocks' local
    /// waves, picking the local EC out of a cross-shard certificate.
    #[test]
    fn reconstructs_settled_set() {
        let remote = ShardId::leaf(1, 1);
        let certs_a = [finalized_wave(1, Some(remote))];
        let head_a = header(1, BlockHash::ZERO, &certs_a);
        let certs_b = [finalized_wave(2, Some(remote))];
        let head_b = header(2, head_a.hash(), &certs_b);
        let terminal = head_b.hash();

        let mut builder =
            SettledSetBuilder::new(SHARD, BlockHeight::new(2), terminal, BlockHeight::new(1));

        assert_eq!(builder.next_request().unwrap().height, BlockHeight::new(2));
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::found(reveal(head_b, &certs_b))),
            SettledOutcome::Accepted,
        );
        assert!(!builder.is_complete());
        assert_eq!(builder.next_request().unwrap().height, BlockHeight::new(1));
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::found(reveal(head_a, &certs_a))),
            SettledOutcome::Accepted,
        );
        assert!(builder.is_complete());
        assert!(builder.next_request().is_none());

        let settled = builder.into_settled();
        assert_eq!(
            settled,
            BTreeSet::from([local_wave(1), local_wave(2)]),
            "only the local-shard waves settle; the remote EC pair is not a settled P-wave",
        );
    }

    /// Hiding a committed certificate changes the recomputed root.
    #[test]
    fn rejects_hidden_certificate() {
        let certs = [finalized_wave(1, None), finalized_wave(2, None)];
        let head = header(5, BlockHash::ZERO, &certs);
        let mut builder =
            SettledSetBuilder::new(SHARD, BlockHeight::new(5), head.hash(), BlockHeight::new(5));
        builder.next_request();
        // Serve only the first certificate.
        let hidden = [certs[0].clone()];
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::found(reveal(head, &hidden))),
            SettledOutcome::Rejected("revealed certificates do not match certificate_root"),
        );
    }

    /// Fabricating an extra certificate changes the recomputed root.
    #[test]
    fn rejects_fabricated_certificate() {
        let certs = [finalized_wave(1, None)];
        let head = header(5, BlockHash::ZERO, &certs);
        let mut builder =
            SettledSetBuilder::new(SHARD, BlockHeight::new(5), head.hash(), BlockHeight::new(5));
        builder.next_request();
        let padded = [certs[0].clone(), finalized_wave(2, None)];
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::found(reveal(head, &padded))),
            SettledOutcome::Rejected("revealed certificates do not match certificate_root"),
        );
    }

    /// A block whose hash doesn't match the expected chain link rejects.
    #[test]
    fn rejects_chain_break() {
        let certs = [finalized_wave(1, None)];
        let head = header(5, BlockHash::ZERO, &certs);
        let mut builder = SettledSetBuilder::new(
            SHARD,
            BlockHeight::new(5),
            BlockHash::from_raw(Hash::from_bytes(b"not-the-terminal")),
            BlockHeight::new(5),
        );
        builder.next_request();
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::found(reveal(head, &certs))),
            SettledOutcome::Rejected("reveal does not extend the attested terminal chain"),
        );
    }

    /// A missing height re-arms for a peer rotation.
    #[test]
    fn missing_height_is_not_yet_available() {
        let mut builder = SettledSetBuilder::new(
            SHARD,
            BlockHeight::new(5),
            BlockHash::ZERO,
            BlockHeight::new(5),
        );
        builder.next_request();
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::not_found()),
            SettledOutcome::NotYetAvailable,
        );
        // Re-arms the same height.
        assert_eq!(builder.next_request().unwrap().height, BlockHeight::new(5));
    }

    /// A block with no committed certificates contributes nothing and
    /// verifies against the zero certificate root.
    #[test]
    fn empty_block_contributes_nothing() {
        let certs: [Arc<Verifiable<FinalizedWave>>; 0] = [];
        let head = header(5, BlockHash::ZERO, &certs);
        let mut builder =
            SettledSetBuilder::new(SHARD, BlockHeight::new(5), head.hash(), BlockHeight::new(5));
        builder.next_request();
        assert_eq!(
            builder.on_response(&GetSettledWavesResponse::found(reveal(head, &certs))),
            SettledOutcome::Accepted,
        );
        assert!(builder.is_complete());
        assert!(builder.into_settled().is_empty());
    }
}
