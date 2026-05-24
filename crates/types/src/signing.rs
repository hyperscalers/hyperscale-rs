//! Domain-separated signing for cryptographic operations.
//!
//! This module provides type-safe domain separation tags for all signed messages
//! in the consensus protocol. Domain separation prevents cross-protocol attacks
//! where a signature from one context could be replayed in another.
//!
//! # Domain Tags
//!
//! Each signable message type has a unique domain tag prefix:
//!
//! | Tag | Purpose |
//! |-----|---------|
//! | `BLOCK_VOTE` | shard consensus block votes |
//! | `EXEC_VOTE` | Execution votes |
//! | `COMMITTED_BLOCK_HEADER` | Committed block header gossip |
//! | `BLOCK_HEADER` | Block header proposal gossip |
//! | `VALIDATOR_BIND` | Validator-bind `PeerId` authentication |
//!
//! # Usage
//!
//! Each signable type pairs with a free `signing_message()` function that
//! constructs the bytes to sign by prepending its domain tag to the
//! serialized content.

use blake3::Hasher;

use crate::{
    BlockHash, BlockHeight, ExecutionCertificate, ExecutionVote, GlobalReceiptRoot,
    NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcVector, Provisions, Round, ShardGroupId, Slot,
    SpcView, ValidatorId, WaveId, WeightedTimestamp,
};

/// Domain tag for shard consensus block votes.
///
/// Format: `BLOCK_VOTE` || `network.id` || `shard_group_id` || height || round
/// || `block_hash`
pub const DOMAIN_BLOCK_VOTE: &[u8] = b"BLOCK_VOTE";

/// Domain tag for committed block header gossip.
///
/// Format: `COMMITTED_BLOCK_HEADER` || `network.id` || `shard_group_id` ||
/// height || `block_hash`
///
/// Signed by the sender (proposer) when broadcasting committed block headers
/// globally. Verified by `IoLoop` before admitting to the state machine.
pub const DOMAIN_COMMITTED_BLOCK_HEADER: &[u8] = b"COMMITTED_BLOCK_HEADER";

/// Build the signing message for a block vote.
///
/// This is used for:
/// - Individual block vote signatures
/// - QC aggregated signature verification
/// - View change `highest_qc` verification
#[must_use]
pub fn block_vote_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    height: BlockHeight,
    round: Round,
    block_hash: &BlockHash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(81);
    message.extend_from_slice(DOMAIN_BLOCK_VOTE);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Build the signing message for a committed block header gossip.
///
/// This is used for verifying the sender's signature on globally broadcast
/// committed block headers before admitting them to the state machine.
#[must_use]
pub fn committed_block_header_message(
    network: &NetworkDefinition,
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    block_hash: &BlockHash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(DOMAIN_COMMITTED_BLOCK_HEADER);
    message.push(network.id);
    message.extend_from_slice(&shard_group_id.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Domain tag for block header proposal gossip.
///
/// Format: `BLOCK_HEADER` || `network.id` || `shard_group_id` || height ||
/// round || `block_hash`
///
/// Signed by the proposer when broadcasting block header proposals.
/// Verified by receivers before admitting the proposal into shard consensus.
/// Distinct from `DOMAIN_BLOCK_VOTE` to prevent cross-protocol replay.
pub const DOMAIN_BLOCK_HEADER: &[u8] = b"BLOCK_HEADER";

/// Build the signing message for a block header proposal.
///
/// This is used for:
/// - Proposer signature on `BlockHeaderNotification` (authenticated proposals)
/// - Verification before admitting proposals to the shard consensus state machine
#[must_use]
pub fn block_header_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    height: BlockHeight,
    round: Round,
    block_hash: &BlockHash,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(81);
    message.extend_from_slice(DOMAIN_BLOCK_HEADER);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message
}

/// Domain tag for state provisions gossip.
///
/// Format: `STATE_PROVISION_BATCH` || `network.id` || `source_shard` ||
/// `target_shard` || `block_height` || `H(tx_hashes)`
///
/// Signed by the sender when broadcasting cross-shard state provisions.
/// Verified by receivers to reject unauthenticated provision spam before
/// doing expensive merkle proof verification.
pub const DOMAIN_STATE_PROVISION_BATCH: &[u8] = b"STATE_PROVISION_BATCH";

/// Build the signing message for a state provisions gossip.
///
/// The message covers source shard, target shard, block height, and a
/// digest of the transaction hashes in the bundle. Cheap to reconstruct at
/// verification while binding the signature to the specific bundle contents.
#[must_use]
pub fn state_provisions_message(network: &NetworkDefinition, provisions: &Provisions) -> Vec<u8> {
    let mut hasher = Hasher::new();
    for tx in provisions.transactions().iter() {
        hasher.update(tx.tx_hash.as_bytes());
    }
    let tx_digest = hasher.finalize();

    let mut message = Vec::with_capacity(97);
    message.extend_from_slice(DOMAIN_STATE_PROVISION_BATCH);
    message.push(network.id);
    message.extend_from_slice(&provisions.source_shard().to_le_bytes());
    message.extend_from_slice(&provisions.target_shard().to_le_bytes());
    message.extend_from_slice(&provisions.block_height().to_le_bytes());
    message.extend_from_slice(tx_digest.as_bytes());
    message
}

/// Domain tag for validator-bind protocol.
///
/// Format: `VALIDATOR_BIND` || `network.id` || `peer_id_bytes` || `nonce`
/// (32 bytes)
///
/// Signed by a validator's BLS key to cryptographically bind their
/// consensus identity (`ValidatorId`) to their ephemeral libp2p `PeerId`.
/// Verified by peers using the BLS public key from the topology.
///
/// The nonce is supplied by the *verifier* in a challenge-response exchange,
/// so the signature is fresh per session and cannot be replayed against the
/// same `(validator_id, peer_id)` pair across different sessions.
pub const DOMAIN_VALIDATOR_BIND: &[u8] = b"VALIDATOR_BIND";

/// Length of the bind-protocol nonce, in bytes.
pub const VALIDATOR_BIND_NONCE_LEN: usize = 32;

/// Build the signing message for the validator-bind protocol.
///
/// Binds a validator's BLS identity to their ephemeral libp2p `PeerId` over a
/// per-session `nonce` chosen by the verifier. The Noise handshake proves
/// `PeerId` ownership; this signature proves the BLS key holder authorised
/// that `PeerId` *for this specific session*.
#[must_use]
pub fn validator_bind_message(
    network: &NetworkDefinition,
    peer_id_bytes: &[u8],
    nonce: &[u8; VALIDATOR_BIND_NONCE_LEN],
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DOMAIN_VALIDATOR_BIND.len() + 1 + peer_id_bytes.len() + nonce.len());
    message.extend_from_slice(DOMAIN_VALIDATOR_BIND);
    message.push(network.id);
    message.extend_from_slice(peer_id_bytes);
    message.extend_from_slice(nonce);
    message
}

/// Domain tag for execution votes.
///
/// Format: `EXEC_VOTE` || `network.id` || `vote_anchor_ts` || `wave_id_shard`
/// || `wave_id_height` || `wave_id_remote_shards_len` ||
/// `wave_id_remote_shards`... || `shard_group` || `global_receipt_root` ||
/// `tx_count`
///
/// Used for both individual `ExecutionVote` signatures and
/// `ExecutionCertificate` aggregated signature verification.
pub const DOMAIN_EXEC_VOTE: &[u8] = b"EXEC_VOTE";

/// Domain tag for execution vote batch gossip.
///
/// Format: `EXEC_VOTE_BATCH` || `network.id` || `shard_group_id` ||
/// `H(global_receipt_roots)`
pub const DOMAIN_EXEC_VOTE_BATCH: &[u8] = b"EXEC_VOTE_BATCH";

/// Domain tag for execution certificate batch gossip.
///
/// Format: `EXEC_CERT_BATCH` || `network.id` || `shard_group_id` ||
/// `H(global_receipt_roots)`
pub const DOMAIN_EXEC_CERT_BATCH: &[u8] = b"EXEC_CERT_BATCH";

/// Build the signing message for an execution vote.
///
/// This is used for:
/// - Individual `ExecutionVote` signatures
/// - `ExecutionCertificate` aggregated signature verification
///
/// The `wave_id` is serialized as length-prefixed sorted shard IDs, making
/// the message deterministic regardless of construction order.
#[must_use]
pub fn exec_vote_message(
    network: &NetworkDefinition,
    vote_anchor_ts: WeightedTimestamp,
    wave_id: &WaveId,
    shard_group: ShardGroupId,
    global_receipt_root: &GlobalReceiptRoot,
    tx_count: u32,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(129);
    message.extend_from_slice(DOMAIN_EXEC_VOTE);
    message.push(network.id);
    message.extend_from_slice(&vote_anchor_ts.as_millis().to_le_bytes());
    // WaveId is self-contained (shard + block_height + remote_shards),
    // so no separate block_hash needed in the signing message.
    message.extend_from_slice(&wave_id.shard_group_id().to_le_bytes());
    message.extend_from_slice(&wave_id.block_height().to_le_bytes());
    message.extend_from_slice(
        &u32::try_from(wave_id.remote_shards().len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for shard in wave_id.remote_shards().iter() {
        message.extend_from_slice(&shard.to_le_bytes());
    }
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(global_receipt_root.as_raw().as_bytes());
    message.extend_from_slice(&tx_count.to_le_bytes());
    message
}

/// Build the signing message for an execution vote batch gossip.
#[must_use]
pub fn exec_vote_batch_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    votes: &[ExecutionVote],
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    for v in votes {
        hasher.update(v.global_receipt_root().as_raw().as_bytes());
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(DOMAIN_EXEC_VOTE_BATCH);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}

/// Build the signing message for an execution certificate batch gossip.
#[must_use]
pub fn exec_cert_batch_message(
    network: &NetworkDefinition,
    shard_group: ShardGroupId,
    certificates: &[ExecutionCertificate],
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    for c in certificates {
        hasher.update(c.global_receipt_root().as_raw().as_bytes());
    }
    let digest = hasher.finalize();

    let mut message = Vec::with_capacity(65);
    message.extend_from_slice(DOMAIN_EXEC_CERT_BATCH);
    message.push(network.id);
    message.extend_from_slice(&shard_group.to_le_bytes());
    message.extend_from_slice(digest.as_bytes());
    message
}

/// Domain tag for validator "ready on shard" signals.
///
/// Format: `HYPERSCALE_READY_SIGNAL_v1` || `network.id` || `validator_id` ||
/// `height_window_start` || `height_window_end`
///
/// Signed by the validator and broadcast to their shard committee. The
/// proposer includes valid dwell-eligible signals in the next block's
/// manifest; verifiers re-derive these bytes to check the BLS sig
/// before admitting the signal to their local pool. The window bounds
/// replay surface — a signal hoarded past `end` no longer validates.
pub const DOMAIN_READY_SIGNAL: &[u8] = b"HYPERSCALE_READY_SIGNAL_v1";

/// Build the canonical signing bytes for a
/// [`ReadySignal`](crate::ReadySignal).
#[must_use]
pub fn ready_signal_message(
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    height_window_start: BlockHeight,
    height_window_end: BlockHeight,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8);
    message.extend_from_slice(DOMAIN_READY_SIGNAL);
    message.push(network.id);
    message.extend_from_slice(&validator_id.to_le_bytes());
    message.extend_from_slice(&height_window_start.to_le_bytes());
    message.extend_from_slice(&height_window_end.to_le_bytes());
    message
}

// ═══════════════════════════════════════════════════════════════════════════
// Beacon PC inner-consensus vote signing
// ═══════════════════════════════════════════════════════════════════════════

/// Domain tag for beacon PC round-1 votes.
pub const DOMAIN_PC_VOTE1: &[u8] = b"HYPERSCALE_PC_VOTE1_v1";

/// Domain tag for beacon PC round-2 votes (per-prefix sigs).
pub const DOMAIN_PC_VOTE2: &[u8] = b"HYPERSCALE_PC_VOTE2_v1";

/// Domain tag for the length attestation rider on a PC round-2 vote.
///
/// Each round-2 vote carries an extra sig over a single-element vector
/// containing its `x.len()` under this tag, binding the signer to a
/// specific `x` length and closing a splice vulnerability in the
/// short-witness construction. A Byzantine prover that lacks the
/// signer's length sig can't splice a long round-2 vote's prefix sigs
/// to fake a "shorter x" claim.
pub const DOMAIN_PC_VOTE2_LENGTH: &[u8] = b"HYPERSCALE_PC_VOTE2_LENGTH_v1";

/// Domain tag for beacon PC round-3 votes.
pub const DOMAIN_PC_VOTE3: &[u8] = b"HYPERSCALE_PC_VOTE3_v1";

/// Domain tag for the SPC empty-view skip statement, which signs the
/// pair `(empty_view, reported_max_view)` for the view-change protocol.
pub const DOMAIN_PC_EMPTY_VIEW: &[u8] = b"HYPERSCALE_PC_EMPTY_VIEW_v1";

/// Derive an SPC instance's domain context from its slot.
///
/// Used as the per-slot binding when constructing PC signing messages
/// — the same vector signed under one slot's context will not verify
/// against another slot's context.
#[must_use]
pub fn spc_context(slot: Slot) -> Vec<u8> {
    slot.to_le_bytes().to_vec()
}

/// Derive a PC instance's domain context from its containing SPC
/// context and the view number.
///
/// Used as the per-view binding when constructing PC signing messages
/// inside a specific SPC view, so a vote in view `w` will not verify
/// as a vote in view `w' ≠ w`.
#[must_use]
pub fn pc_context(spc_ctx: &[u8], view: SpcView) -> Vec<u8> {
    let mut out = Vec::with_capacity(spc_ctx.len() + 4);
    out.extend_from_slice(spc_ctx);
    out.extend_from_slice(&view.to_le_bytes());
    out
}

/// Build the canonical signing bytes for a PC round vote.
///
/// `domain` is one of [`DOMAIN_PC_VOTE1`] / [`DOMAIN_PC_VOTE2`] /
/// [`DOMAIN_PC_VOTE2_LENGTH`] / [`DOMAIN_PC_VOTE3`] /
/// [`DOMAIN_PC_EMPTY_VIEW`]. `context` is normally the output of
/// [`pc_context`] (per-view binding); standalone tests may pass any
/// fixed-width bytes as long as signers and verifiers agree.
///
/// Layout: `domain || ctx_len (u32 LE) || ctx || vector_len (u32 LE)
/// || vector_bytes`. Both `context` and `vector` are length-prefixed
/// so callers that route arbitrary bytes through the signature can't
/// confuse one `(ctx, v)` for another `(ctx', v')` via boundary
/// ambiguity.
#[must_use]
pub fn pc_vote_signing_message(domain: &[u8], context: &[u8], vector: &PcVector) -> Vec<u8> {
    let ctx_len = u32::try_from(context.len()).unwrap_or(u32::MAX);
    let v_len = u32::try_from(vector.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(
        domain.len() + 4 + context.len() + 4 + vector.len() * PC_VALUE_ELEMENT_BYTES,
    );
    out.extend_from_slice(domain);
    out.extend_from_slice(&ctx_len.to_le_bytes());
    out.extend_from_slice(context);
    out.extend_from_slice(&v_len.to_le_bytes());
    for el in vector.iter() {
        out.extend_from_slice(el.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, TxHash};

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn test_block_vote_message_deterministic() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let msg1 = block_vote_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);
        let msg2 = block_vote_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_VOTE));
    }

    #[test]
    fn test_committed_block_header_message_deterministic() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let msg1 = committed_block_header_message(&net(), shard, BlockHeight::new(10), &block);
        let msg2 = committed_block_header_message(&net(), shard, BlockHeight::new(10), &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_COMMITTED_BLOCK_HEADER));
    }

    #[test]
    fn test_block_header_message_deterministic() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let msg1 =
            block_header_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);
        let msg2 =
            block_header_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_BLOCK_HEADER));
    }

    #[test]
    fn test_block_header_differs_from_block_vote() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let header_msg =
            block_header_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);
        let vote_msg =
            block_vote_message(&net(), shard, BlockHeight::new(10), Round::INITIAL, &block);

        // Must differ due to different domain tags (prevents cross-protocol replay)
        assert_ne!(header_msg, vote_msg);
    }

    #[test]
    fn test_state_provisions_message_deterministic() {
        use crate::{MerkleInclusionProof, ProvisionEntry};

        let provisions = Provisions::new(
            ShardGroupId::new(1),
            ShardGroupId::new(2),
            BlockHeight::new(10),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(b"tx1")),
                vec![],
                vec![],
                vec![],
            )],
        );

        let msg1 = state_provisions_message(&net(), &provisions);
        let msg2 = state_provisions_message(&net(), &provisions);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_STATE_PROVISION_BATCH));
    }

    #[test]
    fn test_validator_bind_message_deterministic_for_fixed_nonce() {
        let peer_id = b"12D3KooWDummyPeerId000000000000000";
        let nonce = [7u8; VALIDATOR_BIND_NONCE_LEN];

        let msg1 = validator_bind_message(&net(), peer_id, &nonce);
        let msg2 = validator_bind_message(&net(), peer_id, &nonce);

        assert_eq!(msg1, msg2);
        assert!(msg1.starts_with(DOMAIN_VALIDATOR_BIND));
    }

    #[test]
    fn test_validator_bind_message_differs_per_nonce() {
        let peer_id = b"12D3KooWDummyPeerId000000000000000";
        let nonce_a = [1u8; VALIDATOR_BIND_NONCE_LEN];
        let nonce_b = [2u8; VALIDATOR_BIND_NONCE_LEN];

        let msg_a = validator_bind_message(&net(), peer_id, &nonce_a);
        let msg_b = validator_bind_message(&net(), peer_id, &nonce_b);

        // Different nonces must produce different messages — replay protection.
        assert_ne!(msg_a, msg_b);
    }

    #[test]
    fn test_validator_bind_differs_from_other_domains() {
        let bytes = b"some_bytes_here_for_testing_1234";
        let nonce = [0u8; VALIDATOR_BIND_NONCE_LEN];

        let bind_msg = validator_bind_message(&net(), bytes, &nonce);
        let block_msg = block_vote_message(
            &net(),
            ShardGroupId::new(0),
            BlockHeight::GENESIS,
            Round::INITIAL,
            &BlockHash::from_raw(Hash::from_bytes(bytes)),
        );

        assert_ne!(bind_msg, block_msg);
    }

    #[test]
    fn ready_signal_message_byte_layout_is_pinned() {
        let network = net();
        let validator = ValidatorId::new(0x0123_4567_89AB_CDEF);
        let start = BlockHeight::new(100);
        let end = BlockHeight::new(228);

        let msg = ready_signal_message(&network, validator, start, end);
        let mut expected = Vec::with_capacity(DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8);
        expected.extend_from_slice(DOMAIN_READY_SIGNAL);
        expected.push(network.id);
        expected.extend_from_slice(&validator.to_le_bytes());
        expected.extend_from_slice(&start.to_le_bytes());
        expected.extend_from_slice(&end.to_le_bytes());

        assert_eq!(msg, expected);
        assert_eq!(msg.len(), DOMAIN_READY_SIGNAL.len() + 1 + 8 + 8 + 8);
    }

    #[test]
    fn ready_signal_message_differs_by_window() {
        let validator = ValidatorId::new(7);
        let a = ready_signal_message(&net(), validator, BlockHeight::new(0), BlockHeight::new(1));
        let b = ready_signal_message(&net(), validator, BlockHeight::new(0), BlockHeight::new(2));
        assert_ne!(a, b);
    }

    #[test]
    fn block_vote_message_differs_across_networks() {
        let shard = ShardGroupId::new(1);
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));

        let mainnet = block_vote_message(
            &NetworkDefinition::mainnet(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
        );
        let stokenet = block_vote_message(
            &NetworkDefinition::stokenet(),
            shard,
            BlockHeight::new(10),
            Round::INITIAL,
            &block,
        );
        // Cross-network replay protection: byte-identical inputs under
        // different networks must produce different messages.
        assert_ne!(mainnet, stokenet);
    }

    use crate::PcValueElement;

    fn ve(n: u8) -> PcValueElement {
        PcValueElement::new([n; PC_VALUE_ELEMENT_BYTES])
    }

    /// Pins the byte layout of `pc_vote_signing_message`. Any change
    /// to the encoder — field order, length-prefix width, domain tag
    /// — shifts these bytes and fails this test. Cross-arch
    /// determinism rides on this layout being identical regardless of
    /// `usize` width on the host.
    #[test]
    fn pc_vote_signing_message_byte_layout_is_pinned() {
        let ctx = spc_context(Slot::new(5));
        let v = PcVector::new(vec![ve(1), ve(2)]);
        let bytes = pc_vote_signing_message(DOMAIN_PC_VOTE1, &ctx, &v);

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_PC_VOTE1);
        expected.extend_from_slice(&8u32.to_le_bytes()); // ctx_len
        expected.extend_from_slice(&5u64.to_le_bytes()); // slot
        expected.extend_from_slice(&2u32.to_le_bytes()); // vector_len
        expected.extend_from_slice(ve(1).as_bytes());
        expected.extend_from_slice(ve(2).as_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(
            bytes.len(),
            DOMAIN_PC_VOTE1.len() + 4 + 8 + 4 + 2 * PC_VALUE_ELEMENT_BYTES
        );
    }

    /// Distinct domain tags must produce distinct signing bytes for
    /// the same `(ctx, vector)`. Cross-round replay protection inside
    /// a single SPC view depends on this.
    #[test]
    fn pc_vote_signing_message_domain_separates_rounds() {
        let ctx = spc_context(Slot::new(1));
        let v = PcVector::new(vec![ve(7)]);
        let m1 = pc_vote_signing_message(DOMAIN_PC_VOTE1, &ctx, &v);
        let m2 = pc_vote_signing_message(DOMAIN_PC_VOTE2, &ctx, &v);
        let m3 = pc_vote_signing_message(DOMAIN_PC_VOTE3, &ctx, &v);
        let mev = pc_vote_signing_message(DOMAIN_PC_EMPTY_VIEW, &ctx, &v);
        let m2l = pc_vote_signing_message(DOMAIN_PC_VOTE2_LENGTH, &ctx, &v);
        let all = [&m1, &m2, &m3, &mev, &m2l];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// `pc_context` extends an SPC context by 4 bytes of view, so two
    /// distinct views under the same SPC produce distinct PC
    /// contexts. Locks the cross-view replay protection.
    #[test]
    fn pc_context_separates_views() {
        let spc = spc_context(Slot::new(3));
        let pc_a = pc_context(&spc, SpcView::new(1));
        let pc_b = pc_context(&spc, SpcView::new(2));
        assert_eq!(pc_a.len(), spc.len() + 4);
        assert_eq!(pc_b.len(), spc.len() + 4);
        assert_ne!(pc_a, pc_b);
    }

    /// `spc_context` is exactly the slot LE bytes — bytes-pinned so
    /// the cross-slot replay-protection layout never drifts.
    #[test]
    fn spc_context_byte_layout_is_pinned() {
        assert_eq!(spc_context(Slot::new(0x42)), 0x42u64.to_le_bytes().to_vec());
    }
}
