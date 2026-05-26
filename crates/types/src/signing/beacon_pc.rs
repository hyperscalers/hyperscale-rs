//! Domain-separated signing for beacon PC inner-consensus votes.

use std::ops::Deref;

use crate::{Epoch, NetworkDefinition, PC_VALUE_ELEMENT_BYTES, PcVector, SpcView};

/// Per-epoch SPC signing context. Holds the byte-encoding that binds
/// SPC-level signatures (block certs, empty-views, recovery
/// equivocations) to a specific epoch.
///
/// Wrapping the bytes as a newtype prevents the SPC and PC contexts
/// from being silently cross-fed at call sites: an `&SpcContext`
/// passed where the verifier expects `&PcContext` fails at compile
/// time rather than producing a vote that verifies against the wrong
/// domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpcContext(Vec<u8>);

impl SpcContext {
    /// Borrow the canonical signing bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for SpcContext {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Per-(epoch, view) PC signing context. Holds the byte-encoding that
/// binds PC-level signatures (per-round votes, QC verification) to a
/// specific SPC view within an epoch.
///
/// See [`SpcContext`] for the type-level rationale.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcContext(Vec<u8>);

impl PcContext {
    /// Borrow the canonical signing bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for PcContext {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

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

/// Derive an SPC instance's domain context from its epoch.
///
/// Used as the per-epoch binding when constructing PC signing messages
/// — the same vector signed under one epoch's context will not verify
/// against another epoch's context.
#[must_use]
pub fn spc_context(epoch: Epoch) -> SpcContext {
    SpcContext(epoch.to_le_bytes().to_vec())
}

/// Derive a PC instance's domain context from its containing SPC
/// context and the view number.
///
/// Used as the per-view binding when constructing PC signing messages
/// inside a specific SPC view, so a vote in view `w` will not verify
/// as a vote in view `w' ≠ w`.
#[must_use]
pub fn pc_context(spc_ctx: &SpcContext, view: SpcView) -> PcContext {
    let spc_bytes = spc_ctx.as_bytes();
    let mut out = Vec::with_capacity(spc_bytes.len() + 4);
    out.extend_from_slice(spc_bytes);
    out.extend_from_slice(&view.to_le_bytes());
    PcContext(out)
}

/// Build the canonical signing bytes for a PC round vote.
///
/// `domain` is one of [`DOMAIN_PC_VOTE1`] / [`DOMAIN_PC_VOTE2`] /
/// [`DOMAIN_PC_VOTE2_LENGTH`] / [`DOMAIN_PC_VOTE3`] /
/// [`DOMAIN_PC_EMPTY_VIEW`]. `context` is normally the output of
/// [`pc_context`] (per-view binding); standalone tests may pass any
/// fixed-width bytes as long as signers and verifiers agree.
///
/// Layout: `domain || network.id || ctx_len (u32 LE) || ctx ||
/// vector_len (u32 LE) || vector_bytes`. Both `context` and `vector`
/// are length-prefixed so callers that route arbitrary bytes through
/// the signature can't confuse one `(ctx, v)` for another `(ctx', v')`
/// via boundary ambiguity.
#[must_use]
pub fn pc_vote_signing_message(
    network: &NetworkDefinition,
    domain: &[u8],
    context: &[u8],
    vector: &PcVector,
) -> Vec<u8> {
    let ctx_len = u32::try_from(context.len()).unwrap_or(u32::MAX);
    let v_len = u32::try_from(vector.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(
        domain.len() + 1 + 4 + context.len() + 4 + vector.len() * PC_VALUE_ELEMENT_BYTES,
    );
    out.extend_from_slice(domain);
    out.push(network.id);
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
    use crate::PcValueElement;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

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
        let network = net();
        let ctx = spc_context(Epoch::new(5));
        let v = PcVector::new(vec![ve(1), ve(2)]);
        let bytes = pc_vote_signing_message(&network, DOMAIN_PC_VOTE1, &ctx, &v);

        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_PC_VOTE1);
        expected.push(network.id);
        expected.extend_from_slice(&8u32.to_le_bytes()); // ctx_len
        expected.extend_from_slice(&5u64.to_le_bytes()); // epoch
        expected.extend_from_slice(&2u32.to_le_bytes()); // vector_len
        expected.extend_from_slice(ve(1).as_bytes());
        expected.extend_from_slice(ve(2).as_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(
            bytes.len(),
            DOMAIN_PC_VOTE1.len() + 1 + 4 + 8 + 4 + 2 * PC_VALUE_ELEMENT_BYTES
        );
    }

    /// Distinct domain tags must produce distinct signing bytes for
    /// the same `(ctx, vector)`. Cross-round replay protection inside
    /// a single SPC view depends on this.
    #[test]
    fn pc_vote_signing_message_domain_separates_rounds() {
        let ctx = spc_context(Epoch::new(1));
        let v = PcVector::new(vec![ve(7)]);
        let m1 = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE1, &ctx, &v);
        let m2 = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE2, &ctx, &v);
        let m3 = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE3, &ctx, &v);
        let mev = pc_vote_signing_message(&net(), DOMAIN_PC_EMPTY_VIEW, &ctx, &v);
        let m2l = pc_vote_signing_message(&net(), DOMAIN_PC_VOTE2_LENGTH, &ctx, &v);
        let all = [&m1, &m2, &m3, &mev, &m2l];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// Cross-network replay protection: byte-identical `(domain, ctx,
    /// vector)` inputs under different networks must produce different
    /// signing bytes.
    #[test]
    fn pc_vote_signing_message_differs_across_networks() {
        let ctx = spc_context(Epoch::new(1));
        let v = PcVector::new(vec![ve(7)]);
        let mainnet =
            pc_vote_signing_message(&NetworkDefinition::mainnet(), DOMAIN_PC_VOTE1, &ctx, &v);
        let stokenet =
            pc_vote_signing_message(&NetworkDefinition::stokenet(), DOMAIN_PC_VOTE1, &ctx, &v);
        assert_ne!(mainnet, stokenet);
    }

    /// `pc_context` extends an SPC context by 4 bytes of view, so two
    /// distinct views under the same SPC produce distinct PC
    /// contexts. Locks the cross-view replay protection.
    #[test]
    fn pc_context_separates_views() {
        let spc = spc_context(Epoch::new(3));
        let pc_a = pc_context(&spc, SpcView::new(1));
        let pc_b = pc_context(&spc, SpcView::new(2));
        assert_eq!(pc_a.len(), spc.len() + 4);
        assert_eq!(pc_b.len(), spc.len() + 4);
        assert_ne!(pc_a, pc_b);
    }

    /// `spc_context` is exactly the epoch LE bytes — bytes-pinned so
    /// the cross-epoch replay-protection layout never drifts.
    #[test]
    fn spc_context_byte_layout_is_pinned() {
        assert_eq!(
            spc_context(Epoch::new(0x42)).as_bytes(),
            &0x42u64.to_le_bytes(),
        );
    }
}
