//! The shape a served answer is built in, and what one costs on the wire.
//!
//! Every fetch this node answers by list is a prefix of what was asked:
//! as many items as the ask names and the response's cap admits, cut
//! short where a byte budget runs out. What is cut is simply not
//! answered, and the requester asks for it again. [`Answer`] is that
//! rule written once, so no serve spells its own clamp or its own
//! budget, and none can cut an answer to nothing: the first item is
//! always kept, which is what makes every request progress.
//!
//! What each answer carried is recorded once, where the request handler
//! is registered ([`Served`]), rather than at every return of every
//! serve.

use std::ops::ControlFlow;

use hyperscale_hbor::{Capped, DEFAULT_MAX_DEPTH, Encoder, HborEncode, Sink};
use hyperscale_types::network::Request;
use hyperscale_types::network::request::{
    GetCellsRequest, GetFinalizationsRequest, GetInstanceRecordsRequest, GetLocalProvisionsRequest,
    GetPackageArtifactsRequest, GetProvisionsRequest, GetRemoteHeadersRequest,
    GetSettledTxsRequest, GetStateProofRequest, GetStateRangeRequest, GetTransactionsRequest,
    GetWitnessHistoryRequest,
};

/// A served list under construction: at most `limit` items, at most `N`,
/// and as many bytes as the budget allows past the first.
pub struct Answer<T, const N: usize> {
    kept: Capped<Vec<T>, N>,
    limit: usize,
    budget: usize,
    spent: usize,
}

impl<T, const N: usize> Answer<T, N> {
    /// An answer to an ask of `asked` items: at least one, so an ask of
    /// none is answered like an ask of one, and at most the cap.
    pub fn of(asked: usize) -> Self {
        Self {
            kept: Capped::empty(),
            limit: asked.clamp(1, N),
            budget: usize::MAX,
            spent: 0,
        }
    }

    /// Cut the answer where the bytes it carries would pass `budget`.
    pub const fn within(mut self, budget: usize) -> Self {
        self.budget = budget;
        self
    }

    /// How many items the answer takes at most.
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Offer `item`, which weighs `size` bytes.
    ///
    /// Kept while the answer has room for one more and the item fits
    /// what is left of the budget — or when it is the first, which is
    /// kept whatever it weighs. Breaks once nothing more is taken: the
    /// item was refused, or the answer is now full.
    pub fn offer(&mut self, item: T, size: usize) -> ControlFlow<()> {
        if self.kept.len() >= self.limit {
            return ControlFlow::Break(());
        }
        let spent = self.spent.saturating_add(size);
        if !self.kept.is_empty() && spent > self.budget {
            return ControlFlow::Break(());
        }
        if self.kept.push(item).is_err() {
            return ControlFlow::Break(());
        }
        self.spent = spent;
        if self.kept.len() >= self.limit {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// Offer every item of `items` in order, weighed by `size`, until
    /// the answer stops taking them.
    pub fn offer_all(&mut self, items: impl IntoIterator<Item = T>, size: impl Fn(&T) -> usize) {
        for item in items {
            let weight = size(&item);
            if self.offer(item, weight).is_break() {
                break;
            }
        }
    }

    /// The answer as built.
    pub fn finish(self) -> Capped<Vec<T>, N> {
        self.kept
    }
}

/// Bytes `value` encodes to, counted rather than written.
///
/// `usize::MAX` for a value that does not encode, which no budget
/// admits past the first item.
pub fn encoded_len<T: HborEncode + ?Sized>(value: &T) -> usize {
    let mut count = 0;
    let encoded = value.encode(&mut Encoder::new(Counting(&mut count), DEFAULT_MAX_DEPTH));
    encoded.map_or(usize::MAX, |()| count)
}

/// A sink that keeps nothing but the count.
struct Counting<'a>(&'a mut usize);

impl Sink for Counting<'_> {
    fn write(&mut self, bytes: &[u8]) {
        *self.0 = self.0.saturating_add(bytes.len());
    }

    fn written(&self) -> usize {
        *self.0
    }
}

/// A request whose answers are counted as fetch responses sent.
///
/// Recorded where the handler is registered, labelled by the request's
/// wire name, so a serve returns its answer and nothing else.
pub trait Served: Request {
    /// How many items `response` answers this request with.
    fn served(&self, response: &Self::Response) -> usize;

    /// The metric label: the wire name without its `.request` suffix.
    fn label() -> &'static str {
        let name = Self::message_type_id();
        name.strip_suffix(".request").unwrap_or(name)
    }
}

impl Served for GetTransactionsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response.count()
    }
}

impl Served for GetStateRangeRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response
            .chunk
            .as_ref()
            .map_or(0, |chunk| chunk.leaves.len())
    }
}

impl Served for GetPackageArtifactsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response.artifacts.len()
    }
}

impl Served for GetInstanceRecordsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response.records.len()
    }
}

impl Served for GetWitnessHistoryRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response
            .history
            .as_ref()
            .map_or(0, |chunk| chunk.payloads.len())
    }
}

impl Served for GetProvisionsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response
            .provisions
            .as_ref()
            .map_or(0, |provisions| provisions.transactions().len())
    }
}

impl Served for GetLocalProvisionsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response.entries.len()
    }
}

impl Served for GetFinalizationsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response.finalizations.len()
    }
}

impl Served for GetRemoteHeadersRequest {
    fn served(&self, response: &Self::Response) -> usize {
        response.headers.len()
    }
}

/// One window, served whole or not at all.
impl Served for GetSettledTxsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        usize::from(response.txs.is_some())
    }
}

/// Every key asked, once a proof covers them.
impl Served for GetStateProofRequest {
    fn served(&self, response: &Self::Response) -> usize {
        if response.proof.is_some() {
            self.keys.len()
        } else {
            0
        }
    }
}

/// Every leaf the proof stands on: the keys asked and the entries the
/// intervals returned.
impl Served for GetCellsRequest {
    fn served(&self, response: &Self::Response) -> usize {
        if response.proof.is_some() {
            response
                .ranges
                .iter()
                .fold(self.keys.len(), |sum, range| sum + range.entries.len())
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::to_vec as hbor_to_vec;

    use super::*;

    /// A count past the cap is the cap; an ask of none is one.
    #[test]
    fn an_answer_is_clamped_to_one_through_its_cap() {
        assert_eq!(Answer::<u8, 4>::of(0).limit(), 1);
        assert_eq!(Answer::<u8, 4>::of(3).limit(), 3);
        assert_eq!(Answer::<u8, 4>::of(9).limit(), 4);
    }

    /// The first item is kept whatever it weighs; past it the budget
    /// cuts the answer at a prefix, in the order offered.
    #[test]
    fn the_budget_cuts_a_prefix_and_never_the_first() {
        let mut lone = Answer::<u32, 8>::of(8).within(10);
        assert!(lone.offer(1, 100).is_continue());
        assert!(lone.offer(2, 1).is_break());
        assert_eq!(lone.finish().into_inner(), vec![1]);

        let mut answer = Answer::<u32, 8>::of(8).within(10);
        answer.offer_all([1, 2, 3, 4], |_| 4);
        assert_eq!(answer.finish().into_inner(), vec![1, 2]);
    }

    /// The count limit stops the answer as the budget does.
    #[test]
    fn the_limit_stops_the_answer() {
        let mut answer = Answer::<u32, 8>::of(2);
        assert!(answer.offer(1, 0).is_continue());
        assert!(answer.offer(2, 0).is_break());
        assert!(answer.offer(3, 0).is_break());
        assert_eq!(answer.finish().into_inner(), vec![1, 2]);
    }

    /// The count is the encoding's length.
    #[test]
    fn an_encoded_length_is_counted_not_written() {
        let value: Vec<u64> = (0..100).collect();
        assert_eq!(encoded_len(&value), hbor_to_vec(&value).unwrap().len());
    }

    #[test]
    fn a_label_is_the_wire_name_without_its_suffix() {
        assert_eq!(GetTransactionsRequest::label(), "transaction");
        assert_eq!(GetLocalProvisionsRequest::label(), "local_provision");
    }
}
