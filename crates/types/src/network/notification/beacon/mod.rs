//! Beacon-chain inner-consensus notifications.
//!
//! Direct-mesh unicast wire-types for the latency-sensitive
//! committee-internal traffic: PC round 1/2/3 votes and SPC
//! empty-view / new-view / new-commit signals. All carry
//! `MessageClass::Consensus`.
//!
//! Block dissemination, witness lifts, and recovery requests use
//! gossip (see [`network::gossip`](crate::network::gossip)); catch-up
//! traffic uses request/response (see
//! [`network::request`](crate::network::request)).

mod empty_view;
mod new_commit;
mod new_view;
mod pc_vote1;
mod pc_vote2;
mod pc_vote3;

pub use empty_view::SpcEmptyViewMsgNotification;
pub use new_commit::SpcNewCommitNotification;
pub use new_view::SpcNewViewNotification;
pub use pc_vote1::PcVote1Notification;
pub use pc_vote2::PcVote2Notification;
pub use pc_vote3::PcVote3Notification;
