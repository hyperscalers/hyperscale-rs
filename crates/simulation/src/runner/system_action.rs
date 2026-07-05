//! Submit a system transaction that reports a beacon action.
//!
//! A system transaction is a `lock_fee` no-op paid from the actor's account,
//! carrying a [`BeaconWitnessEvent`] in its message. It routes to the shard
//! owning that account; once committed, that shard reports the action to the
//! beacon over the usual witness rail. This is the simulation counterpart of an
//! operator staking, registering a validator, or voting through a real wallet.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_types::{
    BeaconWitnessEvent, Ed25519PrivateKey, NodeId, NotarizeOptions, TimestampRange, TxHash,
    WeightedTimestamp, encode_system_action, routable_from_notarized_v1,
    sign_and_notarize_with_options,
};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use radix_transactions::model::{MessageContentsV1, MessageV1, PlaintextMessageV1};

use super::SimulationRunner;

impl SimulationRunner {
    /// Build and submit a system transaction that reports `action` to the
    /// beacon: a `lock_fee` no-op paid from `payer`'s account, carrying the
    /// action in its plaintext message. The transaction routes to the shard
    /// owning that account, and the host now carrying that shard receives it.
    /// Returns the transaction hash.
    ///
    /// `payer`'s account must be funded at genesis (via
    /// [`SimulationRunner::initialize_genesis_with_balances`]) so the fee lock
    /// succeeds — a failed transaction reports nothing.
    ///
    /// # Panics
    ///
    /// Panics if signing or routability conversion fails, or if no host carries
    /// the payer account's shard.
    pub fn submit_system_action(
        &mut self,
        payer: &Ed25519PrivateKey,
        nonce: u32,
        action: &BeaconWitnessEvent,
    ) -> TxHash {
        let account = ComponentAddress::preallocated_account_from_public_key(&payer.public_key());
        let manifest = ManifestBuilder::new()
            .lock_fee(account, Decimal::from(10))
            .build();
        let message = MessageV1::Plaintext(PlaintextMessageV1 {
            mime_type: "application/octet-stream".to_string(),
            message: MessageContentsV1::Bytes(encode_system_action(action)),
        });
        let notarized = sign_and_notarize_with_options(
            manifest,
            &NetworkDefinition::simulator(),
            nonce,
            NotarizeOptions {
                message,
                ..Default::default()
            },
            payer,
        )
        .expect("system action transaction signs");

        // Bracket the current chain time so the transaction is live when it
        // lands, mirroring the post-grow validity window.
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO.plus(self.now.saturating_sub(Duration::from_secs(5))),
            WeightedTimestamp::ZERO.plus(self.now + Duration::from_secs(150)),
        );
        let tx =
            routable_from_notarized_v1(notarized, validity).expect("system action is routable");
        let tx_hash = tx.hash();

        let det_node = NodeId::from_radix(account.into_node_id());
        let shard = self
            .host_topology(0)
            .expect("host 0 carries a topology")
            .shard_for_node_id(&det_node);
        let host = (0..self.num_hosts())
            .find(|&host| self.hosts_shard(host, shard).is_some())
            .expect("a host carries the payer account's shard");
        self.schedule_initial_event(
            host,
            Duration::ZERO,
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );
        tx_hash
    }
}
