//! Client-side construction of signed transactions.
//!
//! A transaction is a manifest inside an envelope, and the two halves
//! belong to different layers. The manifest's shape is the VM's: its
//! `native` wrappers spell every stdlib method, drift-pinned against the
//! signatures the packages authored, so nothing here writes a node shape
//! and nothing here can drift from one. The envelope is this workspace's:
//! signing keys, validity windows, fee terms, the network word, and the
//! tree encoding.
//!
//! A [`Client`] holds the pair a construction needs — the world its
//! targets resolve in, and the network its envelopes name — because both
//! are properties of the deployment rather than of any one transaction.
//!
//! Nothing here renders judgement. Admission re-derives every property the
//! builders enforce, so a defect can cost a signer a refused transaction
//! and can never produce one the chain would wrongly accept.

use std::sync::LazyLock;

use hyperscale_effects_bridge::genesis::{World, genesis_world};
use hyperscale_effects_bridge::vm_statics::principal_for;
use hyperscale_effects_bridge::{NodeRecords, XRD};
use hyperscale_types::{
    AccountSigner, NetworkId, ProtocolHasher, SubintentSig, TimestampRange, Transaction,
    TransactionEnvelope,
};
use hyperscale_vm_effects::{
    Claim, EnvelopeTree, IntentDecl, IntentHeader, ManifestGraph, StoredRule,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError, signing};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::PrincipalAddr;

/// The execution gas limit every built envelope signs. Placeholder
/// pricing — well above what a transfer draws, so the ceiling is never
/// what a load generator hits first.
pub const DEFAULT_GAS_LIMIT: u64 = 1_000_000;

/// What a signer commits to beyond the manifest, in this workspace's
/// vocabulary.
///
/// The VM's own terms carry a validity window as plain milliseconds and a
/// gas ceiling the caller chooses; this names the window with the clock
/// type the rest of the workspace speaks and supplies the ceiling from
/// [`DEFAULT_GAS_LIMIT`], which is what makes it deployment binding rather
/// than a second spelling of the same struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The most the signer will pay to have this transaction carried.
    pub max_fee: u128,
    /// When the transaction may be included.
    pub validity: TimestampRange,
    /// Content riding the signature and nothing else.
    ///
    /// A transaction's hash covers the whole signed envelope, so two
    /// otherwise identical submissions inside one validity window are one
    /// transaction and the second deduplicates away. Varying this is how a
    /// caller keeps them distinct.
    pub message: Vec<u8>,
}

/// The world a deployment seating no pools starts from.
///
/// Held once per process because building it admits the stdlib artifacts
/// through the publish check, and the answer is the same every time.
static GENESIS: LazyLock<World> = LazyLock::new(genesis_world);

/// The account address `signer`'s key derives — the identity its
/// signature signs in as.
///
/// # Panics
///
/// If the key is not material its own scheme admits, which is a defect
/// in the signer rather than in anything it was asked to sign.
#[must_use]
pub fn principal_of<S: AccountSigner>(signer: &S) -> PrincipalAddr {
    principal_for(signer.scheme(), &signer.public_key_bytes())
        .expect("a signer's key is material its own scheme admits")
}

/// What a client needs to build a transaction: the world its targets
/// resolve in, and the network its envelopes are signed for.
#[derive(Debug, Clone)]
pub struct Client {
    world: World,
    network: NetworkId,
}

impl Client {
    /// A client on `world`, naming `network` in everything it signs.
    #[must_use]
    pub const fn new(world: World, network: NetworkId) -> Self {
        Self { world, network }
    }

    /// A client on the world a deployment with no seated pools starts
    /// from. A network seating pools resolves them through
    /// [`new`](Self::new) instead, because a pool is an instance and an
    /// instance has to be registered before it can be called.
    #[must_use]
    pub fn genesis(network: NetworkId) -> Self {
        Self::new(GENESIS.clone(), network)
    }

    /// The world this client's targets resolve in.
    #[must_use]
    pub const fn world(&self) -> &World {
        &self.world
    }

    /// The network this client signs for.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// A typed builder over this client's world, for an intent `signer`
    /// will sign.
    ///
    /// The records are loaded by the caller because the view has to
    /// outlive the builder borrowing it — and because one loaded view is
    /// what keeps a graph typed against a single world however many
    /// calls it names.
    #[must_use]
    pub fn builder<'a>(&self, chain: &'a NodeRecords, signer: PrincipalAddr) -> TypedBuilder<'a> {
        TypedBuilder::new(chain, &ProtocolHasher, signer)
    }

    /// What this client's world answers for, pinned — for a caller
    /// opening its own builder.
    #[must_use]
    pub fn records(&self) -> NodeRecords {
        self.world.records()
    }

    /// The withdraw-then-deposit graph moving `amount` of the native
    /// resource from `from` to `to`, composed by `signer`.
    ///
    /// When `signer` is `from`, the withdrawal takes the intent's
    /// signature. For anyone else the withdrawal presents `from`'s own
    /// sign-in, whose stored rule the signer answers with a sign-in at
    /// their own account composed ahead of it — how a key an account's
    /// rule names acts for that account.
    ///
    /// # Errors
    ///
    /// [`TypedError`] if the accounts or their methods do not resolve in
    /// this client's world, which is a world that never published the
    /// stdlib rather than anything about the transfer.
    pub fn transfer_graph(
        &self,
        signer: PrincipalAddr,
        from: PrincipalAddr,
        to: PrincipalAddr,
        amount: u128,
    ) -> Result<ManifestGraph, TypedError> {
        let chain = self.records();
        let mut b = self.builder(&chain, signer);
        let funds = if signer == from {
            account::withdraw(&mut b, from, *XRD, amount)?
        } else {
            let proof = account::authorize(&mut b, from)?;
            b.presenting(proof, |b| account::withdraw(b, from, *XRD, amount))?
        };
        account::deposit(&mut b, to, funds)?;
        b.build()
    }

    /// The sign-in-then-securify graph: `account` stores one rule as all
    /// three roles — the identity `holder`'s key derives — under
    /// `recovery_delay_ms`. The one-way transition off the rule the
    /// account's address derives; from the commit on, `holder`'s key
    /// governs acting and paying, and the account's own key governs
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`TypedError`] if the account or its methods do not resolve in
    /// this client's world.
    pub fn securify_graph(
        &self,
        account: PrincipalAddr,
        holder: PrincipalAddr,
        recovery_delay_ms: u64,
    ) -> Result<ManifestGraph, TypedError> {
        let chain = self.records();
        let mut b = self.builder(&chain, account);
        account::securify_uniform(
            &mut b,
            account,
            &StoredRule::claim(Claim::of_subject(holder)),
            recovery_delay_ms,
        )?;
        b.build()
    }

    /// Wrap `graph` in a single-intent envelope signed by `payer`.
    ///
    /// `message` rides the envelope's signed content, so a caller
    /// submitting the same graph repeatedly inside one validity window
    /// varies it to keep the submissions distinct transactions rather than
    /// one deduplicated by hash.
    #[must_use]
    pub fn sign<S: AccountSigner>(
        &self,
        graph: ManifestGraph,
        payer: &S,
        terms: Terms,
    ) -> TransactionEnvelope {
        self.sign_tree(
            &EnvelopeTree {
                root: IntentDecl {
                    header: IntentHeader {
                        network: self.network,
                        validity_start_ms: terms.validity.start_timestamp_inclusive.as_millis(),
                        validity_end_ms: terms.validity.end_timestamp_exclusive.as_millis(),
                        // Only a subintent's identity becomes a
                        // nullifier, so a root has nothing to
                        // distinguish itself from; what keeps two
                        // identical submissions apart is the envelope,
                        // through `Terms::message`.
                        discriminator: 0,
                    },
                    graph,
                    sockets: Vec::new(),
                },
                root_bindings: Vec::new(),
                subintents: Vec::new(),
                instances: Vec::new(),
                resources: Vec::new(),
            },
            Vec::new(),
            payer,
            terms,
        )
    }

    /// Wrap a composed tree in an envelope signed by `payer`.
    ///
    /// `sigs` are what the tree's own signers produced over their
    /// declarations; what `payer` signs is the whole envelope, those
    /// signatures included.
    ///
    /// The envelope names the principal `payer`'s own scheme and key
    /// derive, which is the account it can open by signing. A scheme is
    /// part of that derivation, so the same key under two schemes names
    /// two accounts and neither pays for the other.
    ///
    /// # Panics
    ///
    /// If `payer` produces a key its own scheme does not admit, which is
    /// a defect in the signer rather than in what it was asked to sign —
    /// or if the composed envelope outgrows the wire caps, which nothing
    /// this client composes does.
    #[must_use]
    pub fn sign_tree<S: AccountSigner>(
        &self,
        tree: &EnvelopeTree,
        sigs: Vec<SubintentSig>,
        payer: &S,
        terms: Terms,
    ) -> TransactionEnvelope {
        let envelope = signing::wrap(
            tree,
            sigs,
            principal_of(payer),
            self.network,
            signing::Terms {
                max_fee: terms.max_fee,
                gas_limit: DEFAULT_GAS_LIMIT,
                validity_start_ms: terms.validity.start_timestamp_inclusive.as_millis(),
                validity_end_ms: terms.validity.end_timestamp_exclusive.as_millis(),
                message: terms.message,
            },
        );
        signing::sign(envelope, payer, &ProtocolHasher)
            .expect("a composed envelope stays within the wire caps")
    }

    /// A signed native-resource transfer from `from` to `to`, composed
    /// by `payer`'s own account.
    ///
    /// # Errors
    ///
    /// As [`transfer_graph`](Self::transfer_graph).
    pub fn transfer<S: AccountSigner>(
        &self,
        payer: &S,
        from: PrincipalAddr,
        to: PrincipalAddr,
        amount: u128,
        terms: Terms,
    ) -> Result<Transaction, TypedError> {
        let graph = self.transfer_graph(principal_of(payer), from, to, amount)?;
        Ok(Transaction::new(self.sign(graph, payer, terms)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_effects_bridge::genesis::account_artifact;
    use hyperscale_types::test_utils::test_principal;
    use hyperscale_vm_effects::{
        Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, Value, admit, package_hash,
    };

    use super::*;

    const NETWORK: NetworkId = NetworkId(242);

    #[test]
    fn a_transfer_is_the_graph_the_hand_written_one_was() {
        // The signatures type the edge exactly as the hand-assembled graph
        // asserted it, so adopting the builder moved no manifest hash and
        // therefore no transaction identity.
        let client = Client::genesis(NETWORK);
        let from = test_principal(0x11);
        let to = test_principal(0x22);
        assert_eq!(
            client.transfer_graph(from, from, to, 100).unwrap(),
            ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: from.into(),
                        method: "authorize".into(),
                        args: vec![],
                        evidence: [EvidenceRef::IntentSignature].into(),
                    },
                    GraphNode {
                        target: from.into(),
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(XRD.address())),
                            GraphArg::Literal(Value::U128(100)),
                        ],
                        evidence: [EvidenceRef::Node(0)].into(),
                    },
                    GraphNode {
                        target: to.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 1,
                                output: 0,
                            },
                            constraints: vec![Constraint::ResourceIs(*XRD)],
                        }],
                        evidence: BTreeSet::new(),
                    },
                ],
            }
        );
    }

    #[test]
    fn a_built_transfer_admits() {
        let client = Client::genesis(NETWORK);
        let graph = client
            .transfer_graph(
                test_principal(0x11),
                test_principal(0x11),
                test_principal(0x22),
                100,
            )
            .unwrap();
        admit(
            &graph,
            test_principal(0x11),
            &client.records(),
            &ProtocolHasher,
        )
        .expect("a built transfer admits");
    }

    #[test]
    fn the_genesis_world_is_the_one_the_stdlib_publishes() {
        let client = Client::genesis(NETWORK);
        assert_eq!(client.network(), NETWORK);
        assert_eq!(
            client.world().account_package,
            package_hash(&ProtocolHasher, account_artifact())
        );
    }
}
