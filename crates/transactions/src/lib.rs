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
use hyperscale_effects_bridge::{NodeRecords, PROTOCOL_RESOURCE};
use hyperscale_types::{
    AccountSigner, NetworkId, ProtocolHasher, SubintentSig, TimestampRange, Transaction,
    TransactionEnvelope,
};
use hyperscale_vm_effects::{Claim, EnvelopeTree, Intent, IntentHeader, ManifestGraph, StoredRule};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError, signing};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::PrincipalAddr;

/// The compute every built envelope signs for whole, split evenly over
/// its nodes by [`default_gas_limits`].
///
/// Placeholder pricing — well above what a transfer draws at any node,
/// so the ceiling is never what a load generator hits first.
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 1_000_000;

/// The per-node ceilings every built envelope signs for a manifest of
/// `nodes` lowered nodes: [`DEFAULT_GAS_LIMIT`] split evenly, so the sum
/// a block reserves is the default whatever the manifest's shape.
#[must_use]
pub fn default_gas_limits(nodes: usize) -> Vec<u64> {
    let share = DEFAULT_GAS_LIMIT / u64::try_from(nodes.max(1)).unwrap_or(u64::MAX);
    vec![share; nodes]
}

/// Where an envelope's compute ceilings came from.
///
/// Named rather than defaulted, because the two are not the same claim.
/// A ceiling a preview measured is what the chain will meter the node
/// against; a ceiling nobody measured is a number, and a transaction
/// signed with one traps where the number was too small and reserves
/// block space it never uses where it was too large. A caller that has
/// not previewed says so here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ceilings {
    /// What a preview measured, one per lowered node in node order —
    /// its report's own figures, with whatever margin it was asked for.
    Measured(Vec<u64>),
    /// The deployment default split evenly over the manifest's nodes.
    ///
    /// For a caller with nothing to measure against: a load generator
    /// sending one shape a million times, a fixture whose figures are
    /// beside the point. A wallet spending someone's balance previews.
    Guessed,
}

impl Ceilings {
    /// The ceilings themselves, for a manifest of `nodes` lowered nodes.
    #[must_use]
    pub(crate) fn over(self, nodes: usize) -> Vec<u64> {
        match self {
            Self::Measured(ceilings) => ceilings,
            Self::Guessed => default_gas_limits(nodes),
        }
    }
}

/// What a signer commits to beyond the manifest, in this workspace's
/// vocabulary.
///
/// The VM's own terms carry a validity window as plain milliseconds and
/// the compute ceilings the caller chooses; this names the window with
/// the clock type the rest of the workspace speaks and asks for the
/// ceilings as a [`Ceilings`], which is what makes it deployment
/// binding rather than a second spelling of the same struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The most the signer will pay to have this transaction carried.
    pub max_fee: u128,
    /// When the transaction may be included.
    pub validity: TimestampRange,
    /// The compute ceilings the envelope signs.
    pub ceilings: Ceilings,
    /// What the signer will pay over the table price to be included, in
    /// basis points, burned like the rest of the fee.
    ///
    /// Buys a place in a block and never a position in one: a proposer
    /// offers the entries that paid over those that did not, and then
    /// orders whatever it offered by hash. So a priority answers
    /// congestion and cannot be sold as sequencing.
    pub priority_bp: u32,
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
        from: PrincipalAddr,
        to: PrincipalAddr,
        amount: u128,
    ) -> Result<ManifestGraph, TypedError> {
        let chain = self.records();
        // Composed for the account it spends from, whoever ends up
        // attesting the intent: the withdrawal's gate names `from`, and
        // the claim answering it rides that intent's own signature.
        let mut b = self.builder(&chain, from);
        let funds = account::withdraw(&mut b, from, *PROTOCOL_RESOURCE, amount)?;
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
            &EnvelopeTree::of_one(Intent::leaf(
                IntentHeader {
                    network: self.network,
                    validity_start_ms: terms.validity.start_timestamp_inclusive.as_millis(),
                    validity_end_ms: terms.validity.end_timestamp_exclusive.as_millis(),
                    // One offer, so one nullifier: a second submission
                    // of this declaration inside this window replaces
                    // it rather than running beside it. A caller who
                    // means two picks two discriminators.
                    discriminator: 0,
                },
                principal_of(payer),
                graph,
            )),
            Vec::new(),
            payer,
            terms,
        )
    }

    /// Wrap a composed tree in an envelope signed by `payer`.
    ///
    /// `sigs` are what the tree's members' signers produced over their
    /// intents; what `payer` signs is the whole envelope, those
    /// signatures included. The root's terms and window are `terms`,
    /// stamped here: the root is the composer's own and is signed last,
    /// so nothing a member signed is touched.
    ///
    /// The terms name the principal `payer`'s own scheme and key
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
        let mut tree = tree.clone();
        tree.root.header.validity_start_ms = terms.validity.start_timestamp_inclusive.as_millis();
        tree.root.header.validity_end_ms = terms.validity.end_timestamp_exclusive.as_millis();
        let envelope = signing::wrap(
            &tree,
            sigs,
            signing::Terms {
                fee_payer: principal_of(payer),
                max_fee: terms.max_fee,
                gas_limits: terms.ceilings.over(tree.node_count()),
                priority_bp: terms.priority_bp,
                message: terms.message,
            },
        );
        signing::sign(envelope, payer, &ProtocolHasher)
            .expect("a composed envelope stays within the wire caps")
    }

    /// A signed native-resource transfer to `to` from the account
    /// `payer`'s own key derives, which is the account the intent acts
    /// as. Paying from an account the key does not derive is
    /// [`build_transfer_paid_by`](crate::build_transfer_paid_by)'s.
    ///
    /// # Errors
    ///
    /// As [`transfer_graph`](Self::transfer_graph).
    pub fn transfer<S: AccountSigner>(
        &self,
        payer: &S,
        to: PrincipalAddr,
        amount: u128,
        terms: Terms,
    ) -> Result<Transaction, TypedError> {
        let graph = self.transfer_graph(principal_of(payer), to, amount)?;
        Ok(Transaction::new(self.sign(graph, payer, terms)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_effects_bridge::envelope_bytes;
    use hyperscale_effects_bridge::genesis::account_artifact;
    use hyperscale_types::test_utils::{test_principal, test_validity_range};
    use hyperscale_types::{Ed25519PrivateKey, MAX_ENVELOPE_BYTES};
    use hyperscale_vm_effects::{
        Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, Value, admit, package_hash,
    };

    use super::*;

    const NETWORK: NetworkId = NetworkId(242);

    /// A transfer is two nodes: the withdrawal the sender's account
    /// gates, and the deposit nobody refuses.
    ///
    /// The withdrawal presents the intent's own signature, which resolves
    /// to the account it acts as — so nothing signs in ahead of it and
    /// the edge the deposit consumes is the first node's.
    #[test]
    fn a_transfer_is_a_withdrawal_and_a_deposit() {
        let client = Client::genesis(NETWORK);
        let from = test_principal(0x11);
        let to = test_principal(0x22);
        assert_eq!(
            client.transfer_graph(from, to, 100).unwrap(),
            ManifestGraph {
                nodes: vec![
                    GraphNode {
                        target: from.into(),
                        method: "withdraw".into(),
                        args: vec![
                            GraphArg::Literal(Value::Address(PROTOCOL_RESOURCE.address())),
                            GraphArg::Literal(Value::U128(100)),
                        ],
                        evidence: [EvidenceRef::IntentSignature].into(),
                    },
                    GraphNode {
                        target: to.into(),
                        method: "deposit".into(),
                        args: vec![GraphArg::Edge {
                            edge: EdgeRef {
                                producer: 0,
                                output: 0,
                            },
                            constraints: vec![Constraint::ResourceIs(*PROTOCOL_RESOURCE)],
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
            .transfer_graph(test_principal(0x11), test_principal(0x22), 100)
            .unwrap();
        admit(
            &graph,
            test_principal(0x11),
            &client.records(),
            &ProtocolHasher,
        )
        .expect("a built transfer admits");
    }

    /// What a real transfer weighs on the wire.
    ///
    /// The retention row prices the envelope every validator keeps, and
    /// the block's retention cap is derived from a link budget — so what
    /// one ordinary transaction actually costs that budget is a figure
    /// worth knowing rather than inferring from the caps around it.
    #[test]
    fn a_transfer_weighs_what_it_weighs() {
        let client = Client::genesis(NETWORK);
        let signer = Ed25519PrivateKey::from_bytes(&[0x31; 32]).expect("a fixture key");
        let transfer = client
            .transfer(
                &signer,
                test_principal(0x22),
                100,
                Terms {
                    max_fee: 1_000_000,
                    validity: test_validity_range(),
                    ceilings: Ceilings::Guessed,
                    priority_bp: 0,
                    message: Vec::new(),
                },
            )
            .expect("a transfer builds");
        let encoded =
            usize::try_from(envelope_bytes(transfer.body()).expect("an envelope encodes"))
                .expect("an envelope's length fits a usize");
        println!("transfer envelope: {encoded} bytes");
        assert!(
            encoded < MAX_ENVELOPE_BYTES / 64,
            "an ordinary transfer weighs {encoded} bytes against a {MAX_ENVELOPE_BYTES} \
             envelope bound: the bound has stopped being an adversary's"
        );
    }

    /// What a wallet that previewed signs is what it measured, and what
    /// a caller that did not say so: the two arms produce different
    /// envelopes, and the measured one carries the report's own figures
    /// node for node.
    #[test]
    fn a_signed_envelope_carries_the_ceilings_it_was_given() {
        let client = Client::genesis(NETWORK);
        let signer = Ed25519PrivateKey::from_bytes(&[0x31; 32]).expect("a fixture key");
        let terms = |ceilings| Terms {
            max_fee: 1_000_000,
            validity: test_validity_range(),
            ceilings,
            priority_bp: 0,
            message: Vec::new(),
        };

        // A transfer lowers to two nodes, so a preview reporting two
        // figures is what the envelope signs.
        let measured = vec![1_234, 5_678];
        let previewed = client
            .transfer(
                &signer,
                test_principal(0x22),
                100,
                terms(Ceilings::Measured(measured.clone())),
            )
            .expect("a measured transfer builds");
        let ceilings = |tx: &Transaction| tx.body().terms.gas_limits.clone();
        assert_eq!(ceilings(&previewed), measured);

        let guessed = client
            .transfer(&signer, test_principal(0x22), 100, terms(Ceilings::Guessed))
            .expect("an unmeasured transfer builds");
        assert_eq!(
            ceilings(&guessed),
            default_gas_limits(measured.len()),
            "a caller that did not preview signs the deployment default"
        );
        assert_ne!(
            previewed.hash(),
            guessed.hash(),
            "the ceilings are signed content, so the two are two transactions"
        );
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
