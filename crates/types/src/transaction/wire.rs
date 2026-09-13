//! [`Transaction`] — the carried form of a signed envelope.
//!
//! [`Transaction`] is the raw wire form. Its verified form is
//! `Verified<Transaction>`; predicate at
//! [`impl Verify<NetworkId>`](Verify::verify) below.
//!
//! The admission conflict keys, the owner prefixes that place the
//! transaction on shards, and the validity window are all derived
//! locally from the signed envelope rather than carried beside it — a
//! sender cannot claim a placement its content does not earn. The
//! derivations are cached on the value.

use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use blake3::Hasher;
use hyperscale_hbor::{Hbor, from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_vm_types::{DeclaredWork, LegShape, PriceTable};
use thiserror::Error;

use crate::transaction::vm::{Derivation, ProtocolVerifier, SchemeVerifier};
use crate::{
    Address, DeclaredKey, DerivationError, Derived, EnvelopeExt, Hash, LocalKey,
    MAX_ENVELOPE_BYTES, NetworkId, OwnerShare, PrincipalAddr, Routing, ShardId, ShardTrie,
    SubstateKey, TimestampRange, TransactionEnvelope, TxHash, Verified, Verify, protocol_statics,
};

/// What a transaction is verified against: the network its envelope has
/// to name, and the derivation this node answers with.
///
/// The derivation rides in the context because it is the node's, not the
/// protocol's — two nodes hold different caches, so the same envelope can
/// derive on one and want a record on the other.
#[derive(Clone, Copy)]
pub struct TransactionContext<'a> {
    /// The network this node verifies for.
    pub network: NetworkId,
    /// This node's derivation.
    pub derivation: &'a dyn Derivation,
}

/// A signed transaction as the network carries it.
///
/// `serialized_bytes` is the canonical wire form — the HBOR
/// encoding of the envelope. The hash is the envelope's signing hash,
/// recomputed locally from those bytes, so a peer can neither ship one
/// encoding and have us key it by another nor mint a second identity for
/// signed content by re-rolling the signature. Every other field is a
/// lazily-populated cache, skipped on the wire and rebuilt at each end.
#[derive(Hbor)]
pub struct Transaction {
    /// HBOR-encoded [`TransactionEnvelope`] bytes — the canonical wire form.
    #[hbor(max = MAX_ENVELOPE_BYTES)]
    serialized_bytes: Vec<u8>,

    /// Decoded envelope, populated by `body()` on first access from
    /// `serialized_bytes`. Constructors pre-populate. Not on the wire.
    #[hbor(skip)]
    body: OnceLock<TransactionEnvelope>,

    /// Derived routing identity and subintent claims, populated at
    /// verification (or lazily for committed transactions). Not on the
    /// wire — derivation is local by construction.
    #[hbor(skip)]
    derived: OnceLock<Derived>,

    /// The envelope's signing hash, populated on first call to `hash()`.
    /// `::new` pre-populates. Not on the wire — recomputed at each end so
    /// a peer can't ship `(hash=X, tx_bytes=Y)` and have us key the bogus
    /// body by X.
    #[hbor(skip)]
    hash: OnceLock<Hash>,

    /// Pre-encoded wire bytes of the full `Transaction`,
    /// populated lazily by `cached_wire_bytes()`. Lets the commit thread
    /// hand bytes to `cf_put_raw` without re-encoding.
    #[hbor(skip)]
    cached_bytes: OnceLock<Vec<u8>>,
}

// Manual PartialEq/Eq - compare by hash for efficiency
impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Transaction {}

// Manual Clone - OnceLock doesn't implement Clone. Every populated cache
// is copied so the clone doesn't pay first-access cost twice; in
// particular the derivation rides across clones, so the work a fresh tx
// incurs at admission is amortized over every later raw clone (tick-state
// extract, mempool block-commit lift, proposal build).
impl Clone for Transaction {
    fn clone(&self) -> Self {
        let body = OnceLock::new();
        if let Some(t) = self.body.get() {
            let _ = body.set(t.clone());
        }
        let derived = OnceLock::new();
        if let Some(r) = self.derived.get() {
            let _ = derived.set(r.clone());
        }
        let hash = OnceLock::new();
        if let Some(h) = self.hash.get() {
            let _ = hash.set(*h);
        }
        let cached_bytes = OnceLock::new();
        if let Some(b) = self.cached_bytes.get() {
            let _ = cached_bytes.set(b.clone());
        }
        Self {
            serialized_bytes: self.serialized_bytes.clone(),
            body,
            derived,
            hash,
            cached_bytes,
        }
    }
}

// Manual Debug — skip the cached_bytes field.
impl Debug for Transaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("hash", &self.hash())
            .finish_non_exhaustive()
    }
}

impl Transaction {
    /// The admission conflict keys for this transaction's reads — the
    /// routed effect sets' shared-mode keys. Nothing key-granular is
    /// carried on the wire.
    #[must_use]
    pub fn admission_read_keys(&self) -> Vec<DeclaredKey> {
        self.routing().read_keys.clone()
    }

    /// The admission conflict keys for this transaction's writes; see
    /// [`Self::admission_read_keys`].
    #[must_use]
    pub fn admission_write_keys(&self) -> Vec<DeclaredKey> {
        self.routing().write_keys.clone()
    }

    /// Every admission conflict key, reads then writes.
    #[must_use]
    pub fn admission_keys(&self) -> Vec<DeclaredKey> {
        let mut keys = self.admission_read_keys();
        keys.extend(self.admission_write_keys());
        keys
    }

    /// What this transaction declares it may consume, whole. Derived
    /// locally, so it is not something a sender can understate.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::routing`].
    #[must_use]
    pub fn work(&self) -> &DeclaredWork {
        &self.derived().work
    }

    /// What each owner prefix bears of the declaration: the effects on
    /// its cells and the kernel cells written under it. Sorted and
    /// unique by owner.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn shares(&self) -> &[OwnerShare] {
        &self.derived().shares
    }

    /// What each manifest node bears, in node order: its signed ceiling
    /// and the artifact instantiating it reads.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn node_terms(&self) -> &[DeclaredWork] {
        &self.derived().node_terms
    }

    /// What every shard committing this transaction bears whatever it
    /// holds: the verification, the committed cell, and the retention.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn everywhere(&self) -> DeclaredWork {
        self.derived().everywhere
    }

    /// What this transaction is charged, in quanta, under `table`: its
    /// declared work at the table's rows, raised by its signed priority.
    /// One figure whatever the outcome and wherever it runs — a
    /// participant measuring only its own legs bills the same as one
    /// that ran the whole — and never more than the signed ceiling,
    /// which admission holds it to.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn price(&self, table: &PriceTable) -> u128 {
        table.price(self.work(), self.body().priority_bp)
    }

    /// [`Self::price`] for an envelope that may not have been derived
    /// yet — what a composer quotes before submitting, deriving under
    /// `derivation` where nothing has.
    ///
    /// # Errors
    ///
    /// [`DerivationError`], where the envelope derives to nothing.
    pub fn price_under(
        &self,
        derivation: &dyn Derivation,
        table: &PriceTable,
    ) -> Result<u128, DerivationError> {
        let work = self.try_derived(derivation)?.work;
        Ok(table.price(&work, self.body().priority_bp))
    }

    /// Each manifest node's placement-free shape, in node order.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn legs(&self) -> &[LegShape] {
        &self.derived().legs
    }

    /// The parties the routing declares beyond any node's frame: the
    /// fee payer and every signer.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn owners(&self) -> &[Address] {
        &self.derived().owners
    }

    /// The cells the kernel writes of its own accord.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn nullifiers(&self) -> &[SubstateKey] {
        &self.derived().nullifiers
    }

    /// How many cells this transaction's execution on `shard` creates
    /// that a sweep will later have to retire, under `trie`'s placement:
    /// its nullifiers under signers the shard holds, and, for every
    /// value edge whose ends the trie places on different shards, the
    /// record where the shard holds the producer and the claim where it
    /// holds the consumer.
    ///
    /// An edge inside one shard passes its value directly and writes
    /// neither. So does one inside a core spanning two shards, and that
    /// one is counted anyway: the count reads placement alone and never
    /// the classification, so it over-flags a core's internal edge
    /// rather than depending on a window's answer. What a block sums,
    /// beside the committed cell it writes for the transaction itself,
    /// to stay under
    /// [`MAX_SWEEPABLE_CREATED_PER_BLOCK`](crate::MAX_SWEEPABLE_CREATED_PER_BLOCK).
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn sweepable_writes_on(&self, trie: &ShardTrie, shard: ShardId) -> usize {
        let derived = self.derived();
        let placed = |target| trie.shard_for_prefix(target);
        let nullifiers = derived
            .nullifiers
            .iter()
            .filter(|cell| placed(cell.owner) == shard)
            .count();
        let escrow: usize = derived
            .legs
            .iter()
            .flat_map(|consumer| {
                consumer
                    .edges
                    .iter()
                    .map(move |edge| (edge.source, consumer.target))
            })
            .map(|(source, consumer)| {
                let Some(producer) = derived.legs.get(source as usize) else {
                    return 0;
                };
                let (from, to) = (placed(producer.target), placed(consumer));
                if from == to {
                    0
                } else {
                    usize::from(from == shard) + usize::from(to == shard)
                }
            })
            .sum();
        nullifiers + escrow
    }

    /// Half-open `WeightedTimestamp` range during which this tx may be
    /// included in a block. Anchored on the parent QC's `weighted_timestamp`
    /// at every check site. Signer-chosen, chain-enforced.
    ///
    /// The *effective* window: the envelope's, narrowed by every
    /// subintent it binds. Read from the derivation rather than from the
    /// envelope, because the envelope's own fields are the composer's
    /// claim and a bound signer's window may be tighter.
    ///
    /// # Panics
    ///
    /// As [`Self::work`], on a transaction that was never derived.
    #[must_use]
    pub fn validity_range(&self) -> TimestampRange {
        self.derived().effective_window
    }

    /// Create a transaction from a signed envelope.
    ///
    /// # Panics
    ///
    /// Panics if the `TransactionEnvelope` cannot be HBOR-encoded; it is a
    /// closed wire type, so encoding is infallible in practice.
    #[must_use]
    pub fn new(vm: TransactionEnvelope) -> Self {
        let payload = hbor_to_vec(&vm).expect("an envelope within its caps encodes");
        let hash = vm.signing_hash();

        let body_lock = OnceLock::new();
        let _ = body_lock.set(vm);
        let hash_lock = OnceLock::new();
        let _ = hash_lock.set(hash);

        Self {
            serialized_bytes: payload,
            body: body_lock,
            derived: OnceLock::new(),
            hash: hash_lock,
            cached_bytes: OnceLock::new(),
        }
    }

    /// The transaction's identity: the protocol hash of the envelope's
    /// signing bytes.
    ///
    /// One identity for every job — dedup, canonical ordering, receipt
    /// and certificate naming, and the root every fresh derivation and
    /// nullifier already grows from — and it covers exactly what the
    /// composer signed. The signature and key sit outside it, so a
    /// re-rolled signature over the same content is the same
    /// transaction rather than a distinct one minting the same fresh
    /// keys: the envelope's "distinct transactions never mint the same
    /// fresh key" guarantee holds structurally.
    ///
    /// Computed on first call and cached; `::new` pre-populates. Bytes
    /// that do not decode as an envelope hash as themselves — such a
    /// transaction is refused at verification and enters nothing, so the
    /// stand-in identity only ever keys the refusal.
    pub fn hash(&self) -> TxHash {
        TxHash::from(*self.hash.get_or_init(|| {
            self.try_body().map_or_else(
                |_| {
                    let mut hasher = Hasher::new();
                    hasher.update(&self.serialized_bytes);
                    Hash::from_hash_bytes(hasher.finalize().as_bytes())
                },
                EnvelopeExt::signing_hash,
            )
        }))
    }

    /// Decode the envelope, or refuse malformed bytes. The fallible path
    /// for wire input; [`Self::body`] is the post-verification accessor.
    ///
    /// # Errors
    ///
    /// [`TransactionVerifyError::UndecodableBody`] when the bytes
    /// do not decode as an envelope.
    pub fn try_body(&self) -> Result<&TransactionEnvelope, TransactionVerifyError> {
        if let Some(body) = self.body.get() {
            return Ok(body);
        }
        let decoded = hbor_from_slice::<TransactionEnvelope>(&self.serialized_bytes)
            .map_err(|_| TransactionVerifyError::UndecodableBody)?;
        Ok(self.body.get_or_init(|| decoded))
    }

    /// The decoded envelope. Constructors pre-populate it; wire-decoded
    /// transactions populate it at verification.
    ///
    /// # Panics
    ///
    /// Panics if `serialized_bytes` does not decode. Wire-decoded
    /// transactions are verified (which decodes fallibly) before this is
    /// invoked.
    pub fn body(&self) -> &TransactionEnvelope {
        self.try_body()
            .expect("Transaction.serialized_bytes failed body decode")
    }

    /// The derived routing identity.
    ///
    /// Reads the cache [`Self::try_derived`] fills; nothing derives here,
    /// because deriving is a node's own answer and this accessor holds no
    /// node.
    ///
    /// # Panics
    ///
    /// Panics if the transaction was never derived — unreachable for
    /// verified transactions, since verification derives, and for
    /// committed ones, since a block whose transactions are not all
    /// verified is not voted on.
    #[must_use]
    pub fn routing(&self) -> &Routing {
        &self.derived().routing
    }

    /// The packages the manifest's calls run — what the execution gate
    /// holds this transaction to on every participant shard.
    ///
    /// # Panics
    ///
    /// As [`Self::routing`]: derivation must have succeeded.
    #[must_use]
    pub fn packages(&self) -> &[Hash] {
        &self.derived().packages
    }

    /// The fee payer's native-resource vault cell — what the payer
    /// shard's reservation check reads and the fee settlement debits.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::routing`].
    #[must_use]
    pub fn fee_vault(&self) -> SubstateKey {
        SubstateKey {
            owner: self.body().fee_payer.address(),
            local: LocalKey(self.derived().fee_vault_local),
        }
    }

    /// The principal the envelope's signature opens — the identity the
    /// root intent presents as evidence.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::routing`].
    #[must_use]
    pub fn signer(&self) -> PrincipalAddr {
        self.derived().signer
    }

    /// The fee payer's stored-authority cell — what the payer shard's
    /// binding verdict reads beside the vault, at the same anchored
    /// height.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::routing`].
    #[must_use]
    pub fn auth_cell(&self) -> SubstateKey {
        SubstateKey {
            owner: self.body().fee_payer.address(),
            local: LocalKey(self.derived().auth_cell_local),
        }
    }

    /// Whether the fee payer's rule admits the envelope signer, given
    /// the payer's stored-authority cell as read at the caller's own
    /// anchored height — `None` or empty meaning absent, the virtual
    /// rule. `clock_ms` reaches [`ProtocolStatics::rule_admits`], which
    /// does not read it: the cell holds one rule, and replacing one is a
    /// write.
    ///
    /// Every fee rule debits the account the envelope's `fee_payer`
    /// names — the reservation the payer shard enforces as block
    /// validity, the burn a completed transaction writes, the floor an
    /// abort settles — so a payer whose rule does not admit the signer
    /// would be a debit on an account that authorised nothing,
    /// spendable by anyone who knows its address.
    ///
    /// Judged only where the payer's state is — the payer's shard, at
    /// mempool admission, at proposal, and as a block-validity
    /// condition at vote.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::routing`].
    ///
    /// [`ProtocolStatics::rule_admits`]: crate::ProtocolStatics::rule_admits
    #[must_use]
    pub fn payer_admits_signer(&self, auth_cell: Option<&[u8]>, clock_ms: u64) -> bool {
        protocol_statics().rule_admits(auth_cell, self.body().fee_payer, self.signer(), clock_ms)
    }

    /// The cached derivation, or a panic saying it was never derived.
    fn derived(&self) -> &Derived {
        self.derived.get().expect(
            "derived facts read from a transaction that was never derived; \
             verification derives, and consensus paths take only verified transactions",
        )
    }

    /// This transaction with its derived legs replaced by `legs`, for a
    /// test that needs a shape the stub derivation cannot produce.
    /// Derives under `derivation` first where nothing has yet.
    ///
    /// # Panics
    ///
    /// If `derivation` refuses the body.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_legs(self, derivation: &dyn Derivation, legs: Vec<LegShape>) -> Self {
        let base = self
            .try_derived(derivation)
            .expect("a stub transaction derives")
            .clone();
        let tx = Self::new(self.body().clone());
        let _ = tx.derived.set(Derived { legs, ..base });
        tx
    }

    /// Derive (or fetch the cached) envelope derivation under this
    /// node's `derivation`.
    ///
    /// Only successes are cached, so a refusal for want of a record this
    /// node has not seen re-derives once the record lands.
    ///
    /// # Errors
    ///
    /// [`DerivationError`] from `derivation`.
    pub fn try_derived(&self, derivation: &dyn Derivation) -> Result<&Derived, DerivationError> {
        if let Some(derived) = self.derived.get() {
            return Ok(derived);
        }
        let derived = derivation.derive(self.body())?;
        Ok(self.derived.get_or_init(|| derived))
    }

    /// Get the cached serialized envelope bytes.
    ///
    /// Use this for computing transaction merkle roots (avoids
    /// re-serialization) and for network encoding.
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.serialized_bytes
    }

    /// Pre-serialized wire bytes of the full `Transaction`.
    /// Computed on first call and cached.
    ///
    /// # Panics
    ///
    /// Panics if HBOR encoding fails — that's a programmer error since
    /// every field is `Hbor` and the type itself is closed.
    pub fn cached_wire_bytes(&self) -> &[u8] {
        self.cached_bytes
            .get_or_init(|| hbor_to_vec(self).expect("Transaction HBOR encode is infallible"))
    }

    /// Check if this transaction is cross-shard under a uniform `num_shards`-way
    /// partition. For the live partition use
    /// [`TopologySnapshot::is_cross_shard_transaction`], which routes against the
    /// active [`ShardTrie`]; this by-count form is for genesis and offline tooling.
    ///
    /// [`TopologySnapshot::is_cross_shard_transaction`]: crate::TopologySnapshot::is_cross_shard_transaction
    pub fn is_cross_shard(&self, num_shards: u64) -> bool {
        let trie = ShardTrie::uniform_from_count(num_shards);
        let mut shards = self
            .routing()
            .write_prefixes
            .iter()
            .map(|prefix| trie.shard_for_prefix(*prefix));
        let Some(first) = shards.next() else {
            return false;
        };
        shards.any(|shard| shard != first)
    }
}

/// Failure modes of [`Transaction`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransactionVerifyError {
    /// The body bytes do not decode as an envelope.
    #[error("transaction body bytes are undecodable")]
    UndecodableBody,
    /// The envelope names a different network than this session's.
    #[error("transaction is signed for network {signed}, not this network {session}")]
    WrongNetwork {
        /// The network the envelope names.
        signed: u8,
        /// The network this node verifies for.
        session: u8,
    },
    /// The envelope's composer signature does not cover its content.
    #[error("transaction signature is invalid")]
    InvalidSignature,
    /// A subintent signature does not cover its declaration hash.
    #[error("subintent {0} signature is invalid")]
    InvalidSubintentSignature(u32),
    /// Static derivation refused the envelope.
    #[error(transparent)]
    Derivation(#[from] DerivationError),
}

/// Construction asserts: the body decodes, the envelope names this
/// session's network, the composer's ed25519 signature covers the
/// envelope content, the tree admits and routes under the context's
/// [`crate::Derivation`] (which caches the derived identity on the
/// transaction and binds every subintent signer address to its public
/// key), and every subintent signature covers its declaration hash.
///
/// The network check runs before the signature: the named network is
/// signed content, so a transaction composed for another network fails
/// here whatever its signature says, and a re-targeted one fails the
/// signature.
///
/// Construction goes through one of two gates:
///
/// - [`<Transaction as Verify>::verify`](Verify::verify) — runs
///   the predicate.
/// - [`Verified::<Transaction>::new_unchecked`] — re-wraps a
///   transaction whose predicate already held via an out-of-band trust
///   source (storage-recovery, where the value was validated before
///   persistence; equivalent-attestation paths). Every call site
///   carries a `// SAFETY:` comment naming the trust source.
impl Verify<TransactionContext<'_>> for Transaction {
    type Error = TransactionVerifyError;

    fn verify(&self, ctx: TransactionContext<'_>) -> Result<Verified<Self>, Self::Error> {
        let vm = self.try_body()?;
        if vm.network != ctx.network {
            return Err(TransactionVerifyError::WrongNetwork {
                signed: vm.network.0,
                session: ctx.network.0,
            });
        }
        if !vm.signature_is_valid() {
            return Err(TransactionVerifyError::InvalidSignature);
        }
        // Derivation checks the tree, the signature arity, and the
        // signer-address binding; the signatures themselves verify here,
        // over the derived declaration hashes.
        let derived = self.try_derived(ctx.derivation)?;
        // What the signed ceiling has to cover is not decided here: the
        // price is the table's, the table is the anchor's, and a
        // signature check holds no snapshot. Admission judges it where
        // the window is resolved.
        for (index, (sig, subintent)) in vm
            .subintent_sigs
            .iter()
            .zip(&derived.subintent_hashes)
            .enumerate()
        {
            let valid =
                ProtocolVerifier.verify(sig.scheme, &sig.public_key, &sig.signature, subintent);
            if !valid {
                return Err(TransactionVerifyError::InvalidSubintentSignature(
                    u32::try_from(index).unwrap_or(u32::MAX),
                ));
            }
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<Transaction> {
    /// Re-wrap a `Transaction` whose trust derives from inclusion
    /// in a committed block.
    ///
    /// Trust chain (BFT-transitive):
    /// 1. The tx is contained in a `CertifiedBlock`.
    /// 2. `CertifiedBlock` carries a QC attesting ≥2f+1 voting power.
    /// 3. Voters refuse to vote on blocks whose `Block.transactions`
    ///    entries are not all `Verifiable::Verified` — see
    ///    `validate_block_for_vote` in `crates/shard`.
    /// 4. Therefore every tx in a committed block was admission-validated
    ///    by at least one honest voter through the standard `Verify` gate.
    ///
    /// Callers: mempool reload from a committed block, storage
    /// rehydration into block containers, and any other path that
    /// surfaces a raw `Transaction` whose container is itself
    /// the trust anchor.
    #[must_use]
    pub const fn from_persisted(tx: Transaction) -> Self {
        Self::new_unchecked(tx)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, Hash32, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };
    use hyperscale_vm_types::{
        Address, AddressClass, LegRole, Mode, Moves, SubintentHash, ValueEdge,
    };

    use super::*;
    use crate::test_utils::{test_prefix, test_validity_range};
    use crate::{
        Derivation, Ed25519PrivateKey, MlDsa65PrivateKey, PrincipalAddr, SchemeId,
        Secp256k1PrivateKey, SubintentSig, TransactionBody,
    };

    struct StubStatics;

    /// The declaration hash the stub claims for `b"with-subintent"`
    /// trees; the fixture's subintent signature covers it.
    const STUB_SUBINTENT_HASH: [u8; 32] = [0x5A; 32];

    impl Derivation for StubStatics {
        fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError> {
            if vm.call_tree().unwrap_or_default() == b"inadmissible" {
                return Err(DerivationError::Refused("stub refusal".into()));
            }
            let subintent_hashes = if vm.call_tree().unwrap_or_default() == b"with-subintent" {
                vec![STUB_SUBINTENT_HASH]
            } else {
                Vec::new()
            };
            Ok(Derived {
                // A stub derives no tree, so the envelope's own window
                // is the whole of it.
                effective_window: vm.validity_window(),
                // The stub cannot derive an address from a key, so it
                // binds the signer to the payer field — every stubbed
                // transaction's payer admits its signer.
                signer: vm.fee_payer,
                owners: vec![vm.fee_payer.address()],
                fee_vault_local: [0xEE; 16],
                auth_cell_local: [0xAE; 16],
                routing: Routing {
                    read_keys: vec![DeclaredKey::substate(test_prefix(0x11), [0u8; 16])],
                    write_keys: vec![DeclaredKey::substate(test_prefix(0x22), [0x01; 16])],
                    read_prefixes: vec![Address::new([0x11; 31], AddressClass::Component)],
                    write_prefixes: vec![Address::new([0x22; 31], AddressClass::Component)],
                    provision_keys: vec![DeclaredKey::substate(test_prefix(0x11), [0u8; 16])],
                    provision_prefixes: vec![Address::new([0x11; 31], AddressClass::Component)],
                    declared_modes: vec![
                        (
                            DeclaredKey::substate(test_prefix(0x11), [0u8; 16]),
                            Mode::Read,
                        ),
                        (
                            DeclaredKey::substate(test_prefix(0x22), [0x01; 16]),
                            Mode::Write { moves: Moves::Both },
                        ),
                    ],
                },
                subintent_hashes,
                work: DeclaredWork::ZERO,
                shares: Vec::new(),
                node_terms: Vec::new(),
                everywhere: DeclaredWork::ZERO,
                legs: Vec::new(),
                nullifiers: Vec::new(),
                packages: Vec::new(),
            })
        }
    }

    /// The network every fixture in this module signs for.
    const TEST_NETWORK: NetworkId = NetworkId(242);

    fn test_envelope(tree: &[u8]) -> TransactionEnvelope {
        unsigned_envelope(tree).sign(&Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap())
    }

    fn unsigned_envelope(tree: &[u8]) -> TransactionEnvelope {
        let range = test_validity_range();
        TransactionEnvelope {
            body: TransactionBody::Call(tree.to_vec()),
            subintent_sigs: Vec::new(),
            fee_payer: PrincipalAddr::new([0xAA; 31]),
            max_fee: 1_000,
            gas_limits: vec![1_000_000],
            priority_bp: 0,
            validity_start_ms: range.start_timestamp_inclusive.as_millis(),
            validity_end_ms: range.end_timestamp_exclusive.as_millis(),
            message: Vec::new(),
            network: TEST_NETWORK,
            signer_scheme: SchemeId::NONE,
            signer: Vec::new(),
            signature: Vec::new(),
        }
    }

    fn fixture(tree: &[u8]) -> Transaction {
        Transaction::new(test_envelope(tree))
    }

    /// The verification context every test here judges against: this
    /// module's stub derivation on the fixture network.
    fn ctx(network: NetworkId) -> TransactionContext<'static> {
        TransactionContext {
            network,
            derivation: &StubStatics,
        }
    }

    /// A transaction's share of the sweep budget is read at a placement:
    /// a nullifier follows its signer, an edge across two shards costs
    /// the producer's shard its record and the consumer's its claim, and
    /// the same edge inside one shard costs nothing, since the value
    /// passes directly.
    #[test]
    fn sweepable_writes_are_counted_where_the_placement_puts_them() {
        let tx = fixture(b"tree");
        let base = StubStatics.derive(tx.body()).expect("the stub derives");
        let sender = Address::new([0x00; 31], AddressClass::Component);
        let recipient = Address::new([0xFF; 31], AddressClass::Component);
        let leg = |target, edges| LegShape {
            target,
            role: LegRole::Inbound,
            edges,
            presents: Vec::new(),
            declares: Vec::new(),
            intent: SubintentHash(Hash32([0x5A; 32])),
            local: 0,
            expiry_ms: 0,
        };
        let edge = ValueEdge {
            source: 0,
            output: 0,
            non_fungible: false,
        };
        let _ = tx.derived.set(Derived {
            legs: vec![leg(sender, Vec::new()), leg(recipient, vec![edge])],
            nullifiers: vec![SubstateKey {
                owner: sender,
                local: LocalKey([1; 16]),
            }],
            ..base
        });

        let split = ShardTrie::from_leaves([ShardId::leaf(1, 0), ShardId::leaf(1, 1)]);
        let (from, to) = (
            split.shard_for_prefix(sender),
            split.shard_for_prefix(recipient),
        );
        assert_ne!(from, to, "the ends must sit apart for the edge to cross");
        assert_eq!(
            tx.sweepable_writes_on(&split, from),
            2,
            "the nullifier and the record"
        );
        assert_eq!(tx.sweepable_writes_on(&split, to), 1, "the claim");

        let whole = ShardTrie::uniform_from_count(1);
        let only = whole.shard_for_prefix(sender);
        assert_eq!(whole.shard_for_prefix(recipient), only);
        assert_eq!(
            tx.sweepable_writes_on(&whole, only),
            1,
            "the nullifier alone: an edge inside one shard writes no escrow"
        );
    }

    #[test]
    fn roundtrip_preserves_hash_and_body() {
        let tx = fixture(b"graph bytes");
        let bytes = hbor_to_vec(&tx).unwrap();
        let decoded: Transaction = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.hash(), tx.hash());
        assert_eq!(decoded.try_body().unwrap(), tx.body());
    }

    #[test]
    fn admission_keys_come_from_the_derivation() {
        let tx = fixture(b"graph bytes");
        tx.try_derived(&StubStatics).expect("the stub routes it");
        assert_eq!(
            tx.admission_read_keys(),
            vec![DeclaredKey::substate(test_prefix(0x11), [0u8; 16])]
        );
        assert_eq!(
            tx.admission_write_keys(),
            vec![DeclaredKey::substate(test_prefix(0x22), [0x01; 16])]
        );
        assert!(!tx.is_cross_shard(1));
    }

    #[test]
    fn the_validity_window_is_the_derived_one() {
        // The envelope's window is the composer's claim; the window the
        // transaction actually has is the derivation's, because a bound
        // subintent may have offered a tighter one. With nothing bound
        // they agree, and that agreement is what this pins.
        let tx = fixture(b"graph bytes");
        tx.try_derived(&StubStatics).expect("the stub derives");
        assert_eq!(tx.validity_range(), test_validity_range());
    }

    #[test]
    fn verification_checks_signature_and_derivation() {
        let good = fixture(b"graph bytes");
        assert!(good.verify(ctx(TEST_NETWORK)).is_ok());

        // A tampered signature refuses.
        let mut vm = good.body().clone();
        vm.signature[0] ^= 1;
        let bad_signature = Transaction::new(vm);
        assert_eq!(
            bad_signature.verify(ctx(TEST_NETWORK)).unwrap_err(),
            TransactionVerifyError::InvalidSignature
        );

        // A refused tree surfaces the derivation error.
        let inadmissible = fixture(b"inadmissible");
        assert!(matches!(
            inadmissible.verify(ctx(TEST_NETWORK)).unwrap_err(),
            TransactionVerifyError::Derivation(_)
        ));

        // Garbage in the body field is an undecodable body, not a panic.
        let mut bytes = fixture(b"graph bytes").serialized_bytes().to_vec();
        bytes.truncate(3);
        let garbage = Transaction {
            serialized_bytes: bytes,
            body: OnceLock::new(),
            derived: OnceLock::new(),
            hash: OnceLock::new(),
            cached_bytes: OnceLock::new(),
        };
        assert_eq!(
            garbage.verify(ctx(TEST_NETWORK)).unwrap_err(),
            TransactionVerifyError::UndecodableBody
        );
    }

    /// A transaction signed for one network fails verification under
    /// another's session — before its signature is even consulted, and
    /// re-targeting it breaks the signature since the network is signed
    /// content.
    #[test]
    fn verification_refuses_a_foreign_networks_transaction() {
        let tx = fixture(b"graph bytes");
        assert!(tx.verify(ctx(TEST_NETWORK)).is_ok());
        assert_eq!(
            tx.verify(ctx(NetworkId(7))).unwrap_err(),
            TransactionVerifyError::WrongNetwork {
                signed: TEST_NETWORK.0,
                session: 7,
            }
        );

        let mut retargeted = tx.body().clone();
        retargeted.network = NetworkId(7);
        assert_eq!(
            Transaction::new(retargeted)
                .verify(ctx(NetworkId(7)))
                .unwrap_err(),
            TransactionVerifyError::InvalidSignature,
        );
    }

    /// Any registered scheme signs an envelope that survives the wire and
    /// verifies at the other end — including one whose material is
    /// kilobytes rather than tens of bytes.
    #[test]
    fn an_envelope_signed_under_any_registered_scheme_round_trips() {
        let ed = unsigned_envelope(b"graph bytes")
            .sign(&Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap());
        let secp = unsigned_envelope(b"graph bytes")
            .sign(&Secp256k1PrivateKey::from_bytes(&[7u8; 32]).unwrap());
        let ml_dsa = unsigned_envelope(b"graph bytes")
            .sign(&MlDsa65PrivateKey::from_bytes(&[7u8; 32]).unwrap());

        assert_eq!(ed.signer_scheme, SchemeId::ED25519);
        assert_eq!(secp.signer_scheme, SchemeId::SECP256K1);
        assert_eq!(ml_dsa.signer_scheme, SchemeId::ML_DSA_65);

        for envelope in [ed, secp, ml_dsa] {
            let bytes = hbor_to_vec(&Transaction::new(envelope)).unwrap();
            let carried: Transaction = hbor_from_slice(&bytes).unwrap();
            carried
                .verify(ctx(TEST_NETWORK))
                .expect("what a registered scheme signed verifies under it");
        }
    }

    /// The scheme rides inside the preimage, so re-tagging signed material
    /// to the other registered scheme loses the signature that covered it.
    /// The re-tagged envelope still decodes: this is a signature verdict,
    /// not a codec one.
    #[test]
    fn re_tagging_between_schemes_loses_the_signature() {
        let ed = unsigned_envelope(b"graph bytes")
            .sign(&Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap());
        let secp = unsigned_envelope(b"graph bytes")
            .sign(&Secp256k1PrivateKey::from_bytes(&[7u8; 32]).unwrap());
        let ml_dsa = unsigned_envelope(b"graph bytes")
            .sign(&MlDsa65PrivateKey::from_bytes(&[7u8; 32]).unwrap());

        for (envelope, other) in [
            (ed, SchemeId::SECP256K1),
            (secp, SchemeId::ML_DSA_65),
            (ml_dsa, SchemeId::ED25519),
        ] {
            let mut retagged = envelope;
            retagged.signer_scheme = other;
            let bytes = hbor_to_vec(&Transaction::new(retagged)).unwrap();
            let carried: Transaction = hbor_from_slice(&bytes).unwrap();
            carried
                .try_body()
                .expect("a re-tagged envelope still decodes");
            assert_eq!(
                carried.verify(ctx(TEST_NETWORK)).unwrap_err(),
                TransactionVerifyError::InvalidSignature,
            );
        }
    }

    #[test]
    fn verification_checks_subintent_signatures() {
        // A subintent signature must cover the derived declaration hash.
        let subintent_key = Ed25519PrivateKey::from_bytes(&[9u8; 32]).unwrap();
        let composer_key = Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
        let mut envelope = test_envelope(b"with-subintent");
        envelope.subintent_sigs = vec![SubintentSig {
            scheme: SchemeId::ED25519,
            public_key: subintent_key.public_key().0.to_vec(),
            signature: subintent_key.sign(STUB_SUBINTENT_HASH).0.to_vec(),
        }];
        let composed = envelope.sign(&composer_key);
        assert!(
            Transaction::new(composed.clone())
                .verify(ctx(TEST_NETWORK))
                .is_ok()
        );

        let mut forged = composed;
        forged.subintent_sigs[0].signature[0] ^= 1;
        let forged = forged.sign(&composer_key);
        assert_eq!(
            Transaction::new(forged)
                .verify(ctx(TEST_NETWORK))
                .unwrap_err(),
            TransactionVerifyError::InvalidSubintentSignature(0)
        );
    }

    #[test]
    fn the_envelope_hash_covers_the_signed_window() {
        // Identical content in different windows is two transactions —
        // the signed window is the natural discriminator dedup keys on;
        // byte-identical envelopes stay one transaction.
        let key = Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
        let base = test_envelope(b"graph bytes");
        let mut shifted = base.clone();
        shifted.validity_start_ms += 1;
        let shifted = shifted.sign(&key);
        assert_ne!(
            Transaction::new(base.clone()).hash(),
            Transaction::new(shifted).hash()
        );
        assert_eq!(
            Transaction::new(base.clone()).hash(),
            Transaction::new(base).hash()
        );
    }

    #[test]
    fn decoded_hash_is_the_signing_hash_not_a_wire_value() {
        // The hash isn't on the wire; decode pulls only `serialized_bytes`
        // and the lazy `hash()` call derives the signing hash from them.
        let tx = fixture(b"graph bytes");
        let bytes = hbor_to_vec(&tx).unwrap();
        let decoded: Transaction = hbor_from_slice(&bytes).unwrap();
        let expected = TxHash::from(decoded.body().signing_hash());
        assert_eq!(decoded.hash(), expected);
    }

    #[test]
    fn a_rerolled_signature_is_the_same_transaction() {
        // The identity covers what the composer signed and nothing else,
        // so an envelope differing only in its signature bytes — a
        // signer re-rolling a nonce, a scheme with malleable encodings —
        // deduplicates to one transaction, and the fresh keys it roots
        // cannot be minted twice under two identities.
        let key = Ed25519PrivateKey::from_bytes(&[9u8; 32]).unwrap();
        let signed = test_envelope(b"graph bytes").sign(&key);
        let mut rerolled = signed.clone();
        rerolled.signature[0] ^= 0xFF;
        assert_ne!(signed.signature, rerolled.signature);
        assert_eq!(
            Transaction::new(signed).hash(),
            Transaction::new(rerolled).hash(),
        );
    }

    #[test]
    fn decode_rejects_oversized_tx_bytes() {
        // Hand-roll a payload whose `serialized_bytes` length prefix
        // exceeds MAX_ENVELOPE_BYTES. The bound check must fire before
        // allocating the full Vec.
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_ENVELOPE_BYTES + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_ENVELOPE_BYTES + 1));
        let err = hbor_from_slice::<Transaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_ENVELOPE_BYTES && actual == MAX_ENVELOPE_BYTES + 1
        ));
    }

    #[test]
    fn decode_rejects_the_declared_set_shape() {
        // Hand-roll a wire layout carrying envelope bytes plus declared
        // read/write sets and a mirrored validity range, to confirm a
        // peer can't ship fields the derivation owns.
        let tx = fixture(b"graph bytes");
        let mut buf = hbor_to_vec(&tx).unwrap();
        buf.extend_from_slice(&hbor_to_vec(&Vec::<[u8; 16]>::new()).unwrap());
        buf.extend_from_slice(&hbor_to_vec(&Vec::<[u8; 16]>::new()).unwrap());
        buf.extend_from_slice(&hbor_to_vec(&0u64).unwrap());
        let err = hbor_from_slice::<Transaction>(&buf).unwrap_err();
        assert!(matches!(err, DecodeError::TrailingBytes { .. }));
    }
}
