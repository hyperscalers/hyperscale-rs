//! The envelope's static derivation: the tree's decode seam and the
//! [`Derivation`] implementation admission verifies through.
//!
//! The tree travels as canonical HBOR of the vocabulary's own types, so
//! what this module owns is the call and the refusal a malformed tree
//! maps to, not an encoding. Derivation is `decode → admit → route` over
//! whatever the node holds — [`records`](crate::records) is where that
//! lives, and this module only asks it — rooted at the envelope's
//! signing hash, projected into the workspace's admission vocabulary:
//! substate-granular keys for point effects, interval-granular keys for
//! collection effects (an entry is its width-one interval), reads and
//! snapshots in the shared class, every other mode exclusive. Subintent
//! nullifier creation writes ride the routed sets, so admission
//! conflicts on them like any other exclusive key.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock, OnceLock};

use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_types::{
    DeclaredKey, DeclaredRange, Derivation, DerivationError, Derived, EnvelopeExt, Hash,
    MAX_STATE_ENTRIES_PER_TX, MAX_SUBINTENT_VALIDITY_RANGE, ProtocolStatics, Routing,
    TimestampRange, TransactionEnvelope, WeightedTimestamp, declared_work,
};
use hyperscale_vm_effects::vocabulary::{AUTH, CONFIG, VAULT};
use hyperscale_vm_effects::{
    AdmittedTree, ChainRecords, Claim, CrossingSite, EnvelopeTree, IntentHeader, ManifestHash,
    PackageHash, PrefixShardResolver, Routing as RoutedTransaction, RuleBytes, Value, admit_tree,
    child_key, effect_units, footprint, legs_of, package_hash,
    package_key as canonical_package_key, principal_address, route_tree, xrd,
};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_stdlib::staking;
use hyperscale_vm_types::{
    Address, Effect, EffectSet, EffectTarget, LegShape, Mode, Moves, PrincipalAddr, ResourceAddr,
    SchemeId, SubstateKey,
};

use crate::ProtocolHasher;
use crate::artifact::admit_package;
use crate::records::{
    InstanceCache, LocalCells, NodeRecords, PackageCache, committed_package, record_cell,
    sweepable_cell,
};

/// The parties a transaction's routing declares beyond any node's
/// frame: the payer, whose vault the reservation and the burn reach,
/// and every signer, whose nullifier a bound subintent writes. Sorted
/// and unique, so two derivations of one envelope agree byte for byte.
fn route_owners(
    vm: &TransactionEnvelope,
    signer: PrincipalAddr,
    admitted: &AdmittedTree,
) -> Vec<Address> {
    [vm.fee_payer.address(), signer.address()]
        .into_iter()
        .chain(
            admitted
                .subintents
                .iter()
                .map(|record| record.signer.address()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The record cell of every value edge among `legs`, in `(producer,
/// output)` order.
///
/// Every edge, not only the ones that turn out to cross: which cross is
/// a placement fact read at an anchor, while the cells are fixed by what
/// each producing node's own signer signed — the intent, the node's index
/// within it, and that intent's expiry — so two compositions of one
/// subintent derive the same record for its nodes.
#[must_use]
pub fn crossing_records(legs: &[LegShape]) -> Vec<SubstateKey> {
    let mut records: Vec<((u32, u32), SubstateKey)> = legs
        .iter()
        .flat_map(|consumer| &consumer.edges)
        .filter_map(|edge| {
            let producer = legs.get(edge.source as usize)?;
            let record = CrossingSite::record_of(&ProtocolHasher, producer, edge.output).key();
            Some(((edge.source, edge.output), record))
        })
        .collect();
    records.sort_unstable_by_key(|(edge, _)| *edge);
    records.into_iter().map(|(_, record)| record).collect()
}

/// What a manifest transaction declares it will touch, priced on the
/// engine's own schedule.
///
/// The declaration spans every shard it routes to, because the
/// reservation is taken once against the whole of it — and every value
/// edge's record and claim beside it, which the engine declares at
/// prepare wherever the edge turns out to cross: placement is a fact of
/// the anchor, and the price is fixed when the envelope is composed.
/// With the fixed charge for carrying the transaction and the ceiling
/// it signed for its own execution, this is its work.
#[must_use]
pub fn declared_footprint(routing: &RoutedTransaction, legs: &[LegShape]) -> u64 {
    routing
        .per_shard
        .values()
        .fold(0u64, |total, set| total.saturating_add(footprint(set)))
        .saturating_add(crossing_cells_footprint(legs))
}

/// The footprint of the cells a transaction's value edges write.
///
/// The record under the producer and the claim under the consumer, each
/// a point write on the effects schedule, for every edge whether or not
/// it crosses at any placement.
#[must_use]
pub fn crossing_cells_footprint(legs: &[LegShape]) -> u64 {
    crossing_records(legs)
        .into_iter()
        .fold(0u64, |total, record| {
            let cell = effect_units(Effect {
                target: EffectTarget::Point(record),
                mode: Mode::Write { moves: Moves::Both },
            });
            total.saturating_add(cell.saturating_mul(2))
        })
}

/// The protocol fee and transfer resource: the genesis publisher's
/// primary issue.
///
/// A resource like any other, minted by an address no signer reaches —
/// so supply moves only where the protocol writes state directly, and
/// the address sits where a hash puts it, on no shard by preference.
pub static XRD: LazyLock<ResourceAddr> = LazyLock::new(|| xrd(&ProtocolHasher));

/// The vault cell for `resource` under `owner` — the same child key the
/// stdlib account metadata's effect clauses compute.
#[must_use]
pub fn vault_key(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The stored-authority cell under `owner` — what `securify` writes,
/// `authorize` reads, and the payer shard's binding verdict consults.
#[must_use]
pub fn auth_key(owner: impl Into<Address>) -> SubstateKey {
    child_key(&ProtocolHasher, owner, AUTH, &[])
}

/// A stake pool's record of one validator it operates: the cell the
/// pool's operator methods declare, keyed by the validator.
///
/// Non-empty means the pool took this validator on and holds the key it
/// registered. The methods that speak about an existing validator read
/// it, so genesis has to write it for members the beacon created before
/// the contract existed.
#[must_use]
pub fn validator_key(pool: impl Into<Address>, validator: u64) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        pool,
        staking::VALIDATORS,
        &[Value::U64(validator).canonical_bytes()],
    )
}

/// A lottery's settled-round cell: where its `draw` records the
/// transaction's randomness beside the entrant it selected. Mirrors the
/// effect signature the method declares.
#[must_use]
pub fn draw_key(lottery: impl Into<Address>) -> SubstateKey {
    child_key(&ProtocolHasher, lottery, lottery::OUTCOME, &[])
}

/// The lottery's round cell: the seal a close writes and a settlement
/// opens. Eight bytes, the epoch the kernel stamped, little-endian.
#[must_use]
pub fn round_key(lottery: impl Into<Address>) -> SubstateKey {
    child_key(&ProtocolHasher, lottery, lottery::ROUND, &[])
}

/// An instance's configuration leaf: the seal its instantiation writes.
///
/// Holds the whole creation-fixed record, and its presence is what makes
/// the component actual — every method the package declares reads it
/// under a presence condition, and the one write the slot admits is
/// refused where the leaf is already there.
#[must_use]
pub fn config_key(owner: impl Into<Address>) -> SubstateKey {
    child_key(&ProtocolHasher, owner, CONFIG, &[])
}

/// Where `publisher`'s copy of the package addressed by `package` lives:
/// the vocabulary's own derivation, bound to the protocol hasher.
#[must_use]
pub fn package_key(publisher: impl Into<Address>, package: PackageHash) -> SubstateKey {
    canonical_package_key(&ProtocolHasher, publisher, package)
}

/// The principal address `public_key` opens under `scheme`, or `None` if
/// the scheme registers nothing or gives its keys another width.
///
/// The address commits to the key and the scheme, so genesis funding,
/// transaction builders and admission all derive the same address from
/// the same key — and admission verifies a signer against its target by
/// recomputing this, with nothing to look up. Material no registered
/// scheme claims opens no account at all, so a key that arrives under the
/// wrong tag derives nothing rather than deriving somewhere unreachable.
#[must_use]
pub fn principal_for(scheme: SchemeId, public_key: &[u8]) -> Option<PrincipalAddr> {
    scheme
        .spec()
        .filter(|spec| spec.admits_key(public_key))
        .map(|_| principal_address(&ProtocolHasher, scheme, public_key))
}

/// The principal address an ed25519 public key opens — the ed25519 case
/// of [`principal_for`], for the callers that hold a typed key.
#[must_use]
pub fn account_address(public_key: &[u8; 32]) -> PrincipalAddr {
    principal_address(&ProtocolHasher, SchemeId::ED25519, public_key)
}

/// Encode an envelope tree to its canonical bytes.
///
/// The vocabulary owns its codec; this is the seam's name for it.
///
/// # Panics
///
/// On a tree past the vocabulary's own caps — one no admission path can
/// have accepted.
#[must_use]
pub fn encode_tree(tree: &EnvelopeTree) -> Vec<u8> {
    hbor_to_vec(tree).expect("a tree within its caps encodes")
}

/// Decode wire bytes into an envelope tree.
///
/// # Errors
///
/// [`DerivationError`] on malformed or non-canonical bytes.
pub fn decode_tree(bytes: &[u8]) -> Result<EnvelopeTree, DerivationError> {
    hbor_from_slice(bytes)
        .map_err(|error| DerivationError::Refused(format!("tree decode: {error}")))
}

/// The window the transaction is admissible in, and the header rules
/// that decide it.
///
/// Every intent names the network and window its own signer declared it
/// for. The network must match the envelope's exactly — an intent binds
/// only into a composition for the network it was signed for — while a
/// window only ever narrows: the answer is the intersection of the
/// envelope's with every intent's, and an empty one is a composition no
/// signer agreed to.
///
/// The root is no special case. Its window folds in like any other, so a
/// composer who states a tighter one on their own intent than on the
/// envelope gets the tighter one, and a wider one buys nothing. That is
/// what a narrowing rule gives for free, where an equality rule would
/// have made a signed field mean one thing in the root and another
/// everywhere else.
///
/// Checked against the envelope rather than against the session's
/// network, and against no clock at all, because a derivation that read
/// either would stop being a pure function of the envelope. The
/// session's own check on the envelope covers the tree transitively, and
/// the anchor check runs once, on the window returned here.
fn effective_window(
    vm: &TransactionEnvelope,
    tree: &EnvelopeTree,
) -> Result<TimestampRange, DerivationError> {
    let mut window = vm.validity_window();
    let headers = std::iter::once(&tree.root.header).chain(
        tree.subintents
            .iter()
            .map(|subintent| &subintent.decl.header),
    );
    for (index, header) in headers.enumerate() {
        let named = || {
            if index == 0 {
                "the root intent".to_string()
            } else {
                format!("subintent {}", index - 1)
            }
        };
        if header.network != vm.network {
            return Err(DerivationError::Refused(format!(
                "{} names a different network than the envelope",
                named()
            )));
        }
        let offered = window_of(header);
        if !offered.is_well_formed_length(MAX_SUBINTENT_VALIDITY_RANGE) {
            return Err(DerivationError::Refused(format!(
                "{} stands for longer than an intent may",
                named()
            )));
        }
        window = window.intersect(offered).ok_or_else(|| {
            DerivationError::Refused(format!(
                "{} shares no window with the transaction binding it",
                named()
            ))
        })?;
    }
    Ok(window)
}

/// A header's window in the workspace's clock vocabulary. The VM crate
/// holds the milliseconds its signer signed; what they mean is here.
const fn window_of(header: &IntentHeader) -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::from_millis(header.validity_start_ms),
        WeightedTimestamp::from_millis(header.validity_end_ms),
    )
}
/// How a routed declaration lands in the workspace's admission
/// vocabulary: the three key classes, and the mode behind each key.
struct DeclaredAccess {
    read_keys: BTreeSet<DeclaredKey>,
    write_keys: BTreeSet<DeclaredKey>,
    provision_keys: BTreeSet<DeclaredKey>,
    declared_modes: Vec<(DeclaredKey, Mode)>,
}

/// Sort a routed transaction's effects into the classes admission,
/// provisioning, and scheduling each read.
///
/// Fresh reads share, mutations exclude, and a locked read takes no
/// admission key and makes no participant — its target cannot change, so
/// nothing can contend on it. The provision set is what a counterpart
/// shard cannot execute without: fresh reads and read-modify-write
/// priors, never a delta or a reservation, neither of which depends on
/// the value it changes.
///
/// The modes ride alongside rather than being recoverable from the sets,
/// because the sets have collapsed delta, reserve and write into one
/// exclusive class by the time they are built — and which of the three a
/// key holds is exactly what decides whether two transactions may be in
/// flight on it together.
///
/// The price is a debit on `fee_payer`'s vault, and the declaration
/// names it like every other debit: the payer's shard is then a
/// participant by the rule every written shard is one by, whether or
/// not the payer touches a node — a sponsored transaction reaches the
/// shard that charges it — and the charge contends with whatever else
/// reaches the vault on the mode a debit has, commutative with another
/// debit and exclusive with a write.
fn classify_declared_access(
    routing: &RoutedTransaction,
    fee_payer: PrincipalAddr,
) -> DeclaredAccess {
    let mut access = DeclaredAccess {
        read_keys: BTreeSet::new(),
        write_keys: BTreeSet::new(),
        provision_keys: BTreeSet::new(),
        declared_modes: Vec::new(),
    };
    for effect in routing.per_shard.values().flat_map(EffectSet::iter) {
        let key = admission_key(&effect.target);
        match effect.mode {
            Mode::Read => {
                access.read_keys.insert(key);
                access.provision_keys.insert(key);
            }
            Mode::Write { .. } => {
                access.write_keys.insert(key);
                access.provision_keys.insert(key);
            }
            Mode::Delta { .. } | Mode::Reserve { .. } => {
                access.write_keys.insert(key);
            }
        }
        access.declared_modes.push((key, effect.mode));
    }
    let fee_vault = DeclaredKey::Cell(vault_key(fee_payer, *XRD));
    let fee_mode = (fee_vault, Mode::Delta { moves: Moves::Out });
    access.write_keys.insert(fee_vault);
    if !access.declared_modes.contains(&fee_mode) {
        access.declared_modes.push(fee_mode);
    }
    access.declared_modes.sort_unstable();
    access
}

/// Refuse a declaration whose provisions could outgrow one bundle.
///
/// The wire codec refuses a provision bundle past
/// [`MAX_STATE_ENTRIES_PER_TX`], so a declaration that could ask for
/// more is refused here — at admission, before an honest server does
/// enumeration work a bundle it cannot encode would throw away. A cell
/// serves one entry; a range serves at most its declared cap.
fn check_provision_weight(provision_keys: &BTreeSet<DeclaredKey>) -> Result<(), DerivationError> {
    let weight: usize = provision_keys
        .iter()
        .map(|key| match key {
            DeclaredKey::Cell(_) => 1,
            DeclaredKey::Range(range) => usize::try_from(range.cap).unwrap_or(usize::MAX),
        })
        .fold(0, usize::saturating_add);
    if weight > MAX_STATE_ENTRIES_PER_TX {
        return Err(DerivationError::Refused(format!(
            "declared provisions could serve {weight} entries, past the \
             {MAX_STATE_ENTRIES_PER_TX} one bundle may carry"
        )));
    }
    Ok(())
}

/// The admission key for one effect target: substate-granular for
/// points, interval-granular for collection targets — an entry is its
/// width-one interval.
const fn admission_key(target: &EffectTarget) -> DeclaredKey {
    match target {
        EffectTarget::Point(key) => DeclaredKey::Cell(*key),
        EffectTarget::Entry {
            owner,
            collection,
            order,
        } => DeclaredKey::Range(DeclaredRange {
            owner: *owner,
            collection: *collection,
            lo: *order,
            hi: *order,
            cap: 1,
        }),
        EffectTarget::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => DeclaredKey::Range(DeclaredRange {
            owner: *owner,
            collection: *collection,
            lo: *lo,
            hi: *hi,
            cap: *cap,
        }),
    }
}

/// The envelope's identity: its signing hash through the workspace's
/// protocol hash, as the vocabulary's hash type.
#[must_use]
pub fn envelope_identity(vm: &TransactionEnvelope) -> ManifestHash {
    ManifestHash(vm.signing_hash().as_hash32())
}

/// A consumer of committed package artifacts — the engine's compile
/// pipeline registers one so a package's code is being compiled from the
/// moment its cell commits, not from its first call.
pub type ArtifactSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// The bridge's [`Derivation`]: `decode → admit → route` over the
/// process's genesis-static metadata.
pub struct BridgeStatics {
    /// Published package metadata, growing as blocks commit.
    pub cache: PackageCache,
    /// The instances the chain answers for, growing as blocks commit.
    pub instances: InstanceCache,
    /// Where a committed package's artifact bytes are handed on, beside
    /// the metadata absorption.
    pub artifact_sink: Option<ArtifactSink>,
    /// This node's own committed state, once it has one.
    ///
    /// Installed by the host, which is the only thing that knows which
    /// shards it serves. Empty on an engine with no node behind it — a
    /// composer, a test, a genesis tool — which answers from its caches
    /// alone and has no state to fall back on.
    pub cells: OnceLock<Arc<dyn LocalCells>>,
}

impl BridgeStatics {
    /// What this node answers for, pinned for one derivation: its caches
    /// and, behind them, its own committed state.
    #[must_use]
    pub fn records(&self) -> NodeRecords {
        NodeRecords::pinned(&self.cache, &self.instances, self.cells.get().cloned())
    }

    /// Tell this node where its own committed state is. The first
    /// installation stands; a node has one state.
    pub fn install_cells(&self, cells: Arc<dyn LocalCells>) {
        let _ = self.cells.set(cells);
    }
}

/// The component targets `tree` names that neither committed state nor
/// the tree's own records resolve.
///
/// A gap rather than a verdict: the addresses derive, and the shard
/// holding each one's seal can answer for it. Collected whole, in the
/// order the flattened manifest names them, so the answer is stable
/// wherever it is computed.
fn unresolved_targets(tree: &EnvelopeTree, chain: &dyn ChainRecords) -> Vec<Address> {
    let carried: BTreeSet<Address> = tree
        .instances
        .iter()
        .map(|meta| meta.address(&ProtocolHasher).address())
        .collect();
    let mut missing = Vec::new();
    let graphs = std::iter::once(&tree.root.graph).chain(
        tree.subintents
            .iter()
            .map(|subintent| &subintent.decl.graph),
    );
    for node in graphs.flat_map(|graph| &graph.nodes) {
        let address = node.target.address();
        if chain.instance(node.target).is_some() || carried.contains(&address) {
            continue;
        }
        if !missing.contains(&address) {
            missing.push(address);
        }
    }
    missing
}

impl BridgeStatics {
    /// A publish's routing: an exclusive write on the package cell, and
    /// one on the publisher's fee vault.
    ///
    /// The vault is declared even though no signature asks for it. A
    /// completed transaction burns its fee there, and declaring it is
    /// what makes two publishes by one payer conflict — without it they
    /// share a block and settle two burns against one cell, which is the
    /// exposure a call transaction avoids only because its own withdraw
    /// happens to name the same vault.
    fn derive_publish(
        vm: &TransactionEnvelope,
        signer: PrincipalAddr,
        artifact: &[u8],
    ) -> Result<Derived, DerivationError> {
        if !vm.subintent_sigs.is_empty() {
            return Err(DerivationError::Refused(
                "a publish carries no subintents".into(),
            ));
        }
        // The artifact has to describe itself before it is addressed:
        // what the address covers is code and signatures together, so an
        // artifact that declares nothing is not a package.
        admit_package(artifact)?;

        let publisher = vm.fee_payer;
        let package = package_hash(&ProtocolHasher, artifact);
        let cell = package_key(publisher, package);
        let vault = vault_key(publisher, *XRD);
        let mut write_keys = vec![DeclaredKey::Cell(cell), DeclaredKey::Cell(vault)];
        write_keys.sort_unstable();
        write_keys.dedup();

        // A publish never reaches the kernel, so it declares no effects
        // for `footprint` to price. Its footprint stands in as the two
        // exclusive cells it claims plus the artifact it writes whole
        // into state — the largest transaction the protocol admits, and
        // one the declared side would otherwise price as the smallest.
        let footprint = (write_keys.len() as u64).saturating_add(artifact.len() as u64);
        let work = declared_work(footprint, vm.gas_limit, vm.signature_work());

        Ok(Derived {
            // A publish carries no tree, so nothing narrows the window
            // its composer signed and nothing binds a subintent.
            effective_window: vm.validity_window(),
            work,
            footprint,
            // No manifest, so nothing to divide, nothing crossing, and no
            // subintent bound; the publisher pays and signs.
            legs: Vec::new(),
            owners: [publisher.address(), signer.address()]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            nullifiers: Vec::new(),
            signer,
            routing: Routing {
                read_prefixes: Vec::new(),
                write_prefixes: vec![publisher.address()],
                provision_prefixes: Vec::new(),
                read_keys: Vec::new(),
                declared_modes: write_keys
                    .iter()
                    .map(|key| (*key, Mode::Write { moves: Moves::Both }))
                    .collect(),
                write_keys,
                provision_keys: Vec::new(),
            },
            subintent_hashes: Vec::new(),
            fee_vault_local: vault.local.0,
            auth_cell_local: auth_key(publisher).local.0,
            // A publish runs no package: it writes one and calls nothing.
            packages: Vec::new(),
        })
    }
}

impl Derivation for BridgeStatics {
    fn absorb_committed_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) {
        let Ok(owner) = Address::from_bytes(owner) else {
            return;
        };
        if self.cache.absorb_cell(owner, local, value)
            && let Some(sink) = &self.artifact_sink
        {
            sink(value);
        }
        self.instances.absorb_cell(owner, local, value);
    }

    fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError> {
        // The identity the envelope's own signature opens: what the root
        // intent presents as evidence, and the identity the payer's rule
        // must admit. Whether it does is the payer shard's verdict —
        // taken where the payer's state is, as a condition of the fee
        // reservation engaging — so derivation records the identity and
        // never compares it against the payer field.
        let Some(signer) = principal_for(vm.signer_scheme, &vm.signer) else {
            return Err(DerivationError::Refused(
                "the envelope's signer key derives no principal".into(),
            ));
        };
        if let Some(artifact) = vm.artifact() {
            return Self::derive_publish(vm, signer, artifact);
        }
        let tree = decode_tree(vm.call_tree().unwrap_or_default())?;
        let effective_window = effective_window(vm, &tree)?;
        if vm.subintent_sigs.len() != tree.subintents.len() {
            return Err(DerivationError::Refused(format!(
                "envelope binds {} subintents but carries {} signatures",
                tree.subintents.len(),
                vm.subintent_sigs.len()
            )));
        }
        // Bind every declared signer address to its public key; the
        // signatures themselves verify at the transaction gate, over the
        // declaration hashes returned here.
        for (index, (sig, subintent)) in vm.subintent_sigs.iter().zip(&tree.subintents).enumerate()
        {
            if principal_for(sig.scheme, &sig.public_key) != Some(subintent.signer) {
                return Err(DerivationError::Refused(format!(
                    "subintent {index} signer address does not match its public key"
                )));
            }
        }
        // What the chain answers a target with: genesis, grown by every
        // seal that has committed since. Admission layers the tree's own
        // records behind these itself, holding each to standing for the
        // seal of the component it derives.
        //
        // One view for the whole derivation: both caches are read once
        // here and held by refcount, so nothing a block commits partway
        // through can make two lookups in one derivation disagree.
        let chain = self.records();
        // Every target this node holds no record for, named before
        // admission runs. Admission refuses at the first one it meets,
        // and a fetch wants the whole set: one round trip rather than
        // one per component the envelope calls.
        let unresolved = unresolved_targets(&tree, &chain);
        if !unresolved.is_empty() {
            return Err(DerivationError::Unresolved(unresolved));
        }
        let admitted = admit_tree(
            &tree,
            signer,
            envelope_identity(vm),
            &chain,
            &ProtocolHasher,
        )
        .map_err(|error| DerivationError::Refused(format!("admission: {error}")))?;
        let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });

        let DeclaredAccess {
            read_keys,
            write_keys,
            provision_keys,
            declared_modes,
        } = classify_declared_access(&routing, vm.fee_payer);
        check_provision_weight(&provision_keys)?;
        let prefixes = |keys: &BTreeSet<DeclaredKey>| -> Vec<Address> {
            keys.iter()
                .map(DeclaredKey::owner)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        // Every package the lowered calls run, deduplicated — what the
        // execution gate holds the transaction to on each shard.
        let packages: Vec<Hash> = routing
            .calls
            .iter()
            .map(|call| Hash::from(call.package.0))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let legs = legs_of(&admitted.admitted);
        let declared_footprint = declared_footprint(&routing, &legs);
        let work = declared_work(declared_footprint, vm.gas_limit, vm.signature_work());
        Ok(Derived {
            effective_window,
            work,
            footprint: declared_footprint,
            legs,
            nullifiers: admitted
                .subintents
                .iter()
                .map(|record| record.nullifier)
                .collect(),
            owners: route_owners(vm, signer, &admitted),
            signer,
            routing: Routing {
                read_prefixes: prefixes(&read_keys),
                write_prefixes: prefixes(&write_keys),
                provision_prefixes: prefixes(&provision_keys),
                read_keys: read_keys.into_iter().collect(),
                write_keys: write_keys.into_iter().collect(),
                provision_keys: provision_keys.into_iter().collect(),
                declared_modes,
            },
            subintent_hashes: admitted
                .subintents
                .iter()
                .map(|record| record.subintent.0.0)
                .collect(),
            fee_vault_local: vault_key(vm.fee_payer, *XRD).local.0,
            auth_cell_local: auth_key(vm.fee_payer).local.0,
            packages,
        })
    }
}

impl ProtocolStatics for BridgeStatics {
    fn package_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) -> Option<Hash> {
        let owner = Address::from_bytes(owner).ok()?;
        committed_package(owner, local, value).map(|package| Hash::from(package.0))
    }

    fn sweepable_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) -> Option<u64> {
        sweepable_cell(Address::from_bytes(owner).ok()?, local, value)
    }

    fn record_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) -> bool {
        Address::from_bytes(owner).is_ok_and(|owner| record_cell(owner, local, value))
    }

    fn rule_admits(
        &self,
        auth_cell: Option<&[u8]>,
        payer: PrincipalAddr,
        signer: PrincipalAddr,
        clock_ms: u64,
    ) -> bool {
        // The verdict is the kernel gate's own, judged over the envelope
        // signer alone — paying is governed by whatever governs
        // `authorize`, which is the one rule the cell holds.
        let _ = clock_ms;
        match auth_cell {
            // An address with nothing stored governs itself, which is the
            // rule's own second branch rather than anything supplied here.
            None | Some([]) => payer == signer,
            // Bytes that are not a rule admit nobody, the same fail-closed
            // verdict the execution gate gives them — as does a rule
            // asking about a holding, which this judge holds nothing to
            // answer with.
            Some(bytes) => RuleBytes::rule_in_cell(bytes)
                .ok()
                .and_then(|rule| rule.claims_only())
                .is_some_and(|claims| claims.satisfied_by(&[Claim::of_subject(signer)])),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        CallTarget, Ed25519PrivateKey, NetworkId, Secp256k1PrivateKey, TX_UNITS, TransactionBody,
    };
    use hyperscale_vm_effects::vocabulary::VAULT;
    use hyperscale_vm_effects::{
        Binding, Claim, Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, Hash32, Hasher,
        InstanceMeta, InstanceRegistry, IntentDecl, ManifestGraph, MetadataCache, PackageHash,
        Socket, StoredRule, Subintent, SubintentHash, child_key, never, nullifier_expiry_ms,
        nullifier_key, package_slot,
    };
    use hyperscale_vm_manifest_builder::signing::sign_subintent;
    use hyperscale_vm_stdlib::account;
    use hyperscale_vm_types::{AddressClass, CollectionId, LegRole, ResourceAddr};

    use super::*;
    use crate::records::record_address;

    const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
    const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

    fn key(seed: u8) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
    }

    fn composer_addr() -> PrincipalAddr {
        account_address(&key(7).public_key().0)
    }

    fn bob_addr() -> PrincipalAddr {
        account_address(&key(9).public_key().0)
    }

    fn statics() -> BridgeStatics {
        let package = PackageHash(ProtocolHasher.hash(b"package", &[b"account"]));
        let mut cache = MetadataCache::new();
        cache
            .publish(package, account::metadata())
            .expect("the account package publishes");
        let mut instances = InstanceRegistry::new();
        // The composer and its counterparty are principals: their
        // addresses derive from their keys, so nothing is registered for
        // them.
        instances.serve_principals(package);
        BridgeStatics {
            cache: PackageCache::new(cache),
            instances: InstanceCache::new(instances),
            artifact_sink: None,
            cells: OnceLock::new(),
        }
    }

    /// The sign-in every fixture graph leads with: node 0 of its intent,
    /// which is what the withdraw fixtures point their proofs at.
    fn sign_in(target: impl Into<CallTarget>) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: "authorize".into(),
            args: vec![],
            evidence: [EvidenceRef::IntentSignature].into(),
        }
    }

    fn withdraw(target: impl Into<CallTarget>, resource: ResourceAddr, amount: u128) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: "withdraw".into(),
            args: vec![
                GraphArg::Literal(Value::Address(resource.address())),
                GraphArg::Literal(Value::U128(amount)),
            ],
            evidence: [EvidenceRef::Node(0)].into(),
        }
    }

    fn deposit_edge(
        target: impl Into<CallTarget>,
        producer: u32,
        resource: ResourceAddr,
    ) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: "deposit".into(),
            args: vec![GraphArg::Edge {
                edge: EdgeRef {
                    producer,
                    output: 0,
                },
                constraints: vec![Constraint::ResourceIs(resource)],
            }],
            evidence: BTreeSet::new(),
        }
    }

    fn deposit_socket(target: impl Into<CallTarget>, socket: u32) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: "deposit".into(),
            args: vec![GraphArg::Socket(socket)],
            evidence: BTreeSet::new(),
        }
    }

    /// The network every envelope in these tests is signed for.
    const NETWORK: NetworkId = NetworkId(242);

    /// The terms every intent in these tests is declared under: the same
    /// window the envelope helper signs, so nothing narrows and the
    /// intersection is the envelope's own.
    const HEADER: IntentHeader = IntentHeader {
        network: NETWORK,
        validity_start_ms: 0,
        validity_end_ms: 1_000_000,
        discriminator: 0,
    };

    fn single_intent_tree(nodes: Vec<GraphNode>) -> EnvelopeTree {
        EnvelopeTree {
            root: IntentDecl {
                header: HEADER,
                graph: ManifestGraph { nodes },
                sockets: Vec::new(),
            },
            root_bindings: Vec::new(),
            subintents: Vec::new(),
            instances: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// The two-signer composition: the composer pays X for the
    /// subintent's Y.
    fn composed_tree() -> EnvelopeTree {
        EnvelopeTree {
            root: IntentDecl {
                header: HEADER,
                graph: ManifestGraph {
                    nodes: vec![
                        sign_in(composer_addr()),
                        withdraw(composer_addr(), RES_X, 100),
                        deposit_socket(composer_addr(), 0),
                    ],
                },
                sockets: vec![Socket::Value {
                    resource: RES_Y,
                    constraints: vec![Constraint::MinAmount(10)],
                }],
            },
            root_bindings: vec![Binding::Value {
                intent: 1,
                edge: EdgeRef {
                    producer: 1,
                    output: 0,
                },
            }],
            subintents: vec![Subintent {
                decl: IntentDecl {
                    header: HEADER,
                    graph: ManifestGraph {
                        nodes: vec![
                            sign_in(bob_addr()),
                            withdraw(bob_addr(), RES_Y, 10),
                            deposit_socket(bob_addr(), 0),
                        ],
                    },
                    sockets: vec![Socket::Value {
                        resource: RES_X,
                        constraints: vec![Constraint::MinAmount(100)],
                    }],
                },
                signer: bob_addr(),
                bindings: vec![Binding::Value {
                    intent: 0,
                    edge: EdgeRef {
                        producer: 1,
                        output: 0,
                    },
                }],
            }],
            instances: Vec::new(),
            resources: Vec::new(),
        }
    }

    fn envelope(tree: &EnvelopeTree, subintent_keys: &[&Ed25519PrivateKey]) -> TransactionEnvelope {
        let subintent_sigs = tree
            .subintents
            .iter()
            .zip(subintent_keys)
            .map(|(subintent, signer)| {
                let hash = subintent.decl.hash(&ProtocolHasher);
                sign_subintent(*signer, &hash.0.0)
            })
            .collect();
        TransactionEnvelope {
            body: TransactionBody::Call(encode_tree(tree)),
            subintent_sigs,
            fee_payer: composer_addr(),
            max_fee: 1_000,
            gas_limit: 1_000_000,
            validity_start_ms: 0,
            validity_end_ms: 1_000_000,
            message: Vec::new(),
            network: NETWORK,
            signer_scheme: SchemeId::NONE,
            signer: Vec::new(),
            signature: Vec::new(),
        }
        .sign(&key(7))
    }

    /// A transfer divides into a sign-in, a withdraw and a deposit. Its
    /// one value edge is one crossing, whose record sits under the
    /// sender and names the vault the withdraw reserved; and it binds
    /// nothing, so it files no nullifier.
    #[test]
    fn a_transfer_derives_one_crossing_per_value_edge() {
        let tree = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let vm = envelope(&tree, &[]);
        let derived = statics().derive(&vm).expect("derives");

        let roles: Vec<LegRole> = derived.legs.iter().map(|leg| leg.role).collect();
        assert_eq!(
            roles,
            vec![LegRole::Attesting, LegRole::Inbound, LegRole::Outbound]
        );
        let records = crossing_records(&derived.legs);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].owner,
            composer_addr().address(),
            "the record sits under the producing node's target"
        );

        assert!(
            derived.nullifiers.is_empty(),
            "nothing bound, nothing spent"
        );

        // The footprint is the term of the price the declaration fixes,
        // carried whole beside the sum it feeds — and it prices the
        // crossing's record and claim beside what the routing declares.
        let cells = crossing_cells_footprint(&derived.legs);
        assert_eq!(
            cells,
            2 * effect_units(Effect {
                target: EffectTarget::Point(records[0]),
                mode: Mode::Write { moves: Moves::Both },
            }),
            "one record and one claim, each a point write"
        );
        assert!(
            derived.footprint > cells,
            "the routing's own declaration is priced beside them"
        );
        assert_eq!(
            derived.work,
            declared_work(derived.footprint, vm.gas_limit, vm.signature_work())
        );
    }

    /// An escrow cell is keyed by what its node's own signer signed. Two
    /// compositions of one subintent derive the same cells for that
    /// subintent's nodes, and the composer moving the root's own window
    /// moves the root's cells and nobody else's.
    #[test]
    fn escrow_cells_follow_the_signing_intent() {
        let first = composed_tree();
        let mut second = composed_tree();
        second.root.header.validity_end_ms -= 1_000;
        let derive = |tree: &EnvelopeTree| {
            statics()
                .derive(&envelope(tree, &[&key(9)]))
                .expect("derives")
        };
        let (one, other) = (derive(&first), derive(&second));
        let bob = first.subintents[0].decl.hash(&ProtocolHasher);

        // The interleave puts Bob's withdraw at manifest node 3, second
        // in his own intent — and the leg says which of those it is.
        assert_eq!(one.legs[3].intent, bob);
        assert_eq!(one.legs[3].local, 1);
        assert_eq!(one.legs[1].intent, first.root.hash(&ProtocolHasher));

        let record_of = |derived: &Derived, node: usize| {
            CrossingSite::record_of(&ProtocolHasher, &derived.legs[node], 0).key()
        };
        assert_eq!(
            record_of(&one, 3),
            record_of(&other, 3),
            "Bob's record is fixed by Bob's signature"
        );
        assert_ne!(
            record_of(&one, 1),
            record_of(&other, 1),
            "the root's record moves with the root's window"
        );
        assert_eq!(
            one.nullifiers[0], other.nullifiers[0],
            "and so is his nullifier"
        );
    }

    /// Work is what a block pays to carry a transaction: a fixed charge
    /// nobody escapes, plus what it declared, plus what it signed for.
    ///
    /// The fixed term is the part that matters. Without it a minimal
    /// zero-gas transaction would price at almost nothing, and a budget
    /// over work would bound weight while the transaction count — which
    /// is what tick entries, tick-chain entries and receipts scale with
    /// — ran free.
    #[test]
    fn work_prices_the_fixed_cost_of_carrying_a_transaction() {
        let tree = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let derived = statics().derive(&envelope(&tree, &[])).expect("derives");

        // The envelope's own ceiling is in there, and so is a charge no
        // declaration can shrink.
        assert!(
            derived.work > TX_UNITS + 1_000_000,
            "work must carry the fixed charge and the signed limit: {}",
            derived.work
        );

        // A second recipient declares more, so it costs more — nothing
        // else about the two envelopes differs.
        let wider = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
            withdraw(composer_addr(), RES_Y, 10),
            deposit_edge(bob_addr(), 3, RES_Y),
        ]);
        let wider = statics().derive(&envelope(&wider, &[])).expect("derives");
        assert!(
            wider.work > derived.work,
            "a wider declaration must not be cheaper: {} vs {}",
            wider.work,
            derived.work
        );
    }

    /// What a transaction's signatures cost to check is priced with the
    /// rest of what it declares, so a wider scheme is a fee fact rather
    /// than free verification.
    #[test]
    fn work_prices_the_signatures_the_envelope_carries() {
        let tree = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let ed = statics().derive(&envelope(&tree, &[])).expect("derives");

        let secp = Secp256k1PrivateKey::from_bytes(&[7u8; 32]).expect("a scalar in range");
        let payer = principal_for(SchemeId::SECP256K1, &secp.public_key().0)
            .expect("a registered scheme opens an account");
        let secp_tree = single_intent_tree(vec![
            sign_in(payer),
            withdraw(payer, RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let mut wider = envelope(&secp_tree, &[]);
        wider.fee_payer = payer;
        let wider = statics().derive(&wider.sign(&secp)).expect("derives");

        assert!(
            wider.work > ed.work,
            "a wider signature scheme must not verify for free: {} vs {}",
            wider.work,
            ed.work
        );
    }

    #[test]
    fn the_tree_codec_round_trips() {
        let tree = composed_tree();
        let decoded = decode_tree(&encode_tree(&tree)).unwrap();
        assert_eq!(decoded, tree);
        assert!(decode_tree(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn a_transfer_derives_substate_keys_and_owner_prefixes() {
        let tree = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let derived = statics().derive(&envelope(&tree, &[])).expect("derives");

        // Reserve at the sender's vault and deltas at the recipient's:
        // all exclusive-class, substate-granular, under the two owners.
        // One read a side and both of them provisions: the sign-in reads
        // the sender's rule cell, whose absence is what the read carries
        // to every participant, and the deposit reads the recipient's
        // own flag to pick between the vault and the quarantine beside
        // it. Neither is a balance, so the movement stays commutative.
        let sender_vault = child_key(
            &ProtocolHasher,
            composer_addr(),
            VAULT,
            &[Value::Address(RES_X.address()).canonical_bytes()],
        );
        assert!(derived.routing.write_keys.contains(&DeclaredKey::substate(
            composer_addr().address(),
            sender_vault.local.0
        )));
        let rule_cell =
            DeclaredKey::substate(composer_addr().address(), auth_key(composer_addr()).local.0);
        let refused = child_key(
            &ProtocolHasher,
            bob_addr(),
            package_slot(0),
            &[Value::Address(RES_X.address()).canonical_bytes()],
        );
        let landing = DeclaredKey::substate(bob_addr().address(), refused.local.0);
        let mut reads = vec![rule_cell, landing];
        reads.sort_unstable();
        assert_eq!(derived.routing.read_keys, reads);
        assert_eq!(derived.routing.provision_keys, reads);
        let mut provisioning = vec![composer_addr().address(), bob_addr().address()];
        provisioning.sort_unstable();
        assert_eq!(derived.routing.provision_prefixes, provisioning);
        assert!(derived.subintent_hashes.is_empty());
        let mut owners = vec![composer_addr(), bob_addr()];
        owners.sort_unstable();
        assert_eq!(derived.routing.write_prefixes, owners);
    }

    /// One identity, as the bytes a rule parameter carries.
    fn bob_rule() -> Vec<u8> {
        RuleBytes::try_from(&StoredRule::claim(Claim::of_subject(bob_addr())))
            .expect("a rule within the vocabulary caps")
            .bytes()
            .to_vec()
    }

    /// The payer shard's binding verdict across the securify boundary:
    /// absent means the address governs itself, stored bytes mean the one
    /// rule the cell holds, and bytes that are no rule admit nobody.
    #[test]
    fn the_stored_rule_governs_the_payer_binding() {
        let statics = statics();
        let stored = |rule: &StoredRule| {
            RuleBytes::try_from(rule)
                .expect("a rule within the vocabulary caps")
                .in_cell()
        };

        // Virtual: the payer's own identity and no other, whatever the
        // clock says.
        assert!(statics.rule_admits(None, composer_addr(), composer_addr(), 0));
        assert!(statics.rule_admits(Some(&[]), composer_addr(), composer_addr(), u64::MAX));
        assert!(!statics.rule_admits(None, composer_addr(), bob_addr(), 0));

        // Securified to Bob: the old identity is dead, the rule's lives.
        let cell = stored(&StoredRule::claim(Claim::of_subject(bob_addr())));
        assert!(statics.rule_admits(Some(&cell), composer_addr(), bob_addr(), 0));
        assert!(!statics.rule_admits(Some(&cell), composer_addr(), composer_addr(), 0));

        // And the cell is the whole of it. A replacement an account has
        // waiting sits in that package's own cells and moves this binding
        // only once it is enacted here — so no instant a verdict is
        // judged at can part two nodes reading one cell.
        for clock in [0, 4_999, 5_000, u64::MAX] {
            assert!(statics.rule_admits(Some(&cell), composer_addr(), bob_addr(), clock));
            assert!(!statics.rule_admits(Some(&cell), composer_addr(), composer_addr(), clock));
        }

        // A frozen account binds no fees: the rule nobody satisfies is
        // written rather than removed, because an unwritten cell is what
        // the address's own key still governs.
        let frozen = stored(&never());
        assert!(!statics.rule_admits(Some(&frozen), composer_addr(), bob_addr(), 0));
        assert!(!statics.rule_admits(Some(&frozen), composer_addr(), composer_addr(), 0));

        // Bytes no cell decodes from admit nobody — fail closed, like
        // the execution gate. Bare rule bytes are among them: the write
        // path stores frames.
        assert!(!statics.rule_admits(Some(&[0xFF, 0xFF]), composer_addr(), composer_addr(), 0));
        let bare = StoredRule::claim(Claim::of_subject(bob_addr()))
            .to_bytes()
            .unwrap();
        assert!(!statics.rule_admits(Some(&bare), composer_addr(), bob_addr(), 0));
    }

    #[test]
    fn a_composed_envelope_derives_the_nullifier_write() {
        let tree = composed_tree();
        let bob = key(9);
        let derived = statics()
            .derive(&envelope(&tree, &[&bob]))
            .expect("derives");

        let hash = tree.subintents[0].decl.hash(&ProtocolHasher);
        assert_eq!(derived.subintent_hashes, vec![hash.0.0]);
        let nullifier = nullifier_key(
            &ProtocolHasher,
            bob_addr(),
            hash,
            nullifier_expiry_ms(&tree.subintents[0].decl.header),
        );
        assert!(derived.routing.write_keys.contains(&DeclaredKey::substate(
            bob_addr().address(),
            nullifier.local.0
        )));
    }

    #[test]
    fn a_fee_payer_the_composer_does_not_own_derives_unbound() {
        // The whole fee path debits whatever this field names, so
        // whether the payer's rule admits the signer is the payer
        // shard's block-validity verdict, taken where the payer's state
        // is. Derivation refuses nothing here: it records the identity
        // the envelope's key opens, and records it from the key rather
        // than from the payer field — so a stranger naming someone
        // else's account gets their own badge, never the account's.
        let tree = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let mut stolen = envelope(&tree, &[]);
        stolen.fee_payer = bob_addr();
        let stolen = stolen.sign(&key(7));

        assert!(stolen.signature_is_valid(), "the composer signed it");
        let derived = statics().derive(&stolen).expect("derives");
        assert_eq!(
            derived.signer,
            composer_addr(),
            "the recorded identity is the key's, not the payer field's"
        );
        assert_ne!(
            derived.signer, stolen.fee_payer,
            "which is exactly the mismatch the payer shard's verdict reads"
        );
    }

    /// The signer's identity is derived under the scheme the envelope
    /// names, so a second scheme's key opens its own account and the
    /// same seed under two schemes is two accounts.
    #[test]
    fn the_signer_identity_derives_under_the_envelopes_scheme() {
        let secp = Secp256k1PrivateKey::from_bytes(&[7u8; 32]).expect("a scalar in range");
        let payer = principal_for(SchemeId::SECP256K1, &secp.public_key().0)
            .expect("a registered scheme opens an account");
        assert_ne!(
            payer,
            composer_addr(),
            "one seed, two schemes, two accounts"
        );

        let tree = single_intent_tree(vec![
            sign_in(payer),
            withdraw(payer, RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        let mut signed = envelope(&tree, &[]);
        signed.fee_payer = payer;
        let signed = signed.sign(&secp);

        assert!(signed.signature_is_valid());
        let derived = statics().derive(&signed).expect("derives");
        assert_eq!(derived.signer, payer);
    }

    /// A withdrawal from an account the envelope carries no signature for
    /// is refused where it is cheapest to refuse it: the composer's own
    /// badge is what the node presents, an unsecurified account admits a
    /// claim on its own key alone, and both are signed content — so
    /// nothing has to be read to know the answer.
    #[test]
    fn a_withdrawal_from_an_unsigned_account_is_refused() {
        let tree = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(bob_addr(), RES_X, 100),
            deposit_edge(composer_addr(), 1, RES_X),
        ]);
        assert!(statics().derive(&envelope(&tree, &[])).is_err());

        // Reversed, it is the ordinary transfer: the composer withdraws
        // from their own account and Bob is credited without being asked.
        // One signature, because only the spending side is gated.
        let transfer = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        assert!(statics().derive(&envelope(&transfer, &[])).is_ok());
    }

    /// A method writing a leaf under its target's prefix and moving no
    /// funds is exactly the shape that is easy to leave open — so
    /// `securify`, which consumes nothing, is held to the same evidence
    /// rule a withdrawal is.
    #[test]
    fn a_leaf_write_presenting_nothing_is_refused() {
        let node = |evidence: BTreeSet<EvidenceRef>| GraphNode {
            target: composer_addr().into(),
            method: "securify".into(),
            args: vec![
                GraphArg::Literal(Value::Bytes(bob_rule())),
                GraphArg::Literal(Value::Bytes(bob_rule())),
                GraphArg::Literal(Value::Bytes(bob_rule())),
                GraphArg::Literal(Value::U64(86_400_000)),
            ],
            evidence,
        };
        // A guarded method reached with no evidence at all is a defect in
        // the signed form, so derivation refuses it and nobody pays.
        // Whether the evidence a call *does* present satisfies its
        // target is the target's own question, answered at execution.
        let refused = statics()
            .derive(&envelope(
                &single_intent_tree(vec![node(BTreeSet::new())]),
                &[],
            ))
            .expect_err("refuses");
        assert!(
            refused.to_string().contains("evidence"),
            "{}",
            refused.to_string()
        );
        // A signature proof is not this method's to read either: it signs
        // in, and the write takes what the sign-in minted.
        let refused = statics()
            .derive(&envelope(
                &single_intent_tree(vec![node([EvidenceRef::IntentSignature].into())]),
                &[],
            ))
            .expect_err("refuses");
        assert!(
            refused.to_string().contains("signature"),
            "{}",
            refused.to_string()
        );
        assert!(
            statics()
                .derive(&envelope(
                    &single_intent_tree(vec![
                        sign_in(composer_addr()),
                        node([EvidenceRef::Node(0)].into()),
                    ]),
                    &[]
                ))
                .is_ok()
        );
    }

    /// A proof is scoped to the intent whose signature produced it, so a
    /// node draws the identity of its own intent's signer and no other —
    /// which is the mechanism the subintent primitive was built for.
    #[test]
    fn a_proof_carries_its_own_intents_signer() {
        let bob = key(9);
        let derived = statics()
            .derive(&envelope(&composed_tree(), &[&bob]))
            .expect("both sides withdraw from themselves");
        // Nothing about the identities survives into the routing view,
        // so what this pins is that the tree derives at all: each intent
        // presents its own signer, and the withdrawals name those same
        // accounts.
        assert!(!derived.routing.write_keys.is_empty());

        // The same envelope with Bob's withdrawal moved into the
        // composer's intent is refused: the node draws its own intent's
        // signer, so the proof it presents carries the composer, and
        // Bob's account admits a claim on Bob's key alone. Both halves
        // of that are signed content, so the answer is admission's to
        // give rather than execution's.
        let mut stolen = composed_tree();
        stolen.root.graph.nodes[1] = withdraw(bob_addr(), RES_X, 100);
        assert!(statics().derive(&envelope(&stolen, &[&bob])).is_err());
    }

    #[test]
    fn a_mismatched_subintent_signer_is_refused() {
        // The tree binds BOB's address, but the carried key is another's.
        let tree = composed_tree();
        let impostor = key(11);
        let refused = statics().derive(&envelope(&tree, &[&impostor]));
        assert!(refused.is_err());

        // A missing signature list is a distinct refusal.
        let mut unsigned = envelope(&tree, &[&key(9)]);
        unsigned.subintent_sigs.clear();
        assert!(statics().derive(&unsigned).is_err());
    }

    #[test]
    fn an_intent_naming_another_network_is_refused() {
        // A subintent signed for one network, bound into a composition
        // for another. Its signer covered the network, so the binding is
        // a claim about content they never signed — and the nullifier
        // that makes the subintent once-only lives on the network they
        // did name.
        let mut foreign = composed_tree();
        foreign.subintents[0].decl.header.network = NetworkId(1);
        assert!(statics().derive(&envelope(&foreign, &[&key(9)])).is_err());

        // The composer's own intent answers the same rule: an envelope
        // whose root disagrees with the network it names is refused
        // before any signature is read.
        let mut root_foreign = single_intent_tree(vec![
            sign_in(composer_addr()),
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 1, RES_X),
        ]);
        root_foreign.root.header.network = NetworkId(1);
        assert!(statics().derive(&envelope(&root_foreign, &[])).is_err());
    }

    #[test]
    fn a_bound_window_narrows_the_transaction_and_never_widens_it() {
        // An offer standing inside the composition's window hands the
        // transaction its own tighter edges: a composer cannot bind a
        // signer past what that signer offered.
        let mut tight = composed_tree();
        tight.subintents[0].decl.header.validity_start_ms = 10;
        tight.subintents[0].decl.header.validity_end_ms = 900;
        let derived = statics()
            .derive(&envelope(&tight, &[&key(9)]))
            .expect("an offer inside the window composes");
        assert_eq!(
            derived
                .effective_window
                .start_timestamp_inclusive
                .as_millis(),
            10
        );
        assert_eq!(
            derived.effective_window.end_timestamp_exclusive.as_millis(),
            900
        );

        // The other direction buys nothing. An offer standing wider than
        // the envelope leaves the transaction exactly as wide as its
        // composer signed for.
        let mut wide = composed_tree();
        wide.subintents[0].decl.header.validity_end_ms = 5_000_000;
        let derived = statics()
            .derive(&envelope(&wide, &[&key(9)]))
            .expect("a wider offer composes");
        assert_eq!(
            derived.effective_window.end_timestamp_exclusive.as_millis(),
            1_000_000
        );
    }

    #[test]
    fn an_offer_sharing_no_window_with_its_composition_is_refused() {
        // The offer closed before the transaction opens. There is no
        // instant both signers agreed to, so there is no transaction.
        let mut lapsed = composed_tree();
        lapsed.subintents[0].decl.header.validity_start_ms = 2_000_000;
        lapsed.subintents[0].decl.header.validity_end_ms = 2_000_001;
        assert!(statics().derive(&envelope(&lapsed, &[&key(9)])).is_err());
    }

    #[test]
    fn an_intent_standing_longer_than_the_cap_is_refused() {
        let mut forever = composed_tree();
        forever.subintents[0].decl.header.validity_end_ms = u64::MAX;
        assert!(statics().derive(&envelope(&forever, &[&key(9)])).is_err());
    }

    #[test]
    fn the_same_offer_twice_takes_two_nullifiers() {
        // One signer, one offer, made twice inside one window. Without
        // something to tell them apart the second carries the first's
        // nullifier and reads as already spent; with it they are two
        // declarations that conflict on nothing.
        let once = composed_tree();
        let mut twice = composed_tree();
        twice.subintents[0].decl.header.discriminator = 1;

        let first = statics()
            .derive(&envelope(&once, &[&key(9)]))
            .expect("the offer composes");
        let second = statics()
            .derive(&envelope(&twice, &[&key(9)]))
            .expect("the same offer, said twice, composes");
        assert_ne!(first.subintent_hashes, second.subintent_hashes);

        // The nullifier is derived from that identity, so the two spend
        // different cells — which is the whole of what the field buys.
        let nullifiers = |derived: &Derived| -> Vec<DeclaredKey> {
            derived
                .routing
                .write_keys
                .iter()
                .filter(|key| {
                    key.cell()
                        .is_some_and(|cell| cell.owner == Address::from(bob_addr()))
                })
                .copied()
                .collect()
        };
        assert_ne!(nullifiers(&first), nullifiers(&second));
    }

    #[test]
    fn an_inadmissible_tree_is_refused() {
        // The produced bucket is never consumed: linearity refuses it.
        let tree = single_intent_tree(vec![withdraw(composer_addr(), RES_X, 100)]);
        assert!(statics().derive(&envelope(&tree, &[])).is_err());
    }

    #[test]
    fn a_nullifier_hash_needs_a_subintent_hash_type() {
        // Pin the record type wiring: the routed hash is the declaration
        // hash, reconstructible from the decoded tree alone.
        let tree = composed_tree();
        let decoded = decode_tree(&encode_tree(&tree)).unwrap();
        assert_eq!(
            decoded.subintents[0].decl.hash(&ProtocolHasher),
            tree.subintents[0].decl.hash(&ProtocolHasher)
        );
        let _typed: SubintentHash = tree.subintents[0].decl.hash(&ProtocolHasher);
    }

    /// The provision-weight cap: cells count one, ranges count their
    /// declared cap, and a set the wire codec could not carry as one
    /// bundle is refused at admission.
    #[test]
    fn a_declaration_past_one_bundles_weight_is_refused() {
        let owner = Address::new([9; 31], AddressClass::Component);
        let range = |cap: u32, salt: u128| {
            DeclaredKey::Range(DeclaredRange {
                owner,
                collection: CollectionId([3; 16]),
                lo: salt,
                hi: salt,
                cap,
            })
        };
        let cap_u32 = u32::try_from(MAX_STATE_ENTRIES_PER_TX).unwrap();

        let at_cap: BTreeSet<DeclaredKey> = [range(cap_u32, 0)].into();
        assert!(check_provision_weight(&at_cap).is_ok());

        let over: BTreeSet<DeclaredKey> = [range(cap_u32, 0), range(1, 1)].into();
        assert!(check_provision_weight(&over).is_err());

        let cells_count: BTreeSet<DeclaredKey> = [
            DeclaredKey::substate(owner, [1; 16]),
            range(cap_u32 - 1, 0),
            range(1, 1),
        ]
        .into();
        assert!(check_provision_weight(&cells_count).is_err());
    }

    /// A record is seated under the address its own contents derive, and
    /// under no other.
    ///
    /// This is the whole of what makes a fetched record safe from any
    /// peer: the address is the hash of the record, so a served record
    /// either is the one asked for or derives somewhere else and seats
    /// nothing. Nobody is trusted, and no consensus stands behind the
    /// answer.
    #[test]
    fn a_record_is_seated_only_under_the_address_it_derives() {
        let meta = InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"honest"])),
            config: vec![Value::U64(7)],
            salt: Hash32([3; 32]),
        };
        let address = meta.address(&ProtocolHasher).address();
        let record = meta.leaf_bytes().expect("a record encodes");

        // Its own address: the key derives, the contents derive, seated.
        let cache = InstanceCache::new(InstanceRegistry::new());
        assert!(cache.absorb_cell(address, config_key(address).local.0, &record));
        assert!(
            cache
                .record(CallTarget::try_from(address).unwrap())
                .is_some()
        );

        // Somebody else's: the same honest bytes, offered for a
        // component they say nothing about.
        let elsewhere = InstanceMeta {
            salt: Hash32([9; 32]),
            ..meta
        }
        .address(&ProtocolHasher)
        .address();
        let cache = InstanceCache::new(InstanceRegistry::new());
        assert!(!cache.absorb_cell(elsewhere, config_key(elsewhere).local.0, &record));
        assert!(
            cache
                .record(CallTarget::try_from(elsewhere).unwrap())
                .is_none(),
            "a record deriving another address seats nothing"
        );

        // And a cell that is not a configuration leaf is not a record,
        // whatever it holds: the key is checked before the value is
        // read, which is what keeps this cheap over every committed cell.
        let cache = InstanceCache::new(InstanceRegistry::new());
        assert!(!cache.absorb_cell(address, vault_key(address, *XRD).local.0, &record));
    }

    /// The address a served record derives, read off the bytes alone.
    #[test]
    fn a_records_address_is_read_from_the_record() {
        let meta = InstanceMeta {
            package: PackageHash(ProtocolHasher.hash(b"package", &[b"served"])),
            config: Vec::new(),
            salt: Hash32([5; 32]),
        };
        assert_eq!(
            record_address(&meta.leaf_bytes().unwrap()),
            Some(meta.address(&ProtocolHasher).address())
        );
        assert_eq!(record_address(b"not a record"), None);
    }
}
