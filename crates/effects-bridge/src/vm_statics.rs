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
//! snapshots in the shared class, every other mode exclusive. Nullifier
//! creation writes ride the routed sets, so admission conflicts on them
//! like any other exclusive key.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, OnceLock};

use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_types::{
    ArtifactTerm, DeclaredKey, DeclaredRange, Derivation, DerivationError, Derived, EnvelopeExt,
    Hash, MAX_STATE_ENTRIES_PER_TX, MAX_SUBINTENT_VALIDITY_RANGE, OwnerShare, ProtocolStatics,
    Routing, TimestampRange, TransactionEnvelope, Unresolved, WeightedTimestamp, whole_work,
};
use hyperscale_vm_effects::vocabulary::{AUTH, CONFIG, VAULT};
use hyperscale_vm_effects::{
    Admitted, AdmittedTree, CROSSING_CELL_BYTES, ChainRecords, Claim, CrossingSite, EnvelopeTree,
    IntentHeader, MARKER_CELL_BYTES, ManifestHash, NodeCall, PackageHash, Value, admit_tree,
    auth_cell_admits, child_key, effect_units, legs_of, package_hash,
    package_key as canonical_package_key, principal_address, protocol_resource,
};
use hyperscale_vm_fixtures::lottery;
use hyperscale_vm_stdlib::staking;
use hyperscale_vm_types::{
    AMOUNT_CELL_BYTES, Address, AddressClass, DeclaredWork, Effect, EffectTarget, LegShape,
    LocalKey, Mode, Moves, PrincipalAddr, ResourceAddr, SchemeId, SubstateKey, TermsRefusal,
    admit_event_bounds, read_bytes, written_leaf,
};

use crate::ProtocolHasher;
use crate::artifact::admit_package;
use crate::records::{
    InstanceCache, LocalCells, NodeRecords, PackageCache, committed_package, record_cell,
    sweepable_cell,
};

/// The accounts a transaction's intents act as: the owner of each
/// intent's nullifier, and of the `auth` cell its sign-in is judged
/// against. Sorted and unique, so two derivations of one envelope agree
/// byte for byte.
///
/// The payer is not folded in. Its shard needs a member of any side,
/// which is a weaker thing than the issuing member an account's sign-in
/// needs, so the classifier is handed the two apart.
fn intent_accounts(admitted: &AdmittedTree) -> Vec<Address> {
    admitted
        .intents
        .iter()
        .map(|record| record.account.address())
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

/// The footprint of one point write on the effects schedule: what a
/// kernel cell the declaration does not name — a record, a claim, the
/// committed cell — costs in exclusion and depth.
const fn point_write_units() -> u64 {
    effect_units(Effect {
        target: EffectTarget::Point(SubstateKey {
            owner: Address::new([0; 31], AddressClass::Component),
            local: LocalKey([0; 16]),
        }),
        mode: Mode::Write { moves: Moves::Both },
    })
}

/// The owner prefix a declared target's cells fall under.
const fn target_owner(target: &EffectTarget) -> Address {
    match target {
        EffectTarget::Point(key) => key.owner,
        EffectTarget::Entry { owner, .. } | EffectTarget::Range { owner, .. } => *owner,
    }
}

/// One artifact read per distinct package `calls` names, carrying the
/// nodes that call it.
///
/// A shard adds a term for a package it instantiates, whichever of that
/// package's nodes brought it there. Attributing the read to one node
/// instead leaves a shard running only the manifest's later nodes
/// reserving nothing for an artifact it still loads — and the read is
/// the artifact's, so a shard running two nodes of one package pays it
/// once.
fn artifact_terms(packages: &PackageCache, calls: &[NodeCall]) -> Vec<ArtifactTerm> {
    let mut by_package: BTreeMap<PackageHash, Vec<u32>> = BTreeMap::new();
    for (index, call) in calls.iter().enumerate() {
        by_package
            .entry(call.package)
            .or_default()
            .push(u32::try_from(index).unwrap_or(u32::MAX));
    }
    by_package
        .into_iter()
        .map(|(package, nodes)| ArtifactTerm {
            read_bytes: packages.artifact_bytes(package).unwrap_or(0),
            nodes,
        })
        .collect()
}

/// What a call transaction declares, by the owner prefix each term
/// falls under, and what every committing shard bears beside the shares.
///
/// The declaration spans every shard it routes to, because the price is
/// taken once against the whole of it — and every value edge's record
/// and claim beside it, which the engine declares at prepare wherever
/// the edge turns out to cross: placement is a fact of the anchor, and
/// the price is fixed when the envelope is composed. A node's ceiling
/// sits under its target and each distinct package's artifact under the
/// first node that runs it; the verification of every signature is
/// borne by every shard, since each verifies before it commits. The
/// whole is the shares plus what every shard bears.
///
/// `envelope_bytes` is the envelope's own encoded length, the one term
/// of retention no derivation of the tree can see.
///
/// # Errors
///
/// [`TermsRefusal::EventBytesSum`] where the methods the manifest calls
/// may emit more between them than a receipt may carry. Refused here
/// rather than held to the cap, because the sum is what retention
/// prices and a figure clipped to the cap would price less than the
/// frames may spend.
pub fn declared_vector(
    packages: &PackageCache,
    vm: &TransactionEnvelope,
    admitted: &Admitted,
    legs: &[LegShape],
    envelope_bytes: u64,
) -> Result<DeclaredVector, TermsRefusal> {
    let mut by_owner: BTreeMap<Address, DeclaredWork> = BTreeMap::new();
    let mut add = |owner: Address, term: DeclaredWork| {
        let share = by_owner.entry(owner).or_default();
        *share = share.saturating_add(term);
    };
    // What the writes leave behind, which is not what they cost: a
    // written leaf carries `WRITE_LEAF_BYTES` of tree-path reads into
    // the write dimension, and those touch nothing after the block.
    // Accumulated beside the shares because retention is borne whole by
    // every shard and so belongs to none of them.
    let mut retained = 0u64;

    // The declaration's effects, each under its target's owner. The byte
    // dimensions are per target, since one leaf is read once and written
    // once however many modes a manifest declares on it; footprint is
    // per effect, because it prices the exclusion each declared access
    // asks for and two of them ask for more than one.
    //
    // The write figure comes off the set rather than being folded here,
    // so this and the quote a wallet signs against read one rule.
    let set = &admitted.declaration().set;
    for target in set.targets() {
        add(
            target_owner(&target),
            DeclaredWork {
                read_bytes: read_bytes(&target, set.width_of(&target)),
                write_bytes: set.write_bytes_of(&target),
                ..DeclaredWork::ZERO
            },
        );
        retained = retained.saturating_add(set.retained_bytes_of(&target));
    }
    for effect in set.iter() {
        add(
            target_owner(&effect.target),
            DeclaredWork {
                footprint: effect_units(effect),
                ..DeclaredWork::ZERO
            },
        );
    }

    // Every value edge's record under its producer and claim under its
    // consumer, at the kernel's own widths, whether or not the edge
    // crosses at any placement. Each is a leaf like any the declaration
    // names, so each is priced through `written_leaf` — the tree path an
    // update reads is what it costs whether a body declared the cell or
    // the kernel writes it unasked.
    let point_write = point_write_units();
    for consumer in legs {
        for edge in &consumer.edges {
            let Some(producer) = legs.get(edge.source as usize) else {
                continue;
            };
            add(
                producer.target,
                DeclaredWork {
                    write_bytes: written_leaf(u64::from(CROSSING_CELL_BYTES)),
                    footprint: point_write,
                    ..DeclaredWork::ZERO
                },
            );
            add(
                consumer.target,
                DeclaredWork {
                    write_bytes: written_leaf(u64::from(MARKER_CELL_BYTES)),
                    footprint: point_write,
                    ..DeclaredWork::ZERO
                },
            );
            retained = retained
                .saturating_add(u64::from(CROSSING_CELL_BYTES))
                .saturating_add(u64::from(MARKER_CELL_BYTES));
        }
    }

    // Each node's ceiling. Per node rather than under the node's owner:
    // a core shard runs every core node whatever it holds, so what a
    // node may consume is owed wherever it runs and an owner prefix
    // cannot say where that is.
    let node_terms: Vec<DeclaredWork> = (0..admitted.calls().len())
        .map(|index| DeclaredWork {
            compute: vm.gas_limits.get(index).copied().unwrap_or(0),
            ..DeclaredWork::ZERO
        })
        .collect();
    let artifacts = artifact_terms(packages, admitted.calls());

    let shares: Vec<OwnerShare> = by_owner
        .into_iter()
        .map(|(owner, work)| OwnerShare { owner, work })
        .collect();
    // What each call may emit, off the method it names: a method that
    // emits states its bound and one that does not states nothing, so a
    // manifest pays for the emissions of the methods it calls and for no
    // others. The kernel meters each node against its own figure and
    // retention prices their sum.
    let metadata = packages.load();
    let event_bytes: Vec<u32> = admitted
        .calls()
        .iter()
        .map(|call| {
            metadata
                .get(call.package)
                .and_then(|package| package.methods.get(&call.export))
                .map_or(0, |method| method.event_bytes)
        })
        .collect();
    let everywhere = everywhere(
        retained,
        envelope_bytes,
        vm.signatures(),
        admit_event_bounds(&event_bytes, admitted.calls().len())?,
    );
    Ok(DeclaredVector {
        shares,
        node_terms,
        artifacts,
        everywhere,
        event_bytes,
    })
}

/// Whose keys attest each intent, in tree order, read off the envelope.
///
/// The addresses only. The signatures themselves verify at the
/// transaction gate, over the declaration hashes admission returns; and
/// whether a key may act as the account its intent names is neither
/// stage's — that is the account's own rule, read on its own shard as
/// the sign-in. A key reaching for an account it does not derive is
/// admissible and refused there, before any body runs, at the price of
/// the reach. What is refused here is a key that names no principal at
/// all, and an arity that does not match: the composition's own intent
/// leads and is attested by the envelope's key, every intent after it
/// by one of `subintent_sigs` in the same order, so an envelope
/// carrying a signature for an intent it does not hold — or holding an
/// intent nothing signs — never reaches admission.
///
/// # Errors
///
/// [`DerivationError::Refused`] on a body with no intent, a count of
/// signatures that does not match the offered intents, or a key that
/// derives no principal.
pub fn attesting_sets(
    vm: &TransactionEnvelope,
    tree: &EnvelopeTree,
) -> Result<Vec<Vec<PrincipalAddr>>, DerivationError> {
    let Some(signer) = principal_for(vm.signer_scheme, &vm.signer) else {
        return Err(DerivationError::Refused(
            "the envelope's signer key derives no principal".into(),
        ));
    };
    let Some((_, offered)) = tree.intents.split_first() else {
        return Err(DerivationError::Refused(
            "a call body carries no intent at all".into(),
        ));
    };
    if vm.subintent_sigs.len() != offered.len() {
        return Err(DerivationError::Refused(format!(
            "envelope carries {} offered intents but {} signatures for them",
            offered.len(),
            vm.subintent_sigs.len()
        )));
    }
    let mut sets = vec![vec![signer]];
    for (index, sig) in vm.subintent_sigs.iter().enumerate() {
        let Some(key) = principal_for(sig.scheme, &sig.public_key) else {
            return Err(DerivationError::Refused(format!(
                "the key attesting intent {} derives no principal",
                index + 1
            )));
        };
        sets.push(vec![key]);
    }
    Ok(sets)
}

/// A call envelope decoded and read for who attests what, ahead of
/// admission.
///
/// The half of a derivation a preview shares. Both read the tree, the
/// attesting sets and the identity off the envelope and admit under the
/// same rule, and holding that in one place is what keeps a preview
/// from reporting a verdict the chain would not reach.
pub struct CallEnvelope<'a> {
    vm: &'a TransactionEnvelope,
    /// The bound tree the envelope carries.
    pub tree: EnvelopeTree,
    /// Whose keys attest each intent, in tree order.
    pub attested_by: Vec<Vec<PrincipalAddr>>,
}

impl<'a> CallEnvelope<'a> {
    /// Decode the tree and read the attesting sets.
    ///
    /// # Errors
    ///
    /// [`DerivationError::Refused`] on a publish body, a tree that does
    /// not decode, or the arity and key refusals of [`attesting_sets`].
    pub fn decode(vm: &'a TransactionEnvelope) -> Result<Self, DerivationError> {
        let Some(bytes) = vm.call_tree() else {
            return Err(DerivationError::Refused(
                "a publish body carries no call tree".into(),
            ));
        };
        let tree = decode_tree(bytes)?;
        let attested_by = attesting_sets(vm, &tree)?;
        Ok(Self {
            vm,
            tree,
            attested_by,
        })
    }

    /// The principal the envelope's own key derives: the key attesting
    /// the composition's intent, and the one the payer's rule is judged
    /// against at the fee gate.
    #[must_use]
    pub fn signer(&self) -> PrincipalAddr {
        self.attested_by[0][0]
    }

    /// Admit the tree against `chain`, and hold the signed terms to the
    /// manifest it lowered to: one ceiling per node, summing under the
    /// bound, and a priority under its own.
    ///
    /// # Errors
    ///
    /// [`DerivationError::Refused`] with admission's own explanation, or
    /// the terms refusal.
    pub fn admit(&self, chain: &dyn ChainRecords) -> Result<AdmittedTree, DerivationError> {
        let admitted = admit_tree(
            &self.tree,
            &self.attested_by,
            envelope_identity(self.vm),
            chain,
            &ProtocolHasher,
        )
        .map_err(|error| DerivationError::Refused(format!("admission: {error}")))?;
        self.vm
            .admit_terms(admitted.admitted.calls().len())
            .map_err(|refusal| DerivationError::Refused(refusal.to_string()))?;
        Ok(admitted)
    }
}

/// What a transaction declares, as the derivation reads it off the tree:
/// the vector by owner and by node, what every shard bears, and the
/// bound the kernel meters the transaction's events against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredVector {
    /// What each owner prefix bears.
    pub shares: Vec<OwnerShare>,
    /// What each manifest node bears, in node order.
    pub node_terms: Vec<DeclaredWork>,
    /// One term per distinct package the manifest calls, with the nodes
    /// that call it.
    pub artifacts: Vec<ArtifactTerm>,
    /// What every shard committing the transaction bears whatever it
    /// holds.
    pub everywhere: DeclaredWork,
    /// The most bytes each call may emit, in node order.
    pub event_bytes: Vec<u32>,
}

/// What every shard that commits a transaction bears whatever it holds:
/// the verification of every signature, the committed cell it writes,
/// and the retention every validator keeps — the envelope, what the
/// writes leave behind, the auth material, and the events its packages
/// may emit.
///
/// `retained` is what the declaration's writes keep, not what they cost.
/// The write dimension carries `WRITE_LEAF_BYTES` of tree-path reads per
/// leaf, and a validator retains none of them — this cap is derived as a
/// share of what actually crosses the link and stays, so counting the
/// reads here would hold a block to a quantity nobody stores.
fn everywhere(
    retained: u64,
    envelope_bytes: u64,
    signatures: DeclaredWork,
    event_bytes: u64,
) -> DeclaredWork {
    // One leaf, written by the shard rather than declared by a body, and
    // priced as one: what it keeps is its own bytes, what it costs is
    // those over the tree path the update reads.
    let committed_cell = u64::from(MARKER_CELL_BYTES);
    DeclaredWork {
        compute: signatures.compute,
        write_bytes: written_leaf(committed_cell),
        retention: envelope_bytes
            .saturating_add(retained)
            .saturating_add(committed_cell)
            .saturating_add(signatures.retention)
            .saturating_add(event_bytes),
        ..DeclaredWork::ZERO
    }
}

/// The envelope's own encoded length: the one term of retention the
/// tree does not carry.
///
/// # Errors
///
/// A locally built envelope past the wire caps, which a decoded one
/// never is.
pub fn envelope_bytes(vm: &TransactionEnvelope) -> Result<u64, DerivationError> {
    hbor_to_vec(vm)
        .map(|bytes| bytes.len() as u64)
        .map_err(|error| DerivationError::Refused(format!("envelope encodes: {error}")))
}

/// The protocol fee and transfer resource: the genesis publisher's
/// primary issue.
///
/// A resource like any other, minted by an address no signer reaches —
/// so supply moves only where the protocol writes state directly, and
/// the address sits where a hash puts it, on no shard by preference.
pub static PROTOCOL_RESOURCE: LazyLock<ResourceAddr> =
    LazyLock::new(|| protocol_resource(&ProtocolHasher));

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
/// and what the injected sign-in condition and the payer shard's
/// reservation verdict both read through `auth_cell_admits`.
#[must_use]
pub(crate) fn auth_key(owner: impl Into<Address>) -> SubstateKey {
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

/// Where the package addressed by `package` lives: the vocabulary's own
/// derivation, bound to the protocol hasher.
#[must_use]
pub fn package_key(package: PackageHash) -> SubstateKey {
    canonical_package_key(&ProtocolHasher, package)
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
/// The composition's own intent is no special case. Its window folds in
/// like any other, so a composer who states a tighter one on their own
/// intent than on the envelope gets the tighter one, and a wider one
/// buys nothing. That is what a narrowing rule gives for free, where an
/// equality rule would have made a signed field mean one thing there and
/// another everywhere else.
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
    let headers = tree.intents.iter().map(|intent| &intent.decl.header);
    for (index, header) in headers.enumerate() {
        let named = || {
            if index == 0 {
                "the composition's own intent".to_string()
            } else {
                format!("intent {index}")
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
fn classify_declared_access(admitted: &Admitted, fee_payer: PrincipalAddr) -> DeclaredAccess {
    let mut access = DeclaredAccess {
        read_keys: BTreeSet::new(),
        write_keys: BTreeSet::new(),
        provision_keys: BTreeSet::new(),
        declared_modes: Vec::new(),
    };
    for effect in admitted.declaration().set.iter() {
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
    let fee_vault = DeclaredKey::Cell(vault_key(fee_payer, *PROTOCOL_RESOURCE));
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
pub(crate) type ArtifactSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

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
fn unresolved_targets(tree: &EnvelopeTree, chain: &dyn ChainRecords) -> Unresolved {
    let carried: BTreeMap<Address, PackageHash> = tree
        .instances
        .iter()
        .map(|meta| (meta.address(&ProtocolHasher).address(), meta.package))
        .collect();
    let mut wanted = Unresolved::default();
    let graphs = tree.intents.iter().map(|intent| &intent.decl.graph);
    for node in graphs.flat_map(|graph| &graph.nodes) {
        let address = node.target.address();
        // The record first, and the package only through it: a target
        // this node holds no record for says nothing about which code it
        // runs, so there is nothing to ask for behind it yet.
        let Some(package) = chain
            .instance(node.target)
            .map(|meta| meta.package)
            .or_else(|| carried.get(&address).copied())
        else {
            if !wanted.instances.contains(&address) {
                wanted.instances.push(address);
            }
            continue;
        };
        let package = Hash::from(package.0);
        if chain.package(PackageHash(package.as_hash32())).is_none()
            && !wanted.packages.contains(&package)
        {
            wanted.packages.push(package);
        }
    }
    wanted
}

impl BridgeStatics {
    /// A publish's routing: an exclusive write on the package cell, and
    /// one on the publisher's fee vault.
    ///
    /// The two sit under different owners — the package under its own
    /// content address, the vault under the payer — so a publish reaches
    /// whichever shard is obliged to keep the artifact as well as the
    /// one holding the fee.
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
        // A publish lowers to one node and signs one ceiling for it.
        vm.admit_terms(1)
            .map_err(|refusal| DerivationError::Refused(refusal.to_string()))?;
        // The artifact has to describe itself before it is addressed:
        // what the address covers is code and signatures together, so an
        // artifact that declares nothing is not a package.
        admit_package(artifact)?;

        let publisher = vm.fee_payer;
        let package = package_hash(&ProtocolHasher, artifact);
        let cell = package_key(package);
        let vault = vault_key(publisher, *PROTOCOL_RESOURCE);
        let mut write_keys = vec![DeclaredKey::Cell(cell), DeclaredKey::Cell(vault)];
        write_keys.sort_unstable();
        write_keys.dedup();

        // A publish never reaches the kernel, so it declares no effects
        // to price. Its vector stands in as the two exclusive point
        // writes it claims — the package cell, written whole with the
        // artifact, and the vault the fee burns from — each under the
        // owner whose prefix carries it, with its one ceiling and its
        // signature.
        //
        // Two leaves and not one sum: each carries its own tree path, so
        // what they cost is `written_leaf` twice where what they keep is
        // their bytes added.
        let artifact_bytes = artifact.len() as u64;
        let retained = artifact_bytes.saturating_add(AMOUNT_CELL_BYTES as u64);
        let point_write = point_write_units();
        let mut shares = vec![
            OwnerShare {
                owner: cell.owner,
                work: DeclaredWork {
                    write_bytes: written_leaf(artifact_bytes),
                    footprint: point_write,
                    ..DeclaredWork::ZERO
                },
            },
            OwnerShare {
                owner: publisher.address(),
                work: DeclaredWork {
                    compute: vm.gas_limit_total(),
                    write_bytes: written_leaf(AMOUNT_CELL_BYTES as u64),
                    footprint: point_write,
                    ..DeclaredWork::ZERO
                },
            },
        ];
        shares.sort_unstable_by_key(|share| share.owner);
        // A publish keeps exactly what it writes: the artifact sits in
        // the package cell and the vault holds its amount.
        let everywhere = everywhere(retained, envelope_bytes(vm)?, vm.signatures(), 0);
        let work = whole_work(&shares, &[], &[], everywhere);

        Ok(Derived {
            // A publish carries no tree, so nothing narrows the window
            // its composer signed and nothing binds a subintent.
            effective_window: vm.validity_window(),
            work,
            shares,
            // No node to divide the ceiling by: a publish invokes
            // nothing, and what it costs is its publisher's alone. Nor
            // any package to instantiate — its artifact is bytes written
            // and retained, which the shares above already carry.
            node_terms: Vec::new(),
            artifacts: Vec::new(),
            everywhere,
            // No manifest, so nothing to divide, nothing crossing, and no
            // subintent bound; the publisher pays and signs.
            legs: Vec::new(),
            // A publish carries no intent, so nothing acts as an
            // account and nothing signs in. What holds the publisher's
            // shard to the transaction is the artifact's own cell, which
            // the write prefixes below name.
            accounts: Vec::new(),
            nullifiers: Vec::new(),
            signer,
            routing: Routing {
                read_prefixes: Vec::new(),
                // Both owners: the artifact's cell sits under its own
                // address, so the shard obliged to keep it is a party to
                // the publish beside the one holding the vault.
                write_prefixes: {
                    let mut written = vec![publisher.address(), cell.owner];
                    written.sort_unstable();
                    written.dedup();
                    written
                },
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
        let call = CallEnvelope::decode(vm)?;
        let effective_window = effective_window(vm, &call.tree)?;
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
        let unresolved = unresolved_targets(&call.tree, &chain);
        if !unresolved.is_empty() {
            return Err(DerivationError::Unresolved(unresolved));
        }
        let admitted_tree = call.admit(&chain)?;
        let admitted = &admitted_tree.admitted;

        let DeclaredAccess {
            read_keys,
            write_keys,
            provision_keys,
            declared_modes,
        } = classify_declared_access(admitted, vm.fee_payer);
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
        let packages: Vec<Hash> = admitted
            .calls()
            .iter()
            .map(|call| Hash::from(call.package.0))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let legs = legs_of(admitted);
        let DeclaredVector {
            shares,
            node_terms,
            artifacts,
            everywhere,
            ..
        } = declared_vector(&self.cache, vm, admitted, &legs, envelope_bytes(vm)?)
            .map_err(|refusal| DerivationError::Refused(refusal.to_string()))?;
        let work = whole_work(&shares, &node_terms, &artifacts, everywhere);
        Ok(Derived {
            effective_window,
            work,
            shares,
            node_terms,
            artifacts,
            everywhere,
            legs,
            nullifiers: admitted_tree
                .intents
                .iter()
                .map(|record| record.nullifier)
                .collect(),
            accounts: intent_accounts(&admitted_tree),
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
            // The offered intents alone, in the order `subintent_sigs`
            // pairs with: the composition's own is attested by the
            // envelope's signature and carries none of them.
            subintent_hashes: admitted_tree
                .intents
                .iter()
                .skip(1)
                .map(|record| record.intent.0.0)
                .collect(),
            fee_vault_local: vault_key(vm.fee_payer, *PROTOCOL_RESOURCE).local.0,
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
        keys: &[PrincipalAddr],
    ) -> bool {
        // The same function the sign-in condition is judged through, so
        // the gate that decides inclusion and the one that decides
        // execution cannot read one cell differently. What differs is
        // only the question: this asks whether the payer's rule admits
        // the envelope's signer, before anything is included at all.
        let keys: Vec<Claim> = keys
            .iter()
            .map(|key| Claim::of_subject(key.address()))
            .collect();
        auth_cell_admits(payer.address(), auth_cell, &keys)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        CallTarget, Ed25519PrivateKey, NetworkId, Secp256k1PrivateKey, TransactionBody,
    };
    use hyperscale_vm_effects::vocabulary::VAULT;
    use hyperscale_vm_effects::{
        Binding, Claim, Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, Hash32, Hasher,
        InstanceMeta, InstanceRegistry, Intent, IntentDecl, IntentHash, ManifestGraph,
        MetadataCache, PackageHash, RuleBytes, Socket, StoredRule, child_key, never,
        nullifier_expiry_ms, nullifier_key, package_slot,
    };
    use hyperscale_vm_manifest_builder::signing::sign_subintent;
    use hyperscale_vm_stdlib::account;
    use hyperscale_vm_types::{
        AMOUNT_CELL_BYTES, CollectionId, LegRole, MAX_GAS_LIMIT, ResourceAddr, WRITE_LEAF_BYTES,
    };

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

    fn withdraw(target: impl Into<CallTarget>, resource: ResourceAddr, amount: u128) -> GraphNode {
        GraphNode {
            target: target.into(),
            method: "withdraw".into(),
            args: vec![
                GraphArg::Literal(Value::Address(resource.address())),
                GraphArg::Literal(Value::U128(amount)),
            ],
            evidence: [EvidenceRef::IntentSignature].into(),
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

    /// A tree of one intent acting as `account` — whose key has to be the
    /// one the envelope around it is signed with.
    fn intent_tree(account: PrincipalAddr, nodes: Vec<GraphNode>) -> EnvelopeTree {
        EnvelopeTree {
            intents: vec![Intent {
                decl: IntentDecl {
                    header: HEADER,
                    graph: ManifestGraph { nodes },
                    sockets: Vec::new(),
                },
                account,
                bindings: Vec::new(),
            }],
            instances: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// The two-signer composition: the composer pays X for the
    /// subintent's Y.
    fn composed_tree() -> EnvelopeTree {
        EnvelopeTree {
            intents: std::iter::once(Intent {
                decl: IntentDecl {
                    header: HEADER,
                    graph: ManifestGraph {
                        nodes: vec![
                            withdraw(composer_addr(), RES_X, 100),
                            deposit_socket(composer_addr(), 0),
                        ],
                    },
                    sockets: vec![Socket::Value {
                        resource: RES_Y,
                        constraints: vec![Constraint::MinAmount(10)],
                    }],
                },
                account: composer_addr(),
                bindings: vec![Binding::Value {
                    intent: 1,
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                }],
            })
            .chain(vec![Intent {
                decl: IntentDecl {
                    header: HEADER,
                    graph: ManifestGraph {
                        nodes: vec![
                            withdraw(bob_addr(), RES_Y, 10),
                            deposit_socket(bob_addr(), 0),
                        ],
                    },
                    sockets: vec![Socket::Value {
                        resource: RES_X,
                        constraints: vec![Constraint::MinAmount(100)],
                    }],
                },
                account: bob_addr(),
                bindings: vec![Binding::Value {
                    intent: 0,
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                }],
            }])
            .collect(),
            instances: Vec::new(),
            resources: Vec::new(),
        }
    }

    fn envelope(tree: &EnvelopeTree, subintent_keys: &[&Ed25519PrivateKey]) -> TransactionEnvelope {
        // The composition's own intent leads and the envelope's
        // signature attests it, so the offered intents are what these
        // keys pair with.
        let subintent_sigs = tree
            .intents
            .iter()
            .skip(1)
            .zip(subintent_keys)
            .map(|(intent, signer)| {
                let hash = intent.decl.hash(&ProtocolHasher);
                sign_subintent(*signer, &hash.0.0)
            })
            .collect();
        TransactionEnvelope {
            body: TransactionBody::Call(encode_tree(tree)),
            subintent_sigs,
            fee_payer: composer_addr(),
            max_fee: 1_000,
            gas_limits: vec![250_000; tree.node_count()],
            priority_bp: 0,
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

    /// A transfer divides into a withdraw and a deposit. Its one value
    /// edge is one crossing, whose record sits under the sender and
    /// names the vault the withdraw reserved; and it binds nothing, so
    /// it files no nullifier.
    #[test]
    fn a_transfer_derives_one_crossing_per_value_edge() {
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let vm = envelope(&tree, &[]);
        let derived = statics().derive(&vm).expect("derives");

        let roles: Vec<LegRole> = derived.legs.iter().map(|leg| leg.role).collect();
        assert_eq!(roles, vec![LegRole::Inbound, LegRole::Outbound]);
        let records = crossing_records(&derived.legs);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].owner,
            composer_addr().address(),
            "the record sits under the producing node's target"
        );

        assert_eq!(
            derived.nullifiers.len(),
            1,
            "the root's own, which is what holds one declaration to one execution"
        );

        // The crossing's record and claim are priced beside what the
        // routing declares: the record under the producer at the
        // crossing cell's width, the claim under the consumer at the
        // marker's, each a point write on the footprint schedule.
        let point_write = effect_units(Effect {
            target: EffectTarget::Point(records[0]),
            mode: Mode::Write { moves: Moves::Both },
        });
        let share = |owner: Address| {
            derived
                .shares
                .iter()
                .find(|share| share.owner == owner)
                .map(|share| share.work)
                .expect("the owner has a share")
        };
        let producer = share(composer_addr().address());
        let consumer = share(bob_addr().address());
        assert!(
            producer.write_bytes >= u64::from(CROSSING_CELL_BYTES)
                && producer.footprint > point_write,
            "the record sits under the producer beside its own declaration"
        );
        assert!(
            consumer.write_bytes >= u64::from(MARKER_CELL_BYTES)
                && consumer.footprint >= point_write,
            "the claim sits under the consumer"
        );
        assert_eq!(
            derived.work,
            whole_work(
                &derived.shares,
                &derived.node_terms,
                &derived.artifacts,
                derived.everywhere,
            ),
            "the whole is the shares and the nodes plus what every shard bears"
        );
        assert_eq!(
            derived.work.compute,
            vm.gas_limit_total() + vm.signatures().compute,
            "compute is the ceilings and the verification"
        );
        assert_eq!(
            derived.work.retention, derived.everywhere.retention,
            "retention is borne whole by every shard"
        );
    }

    /// The ceilings index the lowered manifest one to one: a count off
    /// the node count is refused, whether short or long.
    #[test]
    fn a_ceiling_count_off_the_manifest_is_refused() {
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let mut vm = envelope(&tree, &[]);
        assert_eq!(vm.gas_limits.len(), 2);
        statics().derive(&vm).expect("one ceiling per node derives");

        vm.gas_limits.pop();
        let short = statics()
            .derive(&vm)
            .expect_err("one ceiling for two nodes");
        assert!(short.to_string().contains("2 manifest nodes"), "{short}");

        vm.gas_limits = vec![250_000; 3];
        assert!(
            statics().derive(&vm).is_err(),
            "three ceilings for two nodes"
        );
    }

    /// The bound is on the sum over the nodes, not on any one of them.
    #[test]
    fn ceilings_summing_past_the_bound_are_refused() {
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let mut vm = envelope(&tree, &[]);
        vm.gas_limits = vec![MAX_GAS_LIMIT / 2, MAX_GAS_LIMIT / 2 + 1];
        let heavy = statics()
            .derive(&vm)
            .expect_err("the sum is past the bound");
        assert!(heavy.to_string().contains("sum"), "{heavy}");

        vm.gas_limits = vec![MAX_GAS_LIMIT / 2, MAX_GAS_LIMIT / 2];
        statics().derive(&vm).expect("at the bound derives");
    }

    /// A publish carries one ceiling, the node it lowers to.
    #[test]
    fn a_publish_carries_one_ceiling() {
        let key = key(7);
        let mut vm = TransactionEnvelope {
            body: TransactionBody::Publish(vec![0xAB; 64]),
            subintent_sigs: Vec::new(),
            fee_payer: composer_addr(),
            max_fee: 1_000,
            gas_limits: vec![1, 2],
            priority_bp: 0,
            validity_start_ms: 0,
            validity_end_ms: 1_000_000,
            message: Vec::new(),
            network: NETWORK,
            signer_scheme: SchemeId::NONE,
            signer: Vec::new(),
            signature: Vec::new(),
        }
        .sign(&key);
        let two = statics()
            .derive(&vm)
            .expect_err("two ceilings for one node");
        assert!(two.to_string().contains("1 manifest node"), "{two}");
        // One ceiling passes the terms; what refuses the envelope then
        // is the artifact, which is not a package.
        vm.gas_limits = vec![1];
        let refused = statics()
            .derive(&vm)
            .expect_err("the artifact is not a package");
        assert!(!refused.to_string().contains("ceilings"), "{refused}");
    }

    /// An escrow cell is keyed by what its node's own signer signed. Two
    /// compositions of one subintent derive the same cells for that
    /// subintent's nodes, and the composer moving the root's own window
    /// moves the root's cells and nobody else's.
    #[test]
    fn escrow_cells_follow_the_signing_intent() {
        let first = composed_tree();
        let mut second = composed_tree();
        second.intents[0].decl.header.validity_end_ms -= 1_000;
        let derive = |tree: &EnvelopeTree| {
            statics()
                .derive(&envelope(tree, &[&key(9)]))
                .expect("derives")
        };
        let (one, other) = (derive(&first), derive(&second));
        let bob = first.intents[1].decl.hash(&ProtocolHasher);

        // The interleave puts Bob's withdraw at manifest node 1, first
        // in his own intent — and the leg says which of those it is.
        assert_eq!(one.legs[1].intent, bob);
        assert_eq!(one.legs[1].local, 0);
        assert_eq!(
            one.legs[0].intent,
            first.intents[0].decl.hash(&ProtocolHasher)
        );

        let record_of = |derived: &Derived, node: usize| {
            CrossingSite::record_of(&ProtocolHasher, &derived.legs[node], 0).key()
        };
        assert_eq!(
            record_of(&one, 1),
            record_of(&other, 1),
            "Bob's record is fixed by Bob's signature"
        );
        assert_ne!(
            record_of(&one, 0),
            record_of(&other, 0),
            "the root's record moves with the root's window"
        );
        assert_eq!(
            one.nullifiers[1], other.nullifiers[1],
            "and so is his nullifier"
        );
        assert_ne!(
            one.nullifiers[0], other.nullifiers[0],
            "while the root's moves with the root's window, as its record does"
        );
    }

    /// The vector carries what the envelope signed for and what every
    /// validator keeps of it: the ceilings and the verification as
    /// compute, the envelope's own bytes and its writes as retention, and
    /// the artifacts its nodes instantiate as reads.
    #[test]
    fn work_carries_the_ceilings_the_envelope_and_the_artifacts() {
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let vm = envelope(&tree, &[]);
        let derived = statics().derive(&vm).expect("derives");
        let envelope_bytes = envelope_bytes(&vm).expect("encodes");

        assert_eq!(
            derived.work.compute,
            vm.gas_limit_total() + vm.signatures().compute
        );
        assert!(
            derived.work.retention >= envelope_bytes + vm.signatures().retention,
            "retention carries the envelope and the auth material"
        );
        assert!(
            derived.work.retention < envelope_bytes + derived.work.write_bytes,
            "and what the writes leave behind rather than what they cost: a \
             transfer keeps a few dozen bytes in its vaults where writing \
             them reads thousands off the tree path. {} against a write \
             dimension of {}",
            derived.work.retention,
            derived.work.write_bytes
        );
        // Each call carries the bound its own method declares, so a
        // transfer's withdraw and deposit carry theirs.
        let metadata = account::metadata();
        let bound = |method: &str| {
            u64::from(
                metadata
                    .methods
                    .get(method)
                    .expect("the account publishes it")
                    .event_bytes,
            )
        };
        let moving = bound("withdraw") + bound("deposit");
        assert!(moving > 0, "the movements bound what they may emit");
        assert!(
            derived.work.retention >= envelope_bytes + moving,
            "retention carries the envelope and each call's own event bound"
        );
        // The sum over the calls and nothing else: a second movement
        // pair adds its own bound again, so what retention prices is
        // what the frames may spend between them rather than one
        // package's figure or the cap they are held under.
        let twice = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 2, RES_X),
            ],
        );
        let wider_vm = envelope(&twice, &[]);
        let twice = statics().derive(&wider_vm).expect("derives");
        let wider_bytes = super::envelope_bytes(&wider_vm).expect("encodes");
        // Against what the second pair's leaves KEEP — its edge's record
        // and claim at their own widths — and not against what they cost
        // to write, which carries a per-leaf floor retention never sees.
        assert_eq!(
            twice.work.retention - derived.work.retention,
            moving
                + u64::from(CROSSING_CELL_BYTES + MARKER_CELL_BYTES)
                + (wider_bytes - envelope_bytes),
            "the second pair adds its own event bound, the cells its edge keeps, and its own envelope"
        );
        // The fixture statics know the account package's metadata and
        // not its artifact, so nothing is read for it; a statics that
        // does adds the artifact once however many nodes run it.
        let with_artifact = statics();
        with_artifact.cache.publish(
            PackageHash(ProtocolHasher.hash(b"package", &[b"account"])),
            &account::metadata(),
            12_345,
        );
        let priced = with_artifact.derive(&vm).expect("derives");
        assert_eq!(priced.work.read_bytes, derived.work.read_bytes + 12_345);

        // A second recipient declares more, so it costs more in every
        // dimension the declaration reaches — nothing else about the two
        // envelopes differs.
        let wider = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
                withdraw(composer_addr(), RES_Y, 10),
                deposit_edge(bob_addr(), 2, RES_Y),
            ],
        );
        let wider = statics().derive(&envelope(&wider, &[])).expect("derives");
        assert!(
            wider.work.footprint > derived.work.footprint
                && wider.work.write_bytes > derived.work.write_bytes
                && wider.work.read_bytes > derived.work.read_bytes
                && wider.work.retention > derived.work.retention,
            "a wider declaration must not be cheaper: {:?} vs {:?}",
            wider.work,
            derived.work
        );
    }

    /// A vault reached under two modes is one leaf written once.
    ///
    /// Alice paying Alice is the smallest shape that tells the rules
    /// apart: the withdrawal reserves out of her vault and the deposit
    /// credits into it, so one leaf carries two modes. Charging per mode
    /// would price it as two leaves and leave the chain charging what
    /// `EffectSet::write_bytes` — the figure a wallet is quoted against,
    /// through preflight — does not, so a ceiling signed off the quote
    /// would be refused at admission.
    ///
    /// Read as a difference rather than a constant: collapsing the two
    /// accounts into one removes exactly one vault leaf and nothing
    /// else.
    #[test]
    fn a_vault_paying_itself_is_one_leaf_and_not_two_charges() {
        let plain = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let itself = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(composer_addr(), 0, RES_X),
            ],
        );
        let write_of = |tree| {
            statics()
                .derive(&envelope(tree, &[]))
                .expect("derives")
                .work
                .write_bytes
        };

        let one_leaf = WRITE_LEAF_BYTES + AMOUNT_CELL_BYTES as u64;
        assert_eq!(
            write_of(&itself),
            write_of(&plain) - one_leaf,
            "one vault fewer, and the survivor still written once: {} against {}",
            write_of(&itself),
            write_of(&plain)
        );
    }

    /// A leaf the chain writes costs what a leaf a body declares costs.
    ///
    /// The committed cell is the one every shard writes for every
    /// transaction whatever it holds, so pricing it at its width alone
    /// would leave a full block spending most of its real write budget
    /// outside the cap that is supposed to bound it — the cap is derived
    /// in leaves, and this is a leaf.
    ///
    /// Read against the width rather than as a constant: what the pin is
    /// about is the floor being there, and the floor is the difference.
    #[test]
    fn a_leaf_the_chain_writes_carries_the_floor_a_declared_leaf_does() {
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let derived = statics().derive(&envelope(&tree, &[])).expect("derives");
        assert_eq!(
            derived.everywhere.write_bytes,
            WRITE_LEAF_BYTES + u64::from(MARKER_CELL_BYTES),
            "the committed cell is one leaf written, not {MARKER_CELL_BYTES} bytes of value"
        );

        // And the floor stays out of what is kept: dropping one vault
        // leaf takes the floor off the write dimension and only the
        // leaf's own bytes off retention.
        let itself = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(composer_addr(), 0, RES_X),
            ],
        );
        let fewer = statics().derive(&envelope(&itself, &[])).expect("derives");
        assert_eq!(
            derived.work.write_bytes - fewer.work.write_bytes,
            WRITE_LEAF_BYTES + AMOUNT_CELL_BYTES as u64,
            "a leaf costs its path and its bytes"
        );
        assert_eq!(
            derived.work.retention - fewer.work.retention,
            AMOUNT_CELL_BYTES as u64,
            "and keeps only its bytes"
        );
    }

    /// What a transaction's signatures cost to check is priced with the
    /// rest of what it declares, so a wider scheme is a fee fact rather
    /// than free verification.
    #[test]
    fn work_prices_the_signatures_the_envelope_carries() {
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let ed = statics().derive(&envelope(&tree, &[])).expect("derives");

        let secp = Secp256k1PrivateKey::from_bytes(&[7u8; 32]).expect("a scalar in range");
        let payer = principal_for(SchemeId::SECP256K1, &secp.public_key().0)
            .expect("a registered scheme opens an account");
        let secp_tree = intent_tree(
            payer,
            vec![
                withdraw(payer, RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        let mut wider = envelope(&secp_tree, &[]);
        wider.fee_payer = payer;
        let wider = statics().derive(&wider.sign(&secp)).expect("derives");

        assert!(
            wider.work.compute > ed.work.compute && wider.work.retention > ed.work.retention,
            "a wider signature scheme must not verify for free: {:?} vs {:?}",
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
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
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
        // The root's nullifier is a creation, so its absence is
        // provisioned to every participant beside what the calls read.
        let root_hash = tree.intents[0].decl.hash(&ProtocolHasher);
        let root_nullifier = nullifier_key(
            &ProtocolHasher,
            composer_addr(),
            root_hash,
            nullifier_expiry_ms(&tree.intents[0].decl.header),
        );
        let mut provisioned = reads.clone();
        provisioned.push(DeclaredKey::substate(
            composer_addr().address(),
            root_nullifier.local.0,
        ));
        provisioned.sort_unstable();
        assert_eq!(derived.routing.provision_keys, provisioned);
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

        let admits = |cell: Option<&[u8]>, key: PrincipalAddr| {
            statics.rule_admits(cell, composer_addr(), &[key])
        };

        // Virtual: the payer's own identity and no other.
        assert!(admits(None, composer_addr()));
        assert!(admits(Some(&[]), composer_addr()));
        assert!(!admits(None, bob_addr()));

        // Securified to Bob: the old identity is dead, the rule's lives.
        let cell = stored(&StoredRule::claim(Claim::of_subject(bob_addr())));
        assert!(admits(Some(&cell), bob_addr()));
        assert!(!admits(Some(&cell), composer_addr()));

        // A frozen account binds no fees: the rule nobody satisfies is
        // written rather than removed, because an unwritten cell is what
        // the address's own key still governs.
        let frozen = stored(&never());
        assert!(!admits(Some(&frozen), bob_addr()));
        assert!(!admits(Some(&frozen), composer_addr()));

        // Bytes no cell decodes from admit nobody — fail closed, like
        // the execution gate. Bare rule bytes are among them: the write
        // path stores frames.
        assert!(!admits(Some(&[0xFF, 0xFF]), composer_addr()));
        let bare = StoredRule::claim(Claim::of_subject(bob_addr()))
            .to_bytes()
            .unwrap();
        assert!(!admits(Some(&bare), bob_addr()));
    }

    #[test]
    fn a_composed_envelope_derives_the_nullifier_write() {
        let tree = composed_tree();
        let bob = key(9);
        let derived = statics()
            .derive(&envelope(&tree, &[&bob]))
            .expect("derives");

        let hash = tree.intents[1].decl.hash(&ProtocolHasher);
        assert_eq!(derived.subintent_hashes, vec![hash.0.0]);
        let nullifier = nullifier_key(
            &ProtocolHasher,
            bob_addr(),
            hash,
            nullifier_expiry_ms(&tree.intents[1].decl.header),
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
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
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

        let tree = intent_tree(
            payer,
            vec![
                withdraw(payer, RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
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
        let tree = intent_tree(
            composer_addr(),
            vec![
                withdraw(bob_addr(), RES_X, 100),
                deposit_edge(composer_addr(), 0, RES_X),
            ],
        );
        assert!(statics().derive(&envelope(&tree, &[])).is_err());

        // Reversed, it is the ordinary transfer: the composer withdraws
        // from their own account and Bob is credited without being asked.
        // One signature, because only the spending side is gated.
        let transfer = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
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
                &intent_tree(composer_addr(), vec![node(BTreeSet::new())]),
                &[],
            ))
            .expect_err("refuses");
        assert!(
            refused.to_string().contains("evidence"),
            "{}",
            refused.to_string()
        );
        // The signature is the account's own badge, so a method gated on
        // that account reads it directly — and whether the key behind it
        // still opens the account is the account's shard's to answer, as
        // the sign-in, not derivation's.
        assert!(
            statics()
                .derive(&envelope(
                    &intent_tree(
                        composer_addr(),
                        vec![node([EvidenceRef::IntentSignature].into())],
                    ),
                    &[],
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
        stolen.intents[0].decl.graph.nodes[1] = withdraw(bob_addr(), RES_X, 100);
        assert!(statics().derive(&envelope(&stolen, &[&bob])).is_err());
    }

    #[test]
    fn a_key_attesting_an_account_it_does_not_derive_still_derives() {
        // The tree binds BOB's address, but the carried key is another's.
        // Admissible: whether Bob's account admits that key is state only
        // Bob's own cell holds, so his shard answers it as the sign-in,
        // before any body runs and at the price of the reach.
        let tree = composed_tree();
        let impostor = key(11);
        assert!(statics().derive(&envelope(&tree, &[&impostor])).is_ok());

        // A missing signature list is a different thing: the envelope
        // does not say who attested an intent it carries, which nothing
        // downstream could answer.
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
        foreign.intents[1].decl.header.network = NetworkId(1);
        assert!(statics().derive(&envelope(&foreign, &[&key(9)])).is_err());

        // The composer's own intent answers the same rule: an envelope
        // whose root disagrees with the network it names is refused
        // before any signature is read.
        let mut root_foreign = intent_tree(
            composer_addr(),
            vec![
                withdraw(composer_addr(), RES_X, 100),
                deposit_edge(bob_addr(), 0, RES_X),
            ],
        );
        root_foreign.intents[0].decl.header.network = NetworkId(1);
        assert!(statics().derive(&envelope(&root_foreign, &[])).is_err());
    }

    #[test]
    fn a_bound_window_narrows_the_transaction_and_never_widens_it() {
        // An offer standing inside the composition's window hands the
        // transaction its own tighter edges: a composer cannot bind a
        // signer past what that signer offered.
        let mut tight = composed_tree();
        tight.intents[1].decl.header.validity_start_ms = 10;
        tight.intents[1].decl.header.validity_end_ms = 900;
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
        wide.intents[1].decl.header.validity_end_ms = 5_000_000;
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
        lapsed.intents[1].decl.header.validity_start_ms = 2_000_000;
        lapsed.intents[1].decl.header.validity_end_ms = 2_000_001;
        assert!(statics().derive(&envelope(&lapsed, &[&key(9)])).is_err());
    }

    #[test]
    fn an_intent_standing_longer_than_the_cap_is_refused() {
        let mut forever = composed_tree();
        forever.intents[1].decl.header.validity_end_ms = u64::MAX;
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
        twice.intents[1].decl.header.discriminator = 1;

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
        let tree = intent_tree(composer_addr(), vec![withdraw(composer_addr(), RES_X, 100)]);
        assert!(statics().derive(&envelope(&tree, &[])).is_err());
    }

    #[test]
    fn a_nullifier_hash_needs_a_subintent_hash_type() {
        // Pin the record type wiring: the routed hash is the declaration
        // hash, reconstructible from the decoded tree alone.
        let tree = composed_tree();
        let decoded = decode_tree(&encode_tree(&tree)).unwrap();
        assert_eq!(
            decoded.intents[1].decl.hash(&ProtocolHasher),
            tree.intents[1].decl.hash(&ProtocolHasher)
        );
        let _typed: IntentHash = tree.intents[1].decl.hash(&ProtocolHasher);
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
        assert!(!cache.absorb_cell(
            address,
            vault_key(address, *PROTOCOL_RESOURCE).local.0,
            &record
        ));
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
