//! The VM seam: the envelope re-exported, its crypto binding, and the
//! derivation trait admission runs through.
//!
//! [`TransactionEnvelope`] and its terms live in `hyperscale-vm-types` —
//! the envelope is the VM's artifact, and its signed content is defined
//! there through the derived preimage. What binds here is what the leaf
//! crate deliberately does not know: the protocol hash and the signature
//! arithmetic behind [`EnvelopeExt`], and the workspace's admission
//! vocabulary behind [`Derivation`], which reads the window off the
//! tree's root and the terms beside the tree on the envelope.

use std::sync::OnceLock;

pub use hyperscale_vm_types::{
    AccountSigner, Attestation, MAX_ATTESTATIONS, MAX_INTENTS, MAX_MESSAGE_LEN,
    MAX_TX_ATTESTATIONS, Mode, SchemeId, SchemeVerifier, Terms, TransactionEnvelope,
};
use hyperscale_vm_types::{DeclaredWork, LegShape, NetworkId, SubstateKey, attest};
use thiserror::Error;

use crate::crypto::{
    Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature, verify_ed25519,
    verify_ml_dsa_65, verify_secp256k1,
};
use crate::{
    Address, DeclaredKey, Hash, PrincipalAddr, ProtocolHasher, RoutePrefix, TimestampRange,
};

/// The arithmetic behind the VM's scheme registry.
///
/// The registry says how wide a scheme's material is and what verifying it
/// costs; this says what verifying it *means*. Every scheme the protocol
/// accepts answers here, and one it does not — an id no registry entry
/// claims, or material of a width its entry does not give it — answers
/// `false` alongside a signature that is simply wrong.
///
/// Every message the transaction path presents is a 32-byte hash, and no
/// scheme here digests it a second time: ECDSA takes it as its prehash,
/// and ML-DSA signs it as a message under the pure variant. A message of
/// any other width is refused by the schemes that require the digest
/// exactly, which is the same refusal as any other material this verifier
/// cannot read.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtocolVerifier;

impl SchemeVerifier for ProtocolVerifier {
    fn verify(&self, scheme: SchemeId, key: &[u8], signature: &[u8], message: &[u8]) -> bool {
        let Some(spec) = scheme.spec() else {
            return false;
        };
        if !spec.admits(key, signature) {
            return false;
        }
        match scheme {
            SchemeId::ED25519 => {
                let (Ok(key), Ok(signature)) = (key.try_into(), signature.try_into()) else {
                    return false;
                };
                verify_ed25519(
                    message,
                    &Ed25519PublicKey(key),
                    &Ed25519Signature(signature),
                )
            }
            SchemeId::SECP256K1 => {
                let (Ok(key), Ok(signature), Ok(prehash)) = (
                    key.try_into(),
                    signature.try_into(),
                    <&[u8; 32]>::try_from(message),
                ) else {
                    return false;
                };
                verify_secp256k1(
                    prehash,
                    &Secp256k1PublicKey(key),
                    &Secp256k1Signature(signature),
                )
            }
            SchemeId::ML_DSA_65 => verify_ml_dsa_65(message, key, signature),
            _ => false,
        }
    }
}

/// The workspace's crypto and clock binding for the envelope.
///
/// The envelope defines its signed content — the preimage — and this
/// trait turns it into signatures and windows with the protocol's own
/// hash, signature, and time vocabulary.
pub trait EnvelopeExt: Sized {
    /// The domain-separated hash of the envelope's signed content —
    /// everything but the attestations. This is also the identity fresh
    /// derivations root at: distinct signed envelopes never mint the
    /// same fresh key.
    fn signing_hash(&self) -> Hash;

    /// Attest the envelope's content with `key`, standing the attestation
    /// beside those already given. The caller signs in the order the
    /// root intent declares its attesting principals.
    #[must_use]
    fn sign<S: AccountSigner>(self, key: &S) -> Self;
}

impl EnvelopeExt for TransactionEnvelope {
    fn signing_hash(&self) -> Hash {
        // The digest refuses only an envelope past the wire caps, and
        // nothing here holds one: a decoded envelope stays inside the
        // bounds its decoder enforced, and a composed one was refused at
        // signing before it reached an identity.
        let digest = self
            .signing_digest(&ProtocolHasher)
            .expect("an envelope within its caps digests");
        Hash::from_hash_bytes(&digest)
    }

    fn sign<S: AccountSigner>(mut self, key: &S) -> Self {
        // `manifest-builder`'s own signing tier does the same over its
        // own hasher — this is the protocol hash's spelling of it, for
        // the fixtures and call sites that already hold a key.
        let digest = self
            .signing_digest(&ProtocolHasher)
            .expect("a fixture envelope stays within the wire caps");
        self.signatures.push(attest(key, &digest));
        self
    }
}

/// One attestation and the hash it covers, as derivation reads them off
/// an envelope: the root's over the envelope's digest, a member's over
/// its intent hash.
///
/// Derivation has already held each to the declaration it stands
/// beside — the key derives the principal at its position, and every
/// intent carries one attestation per principal it declares — so what
/// is left for verification is the signature itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// What the signature covers.
    pub hash: [u8; 32],
    /// The scheme, key and signature.
    pub attestation: Attestation,
}

/// A transaction's derived routing identity.
///
/// Admission conflict keys and the owner prefixes that place it on
/// shards. A pure function of the envelope and genesis-static metadata —
/// derived locally at every node, never carried on the wire, so a
/// sender cannot claim a placement its content does not earn. Nullifier
/// creation writes are in the write keys: committing an intent, the
/// root included, is an exclusive write at its canonical nullifier
/// address under each account the intent acts as.
/// Snapshot reads appear nowhere here: they are lock-free and
/// client-proven, so a snapshot-only shard is not a participant at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    /// Conflict keys for fresh reads — the shared admission class.
    pub read_keys: Vec<DeclaredKey>,
    /// Conflict keys for every mutation (writes, deltas, reserves).
    pub write_keys: Vec<DeclaredKey>,
    /// Owner prefixes behind `read_keys`, deduplicated ascending.
    pub read_prefixes: Vec<Address>,
    /// Owner prefixes behind `write_keys`, deduplicated ascending.
    pub write_prefixes: Vec<Address>,
    /// The keys whose committed values counterpart shards must carry:
    /// fresh reads plus read-modify-write priors. Deltas, blind writes,
    /// and reserves provision nothing.
    pub provision_keys: Vec<DeclaredKey>,
    /// Owner prefixes behind `provision_keys`, deduplicated ascending —
    /// the tick's provision dependency set routes on these.
    pub provision_prefixes: Vec<Address>,
    /// What each declared key is accessed under, ascending by key then
    /// mode, with the reservation amount carried where there is one.
    ///
    /// The key sets above answer "does this transaction touch that
    /// cell"; this answers "how", which is what decides whether two
    /// transactions touching one cell can be in flight together. A
    /// reservation also has to say how much, because feasibility is
    /// judged against committed balance less what is already held, and
    /// the amount is statically declared for exactly that reason.
    ///
    /// One key can appear more than once: a manifest may declare several
    /// effects on one cell, and a payer reserving twice reserves the sum.
    pub declared_modes: Vec<(DeclaredKey, Mode)>,
}

impl Routing {
    /// The route every owner prefix the transaction touches takes,
    /// ascending, deduplicated.
    ///
    /// Deduplicated on the route and not on the address, so two prefixes
    /// that place together are one entry: what reads this asks only
    /// where a prefix sits.
    #[must_use]
    pub fn all_routes(&self) -> Vec<RoutePrefix> {
        let mut routes: Vec<RoutePrefix> = self
            .read_prefixes
            .iter()
            .chain(self.write_prefixes.iter())
            .map(|prefix| RoutePrefix::of(*prefix))
            .collect();
        routes.sort_unstable();
        routes.dedup();
        routes
    }

    /// Every owner prefix the transaction touches, ascending, deduplicated.
    #[must_use]
    pub fn all_prefixes(&self) -> Vec<Address> {
        let mut prefixes: Vec<Address> = self
            .read_prefixes
            .iter()
            .chain(self.write_prefixes.iter())
            .copied()
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes
    }

    /// What `key` is declared under by this transaction, if anything.
    ///
    /// A key declared more than once yields each declaration: the caller
    /// decides whether it wants every mode or the sum of the amounts.
    pub fn modes_for<'a>(&'a self, key: &'a DeclaredKey) -> impl Iterator<Item = Mode> + 'a {
        self.declared_modes
            .iter()
            .filter(move |(declared, _)| declared == key)
            .map(|(_, mode)| *mode)
    }
}

/// Everything the bridge derives from an envelope.
///
/// The routing identity, the terms and the network, and every
/// attestation the envelope and its tree carry with the hash each must
/// cover. Which account a key may act as is not checked here: that is
/// the account's own rule, judged on its shard as the sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    /// The routing identity.
    pub routing: Routing,
    /// The envelope's signing-time terms: the payer, the fee ceiling,
    /// the compute ceilings, the priority and the message.
    ///
    /// Copied from the envelope at derivation, so every consumer reads
    /// one derived record rather than the envelope's fields and the
    /// derivation's side by side.
    pub terms: Terms,
    /// The network the root names, which every intent beneath it names
    /// too. What verification holds a transaction to a session by.
    pub network: NetworkId,
    /// The principals attesting the root intent, in declared order —
    /// the set the payer's rule is judged against at the fee gate.
    ///
    /// Deliberately not compared against the envelope's `fee_payer`
    /// here: whether the payer's rule admits this set is the payer
    /// shard's verdict, taken where the payer's state is, so derivation
    /// records the set and leaves the judgement to the one shard that
    /// can reach it.
    pub attested_by: Vec<PrincipalAddr>,
    /// Every attestation the transaction carries with the hash it
    /// covers: the root's over the envelope's digest, then each member's
    /// over its intent hash, in tree order. What verification checks.
    pub attestations: Vec<Attested>,
    /// The local half of the fee payer's native-resource vault cell —
    /// the substate the payer shard's reservation check reads and the
    /// fee settlement debits. The owner half is the envelope's
    /// `fee_payer`.
    pub fee_vault_local: [u8; 16],
    /// The local half of the payer's stored-authority cell, read beside
    /// the vault at the same anchored height: the reservation engages
    /// only for a signer the payer's rule admits.
    pub auth_cell_local: [u8; 16],
    /// The content addresses of every package the manifest's calls run,
    /// deduplicated. What the execution gate holds a candidate to: a
    /// shard dispatches the transaction only once it holds all of them.
    pub packages: Vec<Hash>,
    /// The window the transaction is actually admissible in: the
    /// root's, narrowed by every member beneath it.
    ///
    /// A member signs the window its own signer offered it for, and a
    /// composer cannot widen it — so the answer is the intersection,
    /// and an empty one is refused at derivation rather than admitted
    /// into a window no signer agreed to. Every consumer reads this
    /// rather than the root's own header, which is the composer's claim
    /// alone.
    pub effective_window: TimestampRange,
    /// What this transaction declares it may consume, whole: the sum of
    /// every owner's share and what every participating shard bears.
    ///
    /// Derived locally from the manifest and published metadata like
    /// every other routing quantity — nothing about it travels on the
    /// wire, so a sender cannot understate it. What the fee prices, on
    /// every outcome.
    pub work: DeclaredWork,
    /// The declaration's terms by the owner prefix they fall under: the
    /// effects declared on the owner's cells, the ceilings of the nodes
    /// targeting it, the artifacts those nodes instantiate, and the
    /// kernel cells written under it. Sorted and unique by owner.
    ///
    /// What a shard's own share is read off: the shares of the owners
    /// it holds under a placement, plus [`Self::everywhere`].
    pub shares: Vec<OwnerShare>,
    /// What each manifest node bears, in node order: the ceiling its
    /// composer signed for it, and the artifact instantiating it reads.
    ///
    /// Per node rather than under the node's owner, because a shard runs
    /// more nodes than it holds: a multi-shard core replicates every
    /// core node onto every core shard, so what those nodes may consume
    /// is owed by each of them and reserved by each of them. Empty for a
    /// publish, which invokes nothing and carries its ceiling in its
    /// publisher's share.
    pub node_terms: Vec<DeclaredWork>,
    /// One term per distinct package the manifest calls, with the nodes
    /// that call it. What a shard adds for each package it instantiates.
    ///
    /// Empty for a publish, which invokes nothing.
    pub artifacts: Vec<ArtifactTerm>,
    /// What every shard that commits the transaction bears whatever it
    /// holds: the committed cell it writes, and the whole retention,
    /// since every validator keeps the envelope and its receipt.
    pub everywhere: DeclaredWork,
    /// Each manifest node's placement-free shape, in node order. Empty
    /// for a publish, which has no manifest to divide.
    pub legs: Vec<LegShape>,
    /// The accounts this transaction's intents act as, which the
    /// classifier holds to a shard running an issuing member before it
    /// divides the shape. Sorted and unique.
    ///
    /// The fee payer is not among them unless an intent acts as it. The
    /// two are held to different rules — a reservation needs a member of
    /// any side, an account's sign-in needs one that issues — so they
    /// reach the classifier apart.
    pub accounts: Vec<Address>,
    /// The nullifier cell of every intent, in tree order, each under
    /// the account it acts as.
    ///
    /// One of the cells the kernel writes of its own accord; the others
    /// — the record and claim of every value edge that crosses — are
    /// read off `legs` at a placement, since which edges cross is a fact
    /// of the anchor while this list is fixed when the envelope is
    /// composed. Together they are what
    /// [`Transaction::sweepable_writes_on`](crate::Transaction::sweepable_writes_on)
    /// counts for a shard against
    /// [`MAX_SWEEPABLE_CREATED_PER_BLOCK`](crate::MAX_SWEEPABLE_CREATED_PER_BLOCK).
    pub nullifiers: Vec<SubstateKey>,
}

/// One owner prefix's share of a transaction's declared work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerShare {
    /// The owner prefix the share falls under.
    pub owner: Address,
    /// What the transaction declares against this owner's cells and the
    /// nodes that target it.
    pub work: DeclaredWork,
}

/// The vector a transaction declares whole: every owner's share, every
/// node's own terms, and what each committing shard bears, each counted
/// once.
///
/// A replicated core node is in here once however many shards run it:
/// the composer does not choose the core, so the price must not depend
/// on it.
#[must_use]
pub fn whole_work(
    shares: &[OwnerShare],
    node_terms: &[DeclaredWork],
    artifacts: &[ArtifactTerm],
    everywhere: DeclaredWork,
) -> DeclaredWork {
    let with_nodes = node_terms
        .iter()
        .fold(everywhere, |total, term| total.saturating_add(*term));
    // Each artifact once, however many nodes call it and however many
    // shards instantiate it: the composer chooses neither, so the price
    // must not depend on either.
    let with_artifacts = artifacts.iter().fold(with_nodes, |total, artifact| {
        total.saturating_add(DeclaredWork {
            read_bytes: artifact.read_bytes,
            ..DeclaredWork::ZERO
        })
    });
    shares.iter().fold(with_artifacts, |total, share| {
        total.saturating_add(share.work)
    })
}

/// What instantiating one package the manifest calls reads, and which of
/// its nodes call it.
///
/// The read is the artifact's and not any one node's: a shard pays it
/// once however many of the manifest's nodes it runs out of that
/// package, and every shard that instantiates the package pays it.
/// Riding on a single node's term instead lets a shard running only the
/// manifest's later nodes reserve nothing for an artifact it still
/// loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTerm {
    /// What reading the artifact's bytes costs, once.
    pub read_bytes: u64,
    /// The manifest nodes this package's code runs, ascending.
    pub nodes: Vec<u32>,
}

/// Why a derivation did not answer.
///
/// Two different things, and a caller has to tell them apart. A refusal
/// is a verdict every node reaches alike for the same bytes. A gap is
/// this node's alone: derivation resolves a call target through the
/// records it has seen commit, and one it has not seen resolves nothing
/// here and resolves fine wherever the seal already landed. The first is
/// the envelope's fault forever; the second closes when the record
/// arrives.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DerivationError {
    /// The envelope is inadmissible, on terms every node agrees on.
    #[error("derivation refused the envelope: {0}")]
    Refused(String),
    /// What this node holds none of, so it cannot say what the envelope
    /// declares. Not a verdict: each name is what a fetch asks its
    /// owning shard for, and derivation answers once they are seated.
    #[error("derivation wants what this node has not seen: {0:?}")]
    Unresolved(Unresolved),
}

impl DerivationError {
    /// What this node would need before derivation could answer, or
    /// `None` for a refusal.
    #[must_use]
    pub const fn unresolved(&self) -> Option<&Unresolved> {
        match self {
            Self::Refused(_) => None,
            Self::Unresolved(wanted) => Some(wanted),
        }
    }
}

/// What a derivation is waiting on, in the two forms a fetch asks for.
///
/// Both links of the chain a call resolves through: the record that says
/// which package a target runs, and the package itself. A gap in the
/// first is reported alone — the record is what names the package, so
/// what is missing behind it cannot be known until the record lands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unresolved {
    /// Component addresses this node holds no record for.
    pub instances: Vec<Address>,
    /// Content addresses this node holds no package metadata for.
    pub packages: Vec<Hash>,
}

impl Unresolved {
    /// Whether the derivation wants nothing — the case that is not a gap
    /// at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instances.is_empty() && self.packages.is_empty()
    }

    /// Every name it waits on as an address: a component by its own, a
    /// package by the one its content address derives.
    ///
    /// What a wait is indexed by, so an envelope held for a record and
    /// one held for code are released by the same arrival path.
    #[must_use]
    pub fn awaited(&self, package_address: impl Fn(Hash) -> Address) -> Vec<Address> {
        self.instances
            .iter()
            .copied()
            .chain(self.packages.iter().copied().map(package_address))
            .collect()
    }
}

/// The seam VM admission derives through: what one node can answer.
///
/// Decode the envelope tree, admit it, and route its effect sets into
/// the workspace vocabulary. The effects bridge implements it over the
/// records and packages that node has seen commit.
///
/// Split from [`ProtocolStatics`] on the only line that matters, which
/// is whether two nodes can answer differently. Everything here reads a
/// cache the chain fills, so a node that has not seen a seal commit
/// resolves nothing a node that has resolves fine — a real difference,
/// and one a single shared installation would erase.
pub trait Derivation: Send + Sync {
    /// Derive the envelope's routing identity and attestations, or
    /// refuse it.
    ///
    /// # Errors
    ///
    /// [`DerivationError`] on an undecodable or inadmissible envelope,
    /// an intent carrying a different number of attestations than the
    /// principals it declares, or an attesting key that does not derive
    /// the principal declared at its position.
    fn derive(&self, vm: &TransactionEnvelope) -> Result<Derived, DerivationError>;

    /// Offer one committed cell to the published-package cache.
    ///
    /// Called for every cell a block commits, on the commit path and
    /// on the sync path alike, because both derive their state from the
    /// same block content. What makes a cell a package is a property of
    /// its own bytes, so the implementation decides — this seam carries
    /// no VM vocabulary and no notion of what a package is.
    ///
    /// Feeding the cache from committed state rather than from execution
    /// is what keeps routing identical across replicas: a package is
    /// usable by transactions admitted after its block commits, and a
    /// validator whose cache lagged would refuse what its peers admit.
    fn absorb_committed_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) {
        let _ = (owner, local, value);
    }
}

/// The seam the VM answers protocol questions through: what every node
/// answers alike.
///
/// A verdict over bytes a caller supplies, or a classification of bytes
/// a block committed. Neither reads anything a node accumulates, so two
/// nodes cannot disagree and nothing is gained by holding one of these
/// per node.
///
/// A trait rather than free functions because the dependency runs from
/// the effects bridge to this crate: consensus cannot call into the VM,
/// so the VM installs its answers here.
pub trait ProtocolStatics: Send + Sync {
    /// Whether `payer`'s rule admits the attesting set `keys`, given the
    /// payer's stored-authority cell as read at the caller's own
    /// anchored height — `None` or empty meaning absent.
    ///
    /// The rule's encoding is the VM's fact, so consensus hands the
    /// bytes across this seam and stays blind to them. Absent means the
    /// account is virtual and the rule is the identity its address
    /// derives; stored bytes that do not decode admit nobody, the same
    /// fail-closed verdict the execution gate gives them. The one
    /// implementation is the same function the kernel judges an
    /// intent's sign-in through, so the two gates cannot read one cell
    /// differently — which is why there is no default body here for a
    /// second reading to hide in.
    ///
    /// The cell holds one rule and the verdict is that rule's, so what
    /// replaces one is a write to the cell: a replacement an account has
    /// waiting sits in that package's own cells and governs here only
    /// once a call enacts it. No instant enters the verdict, so two
    /// nodes reading one cell reach one answer whenever each judges.
    fn rule_admits(
        &self,
        auth_cell: Option<&[u8]>,
        payer: PrincipalAddr,
        keys: &[PrincipalAddr],
    ) -> bool;

    /// The content address of the package this committed cell publishes,
    /// or `None` for every other cell.
    ///
    /// What makes a cell a package is a property of its own bytes — the
    /// value re-derives the cell's local key under its owner — so the
    /// implementation decides, and this seam carries no VM vocabulary.
    /// Storage backends consult it to index a committed package's
    /// artifact bytes beside the commit that carries them.
    fn package_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) -> Option<Hash> {
        let _ = (owner, local, value);
        None
    }

    /// The instant this committed cell stops being needed, or `None` for
    /// every cell a sweep does not reach.
    ///
    /// A sweepable cell answers for its own life: the value carries the
    /// expiry and the key derives from it, so the implementation decides
    /// from the bytes alone and this seam carries no VM vocabulary — the
    /// shape [`Self::package_cell`] already has. Storage backends index
    /// what this answers so a sweep can enumerate by expiry over a
    /// keyspace that is owner-major and always will be.
    ///
    /// The expiry is milliseconds on the same clock a block's
    /// `weighted_timestamp` reads, because that is the clock a removal
    /// is judged against.
    fn sweepable_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) -> Option<u64> {
        let _ = (owner, local, value);
        None
    }

    /// Whether this committed cell is an escrow record — value a shard
    /// holds for a crossing it issued, until a consumer claims it or the
    /// issuer takes it back.
    ///
    /// Judged from the bytes as [`Self::sweepable_cell`] is, and asked
    /// for the opposite reason: a record is deliberately outside every
    /// sweep's reach, so nothing else tells a successor that the leaf it
    /// just imported is an obligation. A store answers this only where
    /// it inherits a prefix whole — a reshape successor's adoption — and
    /// what it writes down is the key, the state being the value's
    /// authority.
    fn record_cell(&self, owner: [u8; 32], local: [u8; 16], value: &[u8]) -> bool {
        let _ = (owner, local, value);
        false
    }
}

static PROTOCOL_STATICS: OnceLock<Box<dyn ProtocolStatics>> = OnceLock::new();

/// Install the process-wide protocol answers. The first installation
/// wins, so tests and node boot can both install without coordination.
///
/// There is no counterpart for [`Derivation`]: a derivation is a node's
/// own, and a process running several nodes holds one each.
pub fn install_protocol_statics(statics: Box<dyn ProtocolStatics>) {
    let _ = PROTOCOL_STATICS.set(statics);
}

/// Whether the protocol answers are installed.
#[must_use]
pub fn protocol_statics_installed() -> bool {
    PROTOCOL_STATICS.get().is_some()
}

/// The installed protocol answers.
///
/// # Panics
///
/// If none are installed — transactions cannot exist in a process that
/// never wired the VM seam.
pub fn protocol_statics() -> &'static dyn ProtocolStatics {
    PROTOCOL_STATICS
        .get()
        .expect("protocol statics not installed; node wiring installs the effects-bridge answers")
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::{AccountSigner, ProtocolVerifier, SchemeId, SchemeVerifier};
    use crate::crypto::{Ed25519PrivateKey, MlDsa65PrivateKey, Secp256k1PrivateKey};

    const DIGEST: [u8; 32] = [3u8; 32];

    fn ed() -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(&[3u8; 32]).expect("32 bytes")
    }

    fn secp() -> Secp256k1PrivateKey {
        Secp256k1PrivateKey::from_bytes(&[3u8; 32]).expect("a scalar in range")
    }

    fn ml_dsa() -> MlDsa65PrivateKey {
        MlDsa65PrivateKey::from_bytes(&[3u8; 32]).expect("32 bytes")
    }

    fn signers() -> Vec<Box<dyn AccountSigner>> {
        vec![Box::new(ed()), Box::new(secp()), Box::new(ml_dsa())]
    }

    #[test]
    fn a_signature_verifies_under_the_scheme_it_was_made_in() {
        for signer in signers() {
            let key = signer.public_key_bytes();
            let signature = signer.sign_digest(&DIGEST);
            assert!(ProtocolVerifier.verify(signer.scheme(), &key, &signature, &DIGEST));
            assert!(!ProtocolVerifier.verify(signer.scheme(), &key, &signature, &[9u8; 32]));
        }
    }

    /// Material presented under a scheme that did not produce it verifies
    /// under neither: the widths disagree, and where they agree the curve
    /// does.
    #[test]
    fn a_signature_verifies_under_no_other_scheme() {
        for signer in signers() {
            let key = signer.public_key_bytes();
            let signature = signer.sign_digest(&DIGEST);
            for scheme in [SchemeId::ED25519, SchemeId::SECP256K1, SchemeId::ML_DSA_65] {
                assert_eq!(
                    ProtocolVerifier.verify(scheme, &key, &signature, &DIGEST),
                    scheme == signer.scheme(),
                );
            }
        }
    }

    /// A scheme no registry entry claims verifies nothing, whatever
    /// material is presented under it.
    #[test]
    fn an_unregistered_scheme_verifies_nothing() {
        for signer in signers() {
            let key = signer.public_key_bytes();
            let signature = signer.sign_digest(&DIGEST);
            for scheme in [SchemeId::NONE, SchemeId(4), SchemeId(u16::MAX)] {
                assert!(!ProtocolVerifier.verify(scheme, &key, &signature, &DIGEST));
            }
        }
    }

    /// Material of a width its scheme does not give it is refused before
    /// any curve arithmetic runs, so a short key is never padded out to
    /// one the curve would accept.
    #[test]
    fn material_of_the_wrong_width_refuses() {
        for signer in signers() {
            let scheme = signer.scheme();
            let key = signer.public_key_bytes();
            let signature = signer.sign_digest(&DIGEST);
            assert!(!ProtocolVerifier.verify(scheme, &key[..key.len() - 1], &signature, &DIGEST));
            assert!(!ProtocolVerifier.verify(
                scheme,
                &key,
                &signature[..signature.len() - 1],
                &DIGEST
            ));
            assert!(!ProtocolVerifier.verify(scheme, &[], &[], &DIGEST));
        }
    }

    /// ECDSA reads the message as its prehash, so a message that is not
    /// the curve's digest width is material this verifier cannot read.
    #[test]
    fn secp256k1_refuses_a_message_that_is_not_a_digest() {
        let signer = secp();
        let key = signer.public_key_bytes();
        let signature = signer.sign_digest(&DIGEST);
        assert!(ProtocolVerifier.verify(SchemeId::SECP256K1, &key, &signature, &DIGEST));
        assert!(!ProtocolVerifier.verify(SchemeId::SECP256K1, &key, &signature, &DIGEST[..31]));
    }
}
