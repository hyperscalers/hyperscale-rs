//! Typestate wrapper that carries verification status with a value.
//!
//! A [`Verifiable<T>`] holds either the raw wire form `T` or a [`Verified<T>`]
//! value carrying the type-level claim that `T`'s verification predicate has
//! been checked. Its SBOR encoding is byte-identical to `T`; decoding always
//! lands in [`Verifiable::Unverified`]. Verification produces
//! [`Verifiable::Verified`] in place; the marker rides with the value through
//! ordinary moves, clones, and local-dispatch handoffs.
//!
//! [`Verified<T, A>`] takes an optional `Augment` parameter, defaulting to
//! `()` for witness-style verification (signatures, merkle-root recomputes —
//! the common case). When verification produces a byproduct the caller wants
//! downstream (e.g. a state-root JMT replay returning a prepared-commit
//! handle), the augment slot carries it: `Verified<StateRoot, PreparedCommit>`.
//! The augment never rides through SBOR; only the witness form is wire-
//! eligible, so [`Verifiable<T>`] always carries `Verified<T, ()>`.
//!
//! Read-only access to the inner `T` is via `Deref<Target = T>` (and the
//! `AsRef<T>` it implies). No `&mut`, no `AsMut`, no `Encode`/`Decode` on
//! `Verified<T, A>` — verified values cannot be produced from wire bytes.
//!
//! # Equality and hashing
//!
//! `Verifiable<T>` values compare and hash by their raw `T` content,
//! regardless of variant. This is the only equality semantics that
//! round-trips through SBOR and works in `HashMap<_, Verifiable<T>>`
//! lookups against newly-decoded wire values. `Verified<T, ()>` compares
//! by inner `T`; augmenting forms (`Verified<T, A>` with `A != ()`) don't
//! impl `PartialEq`/`Eq`/`Hash` — the augment may not be equality-relevant.
//!
//! # `From` impls
//!
//! `From<T> for Verifiable<T>` produces [`Verifiable::Unverified`].
//! `From<Verified<T>> for Verifiable<T>` produces [`Verifiable::Verified`].
//! Both are generic and unambiguous: `T` and `Verified<T>` are distinct
//! types, so the impls don't overlap.
//!
//! # Local-dispatch trust assumption
//!
//! The marker is preserved across the in-process local-dispatch fast path
//! because the typed dispatcher downcasts `&dyn Any` back to `&M`. This
//! assumes colocated vnodes share a single trust domain (one process =
//! one operator). If multi-tenant in-process ever ships, this assumption
//! must be revisited.

use std::hash::{Hash, Hasher};
use std::ops::Deref;

use sbor::{
    Categorize, Decode, DecodeError, Decoder, Describe, Encode, EncodeError, Encoder,
    NoCustomTypeKind, NoCustomValueKind, RustTypeId, TypeData, ValueKind,
};

/// A type whose value can be verified against a `Ctx`.
///
/// Each verifier is implemented next to its raw type. `Ctx` is per-verifier
/// (typically a small struct borrowing keys, voting powers, network id,
/// etc.). The associated [`Augment`](Self::Augment) is `()` for witness-
/// style verification or the byproduct type for augmenting verification;
/// the associated [`Error`](Self::Error) is the per-verifier failure-mode
/// vocabulary, defined in the same module as the raw type so the type
/// owns its full predicate contract.
///
/// The `Verify` impl's doc comment is the canonical home of the predicate
/// specification, in the format "Construction asserts: …". The raw type's
/// module doc carries a one-line back-pointer to the impl.
pub trait Verify<Ctx>: Sized {
    /// Byproduct surfaced by verification. `()` for witness-style verifiers
    /// (signature checks, merkle-root recomputes); a real type when the
    /// verifier produces data the caller wants downstream (e.g. a JMT
    /// prepared-commit handle).
    type Augment;

    /// Per-verifier error type. Names the exact failure modes the
    /// predicate can produce; strengthening the predicate requires
    /// extending this enum, which is visible in the type's home module
    /// at review time.
    type Error;

    /// Run the predicate, producing a verified value on success.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] with the variant describing the failure.
    fn verify(&self, ctx: Ctx) -> Result<Verified<Self, Self::Augment>, Self::Error>;
}

/// Sealed value carrying the type-level claim that `T`'s verification
/// predicate has been checked.
///
/// The inner `T` is reachable read-only via `Deref<Target = T>` (and
/// `AsRef<T>`). For augmenting verifiers, the byproduct sits in `augment`,
/// accessible via [`Self::augment`] or [`Self::into_parts`].
///
/// Construction is restricted to three gates: [`Verify::verify`],
/// [`Self::new_unchecked`] / [`Self::new_unchecked_with`] (audited), and
/// inherent `compute` / `genesis` / `assemble` constructors on specific
/// monomorphizations (`impl Verified<X> { ... }`) in the raw type's
/// module.
#[derive(Debug, Clone, Copy)]
pub struct Verified<T, A = ()> {
    inner: T,
    augment: A,
}

impl<T, A> Verified<T, A> {
    /// Audit-point constructor carrying an explicit augment. Skips the
    /// predicate.
    ///
    /// Permitted use sites: storage-recovery (value was verified before
    /// persistence), `PendingAssembly` slot prefill (skipped or
    /// previously-verified roots), and `build_qc_from_verified`-style
    /// re-wraps of values assembled from already-verified inputs. Every
    /// call site carries a `// SAFETY:` comment naming the trust source.
    /// `grep new_unchecked` produces the audit list.
    #[must_use]
    pub const fn new_unchecked_with(inner: T, augment: A) -> Self {
        Self { inner, augment }
    }

    /// Borrow the augmenting byproduct.
    pub const fn augment(&self) -> &A {
        &self.augment
    }

    /// Consume and return both halves.
    #[must_use]
    pub fn into_parts(self) -> (T, A) {
        (self.inner, self.augment)
    }

    /// Consume and return the raw inner, dropping the verified claim and
    /// any augmenting byproduct.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> Verified<T, ()> {
    /// Audit-point constructor for the witness form. Skips the predicate.
    ///
    /// Same audit policy as [`Self::new_unchecked_with`]; the witness
    /// variant doesn't need an augment value.
    #[must_use]
    pub const fn new_unchecked(inner: T) -> Self {
        Self { inner, augment: () }
    }
}

impl<T, A> AsRef<T> for Verified<T, A> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T, A> Deref for Verified<T, A> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: PartialEq> PartialEq for Verified<T, ()> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Eq> Eq for Verified<T, ()> {}

impl<T: Hash> Hash for Verified<T, ()> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

/// Typestate wrapper carrying either the raw form `T` or a witness-form
/// [`Verified<T>`].
///
/// See the module-level docs for the design contract. Augmenting verified
/// values don't ride through `Verifiable` — their byproducts side-channel
/// through code-local storage.
#[derive(Debug, Clone)]
pub enum Verifiable<T> {
    /// Decoded-from-wire or freshly-constructed value that has not yet
    /// passed its verification predicate.
    Unverified(T),
    /// Value carrying the type-level claim that its predicate has been
    /// checked.
    Verified(Verified<T>),
}

impl<T> Verifiable<T> {
    /// Borrow the raw content regardless of variant.
    pub fn as_unverified(&self) -> &T {
        match self {
            Self::Unverified(t) => t,
            Self::Verified(v) => v.as_ref(),
        }
    }

    /// Borrow the verified value if this wrapper has been upgraded.
    pub const fn verified(&self) -> Option<&Verified<T>> {
        match self {
            Self::Verified(v) => Some(v),
            Self::Unverified(_) => None,
        }
    }

    /// Consume the wrapper and return the raw `T`, dropping the verified
    /// claim if present.
    pub fn into_unverified(self) -> T {
        match self {
            Self::Unverified(t) => t,
            Self::Verified(v) => v.into_inner(),
        }
    }

    /// Replace an `Unverified` value with its verified form in place.
    /// No-op on a value that is already `Verified`. Returns a reference to
    /// the verified inner.
    ///
    /// Only available when `T`'s verifier is witness-style
    /// (`Augment = ()`); augmenting verifiers don't fit `Verifiable`'s
    /// single-slot shape.
    ///
    /// # Errors
    ///
    /// Returns `<T as Verify<Ctx>>::Error` if the predicate fails. The
    /// wrapper is left in its `Unverified` state on failure.
    pub fn upgrade_in_place<Ctx>(&mut self, ctx: Ctx) -> Result<&Verified<T>, T::Error>
    where
        T: Verify<Ctx, Augment = ()>,
    {
        let verified = match self {
            Self::Verified(_) => None,
            Self::Unverified(t) => Some(t.verify(ctx)?),
        };
        if let Some(v) = verified {
            *self = Self::Verified(v);
        }
        match self {
            Self::Verified(v) => Ok(v),
            Self::Unverified(_) => unreachable!("just set above"),
        }
    }
}

impl<T: PartialEq> PartialEq for Verifiable<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_unverified() == other.as_unverified()
    }
}

impl<T: Eq> Eq for Verifiable<T> {}

impl<T: Hash> Hash for Verifiable<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_unverified().hash(state);
    }
}

impl<T> From<T> for Verifiable<T> {
    fn from(t: T) -> Self {
        Self::Unverified(t)
    }
}

impl<T> From<Verified<T>> for Verifiable<T> {
    fn from(v: Verified<T>) -> Self {
        Self::Verified(v)
    }
}

/// Deref to the raw `T` so consumers can call `T`'s accessor methods on
/// the wrapper without an explicit `.as_unverified()` hop. The wrapper
/// is for storage (struct fields, event payloads, buffers), not for
/// function signatures: a container that holds `Verifiable<T>` reads
/// the same as one that holds `T` for callers that only need raw
/// fields. Verified-aware code uses [`Self::verified`] explicitly to
/// branch on the marker.
impl<T> Deref for Verifiable<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.as_unverified()
    }
}

// ── SBOR codec forwarding: encode/decode/describe identically to T ──

impl<T> Categorize<NoCustomValueKind> for Verifiable<T>
where
    T: Categorize<NoCustomValueKind>,
{
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        T::value_kind()
    }
}

impl<T, E> Encode<NoCustomValueKind, E> for Verifiable<T>
where
    T: Encode<NoCustomValueKind, E> + Categorize<NoCustomValueKind>,
    E: Encoder<NoCustomValueKind>,
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.as_unverified().encode_value_kind(encoder)
    }
    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.as_unverified().encode_body(encoder)
    }
}

impl<T, D> Decode<NoCustomValueKind, D> for Verifiable<T>
where
    T: Decode<NoCustomValueKind, D> + Categorize<NoCustomValueKind>,
    D: Decoder<NoCustomValueKind>,
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        let t = T::decode_body_with_value_kind(decoder, value_kind)?;
        Ok(Self::Unverified(t))
    }
}

impl<T> Describe<NoCustomTypeKind> for Verifiable<T>
where
    T: Describe<NoCustomTypeKind>,
{
    const TYPE_ID: RustTypeId = <T as Describe<NoCustomTypeKind>>::TYPE_ID;
    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        <T as Describe<NoCustomTypeKind>>::type_data()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sbor::{basic_decode, basic_encode};

    use super::*;

    /// Test-only verifier error. Each real verifier defines its own
    /// per-type error enum; this one is a stub that never produces a
    /// value (verification on `u32` is infallible in the test fixture).
    #[derive(Debug, PartialEq, Eq)]
    pub enum VForTestError {}

    impl Verify<()> for u32 {
        type Augment = ();
        type Error = VForTestError;
        fn verify(&self, _ctx: ()) -> Result<Verified<Self>, Self::Error> {
            Ok(Verified::new_unchecked(*self))
        }
    }

    type V = Verifiable<u32>;

    #[test]
    fn verifiable_encode_matches_inner_regardless_of_state() {
        let u: u32 = 0xABCD_1234;
        let unverified: V = Verifiable::Unverified(u);
        let verified: V = Verifiable::Verified(Verified::new_unchecked(u));

        let bare = basic_encode(&u).unwrap();
        let unv = basic_encode(&unverified).unwrap();
        let ver = basic_encode(&verified).unwrap();

        assert_eq!(bare, unv, "Unverified must encode byte-identically to T");
        assert_eq!(bare, ver, "Verified must encode byte-identically to T");
    }

    #[test]
    fn verifiable_decodes_as_unverified() {
        let u: u32 = 7;
        let bytes = basic_encode(&u).unwrap();
        let decoded: V = basic_decode(&bytes).unwrap();
        match decoded {
            Verifiable::Unverified(x) => assert_eq!(x, u),
            Verifiable::Verified(_) => panic!("wire decode must land in Unverified"),
        }
    }

    #[test]
    fn verifiable_equality_across_states() {
        let u: u32 = 42;
        let unv: V = Verifiable::Unverified(u);
        let ver: V = Verifiable::Verified(Verified::new_unchecked(u));
        assert_eq!(unv, ver);
        assert_eq!(ver, unv);

        let other_unv: V = Verifiable::Unverified(43);
        assert_ne!(unv, other_unv);
    }

    /// `HashMap` lookup must find an entry inserted as `Unverified(t)` when
    /// the query key is `Verified(v)` with the same underlying content,
    /// and vice-versa. This is what makes
    /// [`coordinator.rs:1129`](../../shard/src/coordinator.rs#L1129)'s
    /// cached-vs-incoming check work after the field becomes `Verifiable`.
    #[test]
    fn verifiable_hashmap_collision_across_states() {
        let u: u32 = 0xDEAD_BEEF;

        let unv: V = Verifiable::Unverified(u);
        let ver: V = Verifiable::Verified(Verified::new_unchecked(u));

        let mut by_unverified: HashMap<V, &'static str> = HashMap::new();
        by_unverified.insert(unv.clone(), "inserted as unverified");
        assert_eq!(
            by_unverified.get(&ver),
            Some(&"inserted as unverified"),
            "Verified key must find an entry inserted under the T-equivalent Unverified key"
        );

        let mut by_verified: HashMap<V, &'static str> = HashMap::new();
        by_verified.insert(ver, "inserted as verified");
        assert_eq!(
            by_verified.get(&unv),
            Some(&"inserted as verified"),
            "Unverified key must find an entry inserted under the T-equivalent Verified key"
        );
    }

    #[test]
    fn verifiable_from_raw_produces_unverified() {
        let u: u32 = 99;
        let v: V = u.into();
        assert!(matches!(v, Verifiable::Unverified(99)));
    }

    #[test]
    fn verifiable_from_verified_produces_verified() {
        let v: V = Verified::new_unchecked(99u32).into();
        assert!(matches!(v, Verifiable::Verified(_)));
        match v {
            Verifiable::Verified(inner) => assert_eq!(*inner, 99),
            Verifiable::Unverified(_) => unreachable!(),
        }
    }

    #[test]
    fn upgrade_in_place_unverified_becomes_verified() {
        let mut v: V = Verifiable::Unverified(123);
        let r = v.upgrade_in_place(()).unwrap();
        assert_eq!(r.as_ref(), &123);
        assert!(matches!(v, Verifiable::Verified(_)));
    }

    #[test]
    fn upgrade_in_place_verified_is_noop() {
        let mut v: V = Verifiable::Verified(Verified::new_unchecked(7));
        let r = v.upgrade_in_place(()).unwrap();
        assert_eq!(r.as_ref(), &7);
    }

    // ── Augment-slot exercise ──

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AugTag(String);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AugInput(u32);

    #[derive(Debug, PartialEq, Eq)]
    enum AugError {}

    impl Verify<&str> for AugInput {
        type Augment = AugTag;
        type Error = AugError;
        fn verify(&self, ctx: &str) -> Result<Verified<Self, AugTag>, Self::Error> {
            Ok(Verified::new_unchecked_with(
                self.clone(),
                AugTag(ctx.to_owned()),
            ))
        }
    }

    #[test]
    fn augmenting_verify_carries_byproduct() {
        let input = AugInput(42);
        let verified = input.verify("hello").unwrap();
        assert_eq!(verified.as_ref(), &AugInput(42));
        assert_eq!(verified.augment(), &AugTag("hello".to_owned()));

        let (inner, augment) = verified.into_parts();
        assert_eq!(inner, AugInput(42));
        assert_eq!(augment, AugTag("hello".to_owned()));
    }
}
