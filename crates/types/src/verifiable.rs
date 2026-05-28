//! Typestate wrapper that carries verification status with a value.
//!
//! A [`Verifiable<T>`] holds either the raw wire form `T` or a [`Verified<T>`]
//! value carrying the type-level claim that `T`'s verification predicate has
//! been checked. Its SBOR encoding is byte-identical to `T`; decoding always
//! lands in [`Verifiable::Unverified`]. Verification produces
//! [`Verifiable::Verified`] in place; the marker rides with the value through
//! ordinary moves, clones, and local-dispatch handoffs.
//!
//! Read-only access to the inner `T` is via `Deref<Target = T>` (and the
//! `AsRef<T>` it implies). No `&mut`, no `AsMut`, no `Encode`/`Decode` on
//! `Verified<T>` — verified values cannot be produced from wire bytes.
//!
//! # Equality and hashing
//!
//! `Verifiable<T>` values compare and hash by their raw `T` content,
//! regardless of variant. This is the only equality semantics that
//! round-trips through SBOR and works in `HashMap<_, Verifiable<T>>`
//! lookups against newly-decoded wire values. `Verified<T>` compares by
//! inner `T`.
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
/// etc.); the associated [`Error`](Self::Error) is the per-verifier
/// failure-mode vocabulary, defined in the same module as the raw type so
/// the type owns its full predicate contract.
///
/// The `Verify` impl's doc comment is the canonical home of the predicate
/// specification, in the format "Construction asserts: …". The raw type's
/// module doc carries a one-line back-pointer to the impl.
pub trait Verify<Ctx>: Sized {
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
    fn verify(&self, ctx: Ctx) -> Result<Verified<Self>, Self::Error>;
}

/// Sealed value carrying the type-level claim that `T`'s verification
/// predicate has been checked.
///
/// The inner `T` is reachable read-only via `Deref<Target = T>` (and
/// `AsRef<T>`).
///
/// Construction is restricted to three gates: [`Verify::verify`],
/// [`Self::new_unchecked`] (audited), and inherent `compute` / `genesis`
/// / `assemble` / `from_qc_attestation` / `sign_local` constructors on
/// specific monomorphizations (`impl Verified<X> { ... }`) in the raw
/// type's module.
#[derive(Debug, Clone, Copy)]
pub struct Verified<T> {
    inner: T,
}

impl<T> Verified<T> {
    /// Construct a verified value without running the predicate. The
    /// caller asserts the predicate holds via an out-of-band trust source.
    ///
    /// Production callers reach this through named typed gates defined
    /// inside `crates/types`, each delegating here under a documented
    /// trust source. The only outside-`crates/types` access is via
    /// [`Self::new_unchecked_for_test`], re-exported behind the
    /// `test-utils` feature for fixture construction.
    #[must_use]
    pub(crate) const fn new_unchecked(inner: T) -> Self {
        Self { inner }
    }

    /// Test-only [`Self::new_unchecked`]. Available behind `#[cfg(test)]`
    /// inside `crates/types` and to downstream crates that enable the
    /// `test-utils` feature.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn new_unchecked_for_test(inner: T) -> Self {
        Self::new_unchecked(inner)
    }

    /// Consume and return the raw inner, dropping the verified claim.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsRef<T> for Verified<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> Deref for Verified<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: PartialEq> PartialEq for Verified<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Eq> Eq for Verified<T> {}

impl<T: Hash> Hash for Verified<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

/// Typestate wrapper carrying either the raw form `T` or a verified form
/// [`Verified<T>`].
///
/// The wrapper's two-state taxonomy is a private implementation detail
/// of this module. Construction goes through the [`From`] impls
/// (`T → Verifiable<T>::Unverified` and `Verified<T> → Verifiable<T>::Verified`);
/// inspection goes through [`Self::is_verified`], [`Self::verified`],
/// [`Self::into_verified`], [`Self::upgrade`], and the
/// [`Deref<Target = T>`](Deref) raw-access path.
///
/// See the module-level docs for the design contract.
#[derive(Debug, Clone)]
pub struct Verifiable<T>(VerifiableState<T>);

/// Internal taxonomy of a [`Verifiable<T>`]. Kept private so the
/// two-state design isn't part of the public API surface — extending
/// the taxonomy (e.g. negative caching) wouldn't be a breaking change
/// to downstream pattern matches.
#[derive(Debug, Clone)]
enum VerifiableState<T> {
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
        match &self.0 {
            VerifiableState::Unverified(t) => t,
            VerifiableState::Verified(v) => v.as_ref(),
        }
    }

    /// Borrow the verified value if this wrapper has been upgraded.
    pub const fn verified(&self) -> Option<&Verified<T>> {
        match &self.0 {
            VerifiableState::Verified(v) => Some(v),
            VerifiableState::Unverified(_) => None,
        }
    }

    /// Consume the wrapper and return the raw `T`, dropping the verified
    /// claim if present.
    pub fn into_unverified(self) -> T {
        match self.0 {
            VerifiableState::Unverified(t) => t,
            VerifiableState::Verified(v) => v.into_inner(),
        }
    }

    /// Replace an `Unverified` value with its verified form in place.
    /// No-op on a value that is already `Verified`. Returns a reference to
    /// the verified inner.
    ///
    /// # Errors
    ///
    /// Returns `<T as Verify<Ctx>>::Error` if the predicate fails. The
    /// wrapper is left in its `Unverified` state on failure.
    pub fn upgrade_in_place<Ctx>(&mut self, ctx: Ctx) -> Result<&Verified<T>, T::Error>
    where
        T: Verify<Ctx>,
    {
        let verified = match &self.0 {
            VerifiableState::Verified(_) => None,
            VerifiableState::Unverified(t) => Some(t.verify(ctx)?),
        };
        if let Some(v) = verified {
            self.0 = VerifiableState::Verified(v);
        }
        match &self.0 {
            VerifiableState::Verified(v) => Ok(v),
            VerifiableState::Unverified(_) => unreachable!("just set above"),
        }
    }

    /// Consume and return a [`Verified<T>`], running `Verify::verify`
    /// only when the marker isn't already live. The verified arm
    /// short-circuits; the unverified arm runs the predicate and
    /// packages the raw value alongside the error on failure so the
    /// caller can still report or buffer it.
    ///
    /// # Errors
    ///
    /// Returns `(T, <T as Verify<Ctx>>::Error)` if the predicate fails
    /// on the unverified arm.
    pub fn upgrade<Ctx>(self, ctx: Ctx) -> Result<Verified<T>, (T, T::Error)>
    where
        T: Verify<Ctx>,
    {
        match self.0 {
            VerifiableState::Verified(v) => Ok(v),
            VerifiableState::Unverified(t) => match t.verify(ctx) {
                Ok(v) => Ok(v),
                Err(e) => Err((t, e)),
            },
        }
    }

    /// Whether the wrapper holds a verified value. Named alias of
    /// `self.verified().is_some()` for readable assertions.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self.0, VerifiableState::Verified(_))
    }

    /// Consume the wrapper, returning `Ok(verified)` when the marker
    /// is live and `Err(raw)` when it isn't — the unverified arm has
    /// to be matched, so the raw cannot silently disappear. Callers
    /// that want to verify on the `Err` arm should use
    /// [`Self::upgrade`] instead.
    ///
    /// Sized for the narrow case where an upstream type-level invariant
    /// already proves the wrapper is verified and the caller wants the
    /// inner [`Verified<T>`] by value without running the predicate.
    ///
    /// # Errors
    ///
    /// Returns the recovered raw `T` on the unverified arm.
    pub fn into_verified(self) -> Result<Verified<T>, T> {
        match self.0 {
            VerifiableState::Verified(v) => Ok(v),
            VerifiableState::Unverified(t) => Err(t),
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
        Self(VerifiableState::Unverified(t))
    }
}

impl<T> From<Verified<T>> for Verifiable<T> {
    fn from(v: Verified<T>) -> Self {
        Self(VerifiableState::Verified(v))
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
        Ok(Self(VerifiableState::Unverified(t)))
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
        type Error = VForTestError;
        fn verify(&self, _ctx: ()) -> Result<Verified<Self>, Self::Error> {
            Ok(Verified::new_unchecked(*self))
        }
    }

    type V = Verifiable<u32>;

    #[test]
    fn verifiable_encode_matches_inner_regardless_of_state() {
        let u: u32 = 0xABCD_1234;
        let unverified: V = u.into();
        let verified: V = Verified::new_unchecked(u).into();

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
        assert!(!decoded.is_verified(), "wire decode must land Unverified");
        assert_eq!(*decoded, u);
    }

    #[test]
    fn verifiable_equality_across_states() {
        let u: u32 = 42;
        let unv: V = u.into();
        let ver: V = Verified::new_unchecked(u).into();
        assert_eq!(unv, ver);
        assert_eq!(ver, unv);

        let other_unv: V = 43u32.into();
        assert_ne!(unv, other_unv);
    }

    /// `HashMap` lookup must find an entry inserted as the unverified
    /// state when the query key is in the verified state with the same
    /// underlying content, and vice-versa. Underpins the
    /// cached-vs-incoming lookups in the shard coordinator's verified-QC
    /// cache, which key off the raw `block_hash` regardless of the
    /// candidate's current marker.
    #[test]
    fn verifiable_hashmap_collision_across_states() {
        let u: u32 = 0xDEAD_BEEF;

        let unv: V = u.into();
        let ver: V = Verified::new_unchecked(u).into();

        let mut by_unverified: HashMap<V, &'static str> = HashMap::new();
        by_unverified.insert(unv.clone(), "inserted as unverified");
        assert_eq!(
            by_unverified.get(&ver),
            Some(&"inserted as unverified"),
            "verified key must find an entry inserted under the T-equivalent unverified key"
        );

        let mut by_verified: HashMap<V, &'static str> = HashMap::new();
        by_verified.insert(ver, "inserted as verified");
        assert_eq!(
            by_verified.get(&unv),
            Some(&"inserted as verified"),
            "unverified key must find an entry inserted under the T-equivalent verified key"
        );
    }

    #[test]
    fn verifiable_from_raw_produces_unverified() {
        let v: V = 99u32.into();
        assert!(!v.is_verified());
        assert_eq!(*v, 99);
    }

    #[test]
    fn verifiable_from_verified_produces_verified() {
        let v: V = Verified::new_unchecked(99u32).into();
        assert!(v.is_verified());
        assert_eq!(*v, 99);
        let inner = v.into_verified().expect("verified arm");
        assert_eq!(*inner, 99);
    }

    #[test]
    fn upgrade_in_place_unverified_becomes_verified() {
        let mut v: V = 123u32.into();
        let r = v.upgrade_in_place(()).unwrap();
        assert_eq!(r.as_ref(), &123);
        assert!(v.is_verified());
    }

    #[test]
    fn upgrade_in_place_verified_is_noop() {
        let mut v: V = Verified::new_unchecked(7u32).into();
        let r = v.upgrade_in_place(()).unwrap();
        assert_eq!(r.as_ref(), &7);
    }

    /// Test-only verifier that always fails, paired with `u64` so it
    /// doesn't collide with the infallible `u32` verifier above.
    #[derive(Debug, PartialEq, Eq)]
    pub struct AlwaysFails;

    impl Verify<()> for u64 {
        type Error = AlwaysFails;
        fn verify(&self, _ctx: ()) -> Result<Verified<Self>, Self::Error> {
            Err(AlwaysFails)
        }
    }

    #[test]
    fn upgrade_verified_short_circuits() {
        let v: V = Verified::new_unchecked(7u32).into();
        let verified = v.upgrade(()).expect("verified arm short-circuits");
        assert_eq!(verified.as_ref(), &7);
    }

    #[test]
    fn upgrade_unverified_runs_predicate() {
        let v: V = 42u32.into();
        let verified = v.upgrade(()).expect("u32 verifier is infallible");
        assert_eq!(verified.as_ref(), &42);
    }

    #[test]
    fn upgrade_unverified_packages_raw_with_error() {
        let v: Verifiable<u64> = 99u64.into();
        let (raw, err) = v.upgrade(()).expect_err("u64 verifier always fails");
        assert_eq!(raw, 99);
        assert_eq!(err, AlwaysFails);
    }

    #[test]
    fn is_verified_matches_state() {
        let unv: V = 7u32.into();
        let ver: V = Verified::new_unchecked(7u32).into();
        assert!(!unv.is_verified());
        assert!(ver.is_verified());
    }

    #[test]
    fn into_verified_extracts_only_verified_arm() {
        let ver: V = Verified::new_unchecked(7u32).into();
        let inner = ver.into_verified().expect("verified arm yields Ok");
        assert_eq!(inner.as_ref(), &7);

        let unv: V = 99u32.into();
        let raw = unv
            .into_verified()
            .expect_err("unverified arm yields Err with the raw");
        assert_eq!(raw, 99);
    }
}
