//! Typestate wrapper that carries verification status with a value.
//!
//! A [`Verifiable<U, V>`] holds either the raw wire form `U` or a verified
//! newtype `V`. Its SBOR encoding is byte-identical to `U`; decoding always
//! lands in [`Verifiable::Unverified`]. Verification produces
//! [`Verifiable::Verified`] in place; the marker rides with the value through
//! ordinary moves, clones, and local-dispatch handoffs.
//!
//! `V` is constrained as `AsRef<U>` so the raw content is always reachable;
//! verified newtypes are sealed `#[repr(transparent)]` wrappers around `U`
//! whose only public read surface is `Deref<Target = U>` (which gives the
//! `AsRef<U>` impl).
//!
//! # Equality and hashing
//!
//! `Verifiable<U, V>` values compare and hash by their raw `U` content,
//! regardless of variant. This is the only equality semantics that
//! round-trips through SBOR and works in `HashMap<_, Verifiable<U, V>>`
//! lookups against newly-decoded wire values.
//!
//! # `From` impls
//!
//! `From<U> for Verifiable<U, V>` produces [`Verifiable::Unverified`].
//! There is no `From<V>` impl — under the blanket `AsRef<T> for T` it
//! would overlap with `From<U>` when `U = V`. Verified-direction
//! construction uses the variant constructor: `Verifiable::Verified(v)`.
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
/// etc.). The associated [`Verified`](Self::Verified) is the sealed newtype
/// returned on success; the associated [`Error`](Self::Error) is the
/// per-verifier failure-mode vocabulary, defined in the same module as the
/// raw type so the type owns its full predicate contract.
pub trait Verify<Ctx> {
    /// Sealed newtype carrying the "predicate passed" guarantee.
    type Verified: AsRef<Self>;

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
    fn verify(&self, ctx: Ctx) -> Result<Self::Verified, Self::Error>;
}

/// Typestate wrapper carrying either the raw form `U` or a verified `V`.
///
/// See the module-level docs for the design contract.
#[derive(Debug, Clone)]
pub enum Verifiable<U, V: AsRef<U>> {
    /// Decoded-from-wire or freshly-constructed value that has not yet
    /// passed its verification predicate.
    Unverified(U),
    /// Value carrying the type-level claim that its predicate has been
    /// checked.
    Verified(V),
}

impl<U, V: AsRef<U>> Verifiable<U, V> {
    /// Borrow the raw content regardless of variant.
    pub fn as_unverified(&self) -> &U {
        match self {
            Self::Unverified(u) => u,
            Self::Verified(v) => v.as_ref(),
        }
    }

    /// Borrow the verified newtype if this value has been verified.
    pub const fn verified(&self) -> Option<&V> {
        match self {
            Self::Verified(v) => Some(v),
            Self::Unverified(_) => None,
        }
    }

    /// Consume the wrapper and return the raw `U`, dropping the verified
    /// claim if present.
    pub fn into_unverified(self) -> U
    where
        V: Into<U>,
    {
        match self {
            Self::Unverified(u) => u,
            Self::Verified(v) => v.into(),
        }
    }

    /// Replace an `Unverified` value with its verified form in place.
    /// No-op on a value that is already `Verified`. Returns a reference to
    /// the verified inner.
    ///
    /// # Errors
    ///
    /// Returns `<U as Verify<Ctx>>::Error` if the predicate fails. The
    /// wrapper is left in its `Unverified` state on failure.
    pub fn upgrade_in_place<Ctx>(&mut self, ctx: Ctx) -> Result<&V, <U as Verify<Ctx>>::Error>
    where
        U: Verify<Ctx, Verified = V>,
    {
        let verified = match self {
            Self::Verified(_) => None,
            Self::Unverified(u) => Some(u.verify(ctx)?),
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

impl<U: PartialEq, V: AsRef<U>> PartialEq for Verifiable<U, V> {
    fn eq(&self, other: &Self) -> bool {
        self.as_unverified() == other.as_unverified()
    }
}

impl<U: Eq, V: AsRef<U>> Eq for Verifiable<U, V> {}

impl<U: Hash, V: AsRef<U>> Hash for Verifiable<U, V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_unverified().hash(state);
    }
}

impl<U, V: AsRef<U>> From<U> for Verifiable<U, V> {
    fn from(u: U) -> Self {
        Self::Unverified(u)
    }
}

/// Deref to the raw `U` so consumers can call `U`'s accessor methods on
/// the wrapper without an explicit `.as_unverified()` hop. This is the
/// read-only equivalent of the plan's "wrapper is for storage, not
/// function signatures" — callers reading off the wire form keep
/// working unchanged after a container's field type changes from `U` to
/// `Verifiable<U, V>`. Verified-aware code uses [`Self::verified`]
/// explicitly to branch on the marker.
impl<U, V: AsRef<U>> Deref for Verifiable<U, V> {
    type Target = U;
    fn deref(&self) -> &U {
        self.as_unverified()
    }
}

// ── SBOR codec forwarding: encode/decode/describe identically to U ──

impl<U, V> Categorize<NoCustomValueKind> for Verifiable<U, V>
where
    U: Categorize<NoCustomValueKind>,
    V: AsRef<U>,
{
    fn value_kind() -> ValueKind<NoCustomValueKind> {
        U::value_kind()
    }
}

impl<U, V, E> Encode<NoCustomValueKind, E> for Verifiable<U, V>
where
    U: Encode<NoCustomValueKind, E> + Categorize<NoCustomValueKind>,
    V: AsRef<U>,
    E: Encoder<NoCustomValueKind>,
{
    fn encode_value_kind(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.as_unverified().encode_value_kind(encoder)
    }
    fn encode_body(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.as_unverified().encode_body(encoder)
    }
}

impl<U, V, D> Decode<NoCustomValueKind, D> for Verifiable<U, V>
where
    U: Decode<NoCustomValueKind, D> + Categorize<NoCustomValueKind>,
    V: AsRef<U>,
    D: Decoder<NoCustomValueKind>,
{
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        let u = U::decode_body_with_value_kind(decoder, value_kind)?;
        Ok(Self::Unverified(u))
    }
}

impl<U, V> Describe<NoCustomTypeKind> for Verifiable<U, V>
where
    U: Describe<NoCustomTypeKind>,
    V: AsRef<U>,
{
    const TYPE_ID: RustTypeId = <U as Describe<NoCustomTypeKind>>::TYPE_ID;
    fn type_data() -> TypeData<NoCustomTypeKind, RustTypeId> {
        <U as Describe<NoCustomTypeKind>>::type_data()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sbor::{basic_decode, basic_encode};

    use super::*;

    /// Sealed verified newtype over `u32` for trait-shape exercises.
    /// Mirrors the real `Verified*` shape: private field, only-`AsRef`
    /// public read access. `pub` inside the test module so the
    /// `Verify` impl on the foreign type `u32` doesn't leak a private
    /// associated type.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VForTest(u32);

    impl AsRef<u32> for VForTest {
        fn as_ref(&self) -> &u32 {
            &self.0
        }
    }

    /// Test-only verifier error. Each real verifier defines its own
    /// per-type error enum; this one is a stub that never produces a
    /// value (verification on `u32` is infallible in the test fixture).
    #[derive(Debug, PartialEq, Eq)]
    pub enum VForTestError {}

    impl Verify<()> for u32 {
        type Verified = VForTest;
        type Error = VForTestError;
        fn verify(&self, _ctx: ()) -> Result<Self::Verified, Self::Error> {
            Ok(VForTest(*self))
        }
    }

    type V = Verifiable<u32, VForTest>;

    #[test]
    fn verifiable_encode_matches_inner_regardless_of_state() {
        let u: u32 = 0xABCD_1234;
        let unverified: V = Verifiable::Unverified(u);
        let verified: V = Verifiable::Verified(VForTest(u));

        let bare = basic_encode(&u).unwrap();
        let unv = basic_encode(&unverified).unwrap();
        let ver = basic_encode(&verified).unwrap();

        assert_eq!(bare, unv, "Unverified must encode byte-identically to U");
        assert_eq!(bare, ver, "Verified must encode byte-identically to U");
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
        let ver: V = Verifiable::Verified(VForTest(u));
        assert_eq!(unv, ver);
        assert_eq!(ver, unv);

        let other_unv: V = Verifiable::Unverified(43);
        assert_ne!(unv, other_unv);
    }

    /// `HashMap` lookup must find an entry inserted as `Unverified(u)` when
    /// the query key is `Verified(v)` with the same underlying content,
    /// and vice-versa. This is what makes
    /// [`coordinator.rs:1129`](../../shard/src/coordinator.rs#L1129)'s
    /// cached-vs-incoming check work after the field becomes `Verifiable`.
    #[test]
    fn verifiable_hashmap_collision_across_states() {
        let u: u32 = 0xDEAD_BEEF;

        let unv: V = Verifiable::Unverified(u);
        let ver: V = Verifiable::Verified(VForTest(u));

        let mut by_unverified: HashMap<V, &'static str> = HashMap::new();
        by_unverified.insert(unv.clone(), "inserted as unverified");
        assert_eq!(
            by_unverified.get(&ver),
            Some(&"inserted as unverified"),
            "Verified key must find an entry inserted under the U-equivalent Unverified key"
        );

        let mut by_verified: HashMap<V, &'static str> = HashMap::new();
        by_verified.insert(ver, "inserted as verified");
        assert_eq!(
            by_verified.get(&unv),
            Some(&"inserted as verified"),
            "Unverified key must find an entry inserted under the U-equivalent Verified key"
        );
    }

    #[test]
    fn verifiable_from_impl_compiles_and_dispatches_unverified() {
        let u: u32 = 99;
        let v: V = u.into();
        assert!(matches!(v, Verifiable::Unverified(99)));
    }

    #[test]
    fn upgrade_in_place_unverified_becomes_verified() {
        let mut v: V = Verifiable::Unverified(123);
        let r = v.upgrade_in_place(()).unwrap();
        assert_eq!(r, &VForTest(123));
        assert!(matches!(v, Verifiable::Verified(VForTest(123))));
    }

    #[test]
    fn upgrade_in_place_verified_is_noop() {
        let mut v: V = Verifiable::Verified(VForTest(7));
        let r = v.upgrade_in_place(()).unwrap();
        assert_eq!(r, &VForTest(7));
    }
}
