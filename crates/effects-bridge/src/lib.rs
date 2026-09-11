//! The workspace's binding to the VM effect vocabulary.
//!
//! [`ProtocolHasher`] puts the protocol hash — blake3 — behind the
//! `vm_effects` hashing seam: domain-separated and length-framed, so a
//! part boundary is always semantic. [`BridgeStatics`] derives a signed
//! envelope's admission keys, participant prefixes and subintent claims
//! through it; [`admit_package`] judges a publish; [`PoolRegistry`] reads
//! a recognised pool's events as beacon facts.

pub mod artifact;
pub mod genesis;
pub mod records;
pub mod staking;
pub mod vm_metadata;
pub mod vm_statics;

pub use artifact::{
    METADATA_SECTION, admit_package, admit_protocol_package, attach_metadata, extract_metadata,
};
pub use hyperscale_types::ProtocolHasher;
pub use records::{LocalCells, NodeRecords};
pub use staking::{PoolRegistry, witness_from_event};
pub use vm_metadata::{MAX_PACKAGE_METADATA_BYTES, decode_metadata, encode_metadata};
pub use vm_statics::{
    BridgeStatics, XRD, account_address, declared_footprint, decode_tree, draw_key, encode_tree,
    envelope_identity, validator_key, vault_key,
};

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::Hasher;
    use hyperscale_vm_effects::vectors::{address_vector_lines, address_vectors, expected_classes};

    use super::ProtocolHasher;

    #[test]
    fn derivation_vectors_are_pinned_under_the_protocol_hash() {
        // The same corpus the vocabulary crate pins under its test
        // hasher, pinned here under the hash consensus actually runs. An
        // address is where a substate lives, so a derivation that moves
        // moves state; these values change only with a deliberate
        // protocol version change.
        assert_eq!(
            address_vector_lines(&ProtocolHasher),
            vec![
                "principal/ed25519/a = 6cfc6f85164212524c59a6cd6b1df06cfa231522715d0748d7fe5adf1cda2401",
                "principal/ed25519/b = eef14e9e4037201e80c2cc20ce863c237f751c337d87224ae1d56d1e53363b01",
                "component/salted = 6abb649cd46f582de44c4ec573818a3c678f643292307e48ac94e49d7fa7b702",
                "package/content = 7e5f726fe1bb474718cfd6c20c04e2cd10de46768f830dabdc8845f0e2bc1e03",
                "resource/minted = e7ade2f9f5f36c4a571c1f0f003b6a5e3a788d18362634e11b9d82df673bd404",
                "resource/minted-nf = ac913fc5425c3f6b4712e91099ef2754b4d739998d3bdee9eff308794405b904",
                "native/genesis-publisher = a8d17f712889af8c3657c416f393543e4c7c2871c0e361decaedefda4fc9c705",
                "resource/xrd = f0762f0fd514e13031e6b12df742a5901b263aec476126ca1bc0b130bc0d3d04",
            ]
        );
    }

    #[test]
    fn every_derivation_carries_its_own_class_under_the_protocol_hash() {
        let derived = address_vectors(&ProtocolHasher);
        let expected = expected_classes();
        assert_eq!(derived.len(), expected.len());
        for ((name, address), (expected_name, class)) in derived.iter().zip(expected) {
            assert_eq!(*name, expected_name);
            assert_eq!(address.class(), class, "{name}");
        }
    }

    #[test]
    fn the_protocol_hasher_is_deterministic_framed_and_domain_separated() {
        let a = ProtocolHasher.hash(b"d", &[b"ab", b"c"]);
        assert_eq!(a, ProtocolHasher.hash(b"d", &[b"ab", b"c"]));
        // Part boundaries are semantic.
        assert_ne!(a, ProtocolHasher.hash(b"d", &[b"a", b"bc"]));
        assert_ne!(a, ProtocolHasher.hash(b"d", &[b"abc"]));
        // Domains separate.
        assert_ne!(a, ProtocolHasher.hash(b"e", &[b"ab", b"c"]));
    }
}
