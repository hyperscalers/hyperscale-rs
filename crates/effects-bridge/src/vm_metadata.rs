//! The package-metadata section codec, as the chain reaches it.
//!
//! Both the codec and the byte budget are [`hyperscale_vm_gate`]'s: the
//! cap is a share of [`MAX_ARTIFACT_BYTES`], which is the vocabulary's
//! own constant, so the number and the encoding it bounds sit together.
//! What this module adds is the chain's error type.
//!
//! [`MAX_ARTIFACT_BYTES`]: hyperscale_types::MAX_ARTIFACT_BYTES

use hyperscale_types::DerivationError;
use hyperscale_vm_effects::PackageMetadata;
pub use hyperscale_vm_gate::MAX_PACKAGE_METADATA_BYTES;
use hyperscale_vm_gate::{
    decode_metadata as decode_canonical, encode_metadata as encode_canonical,
};

/// Encode package metadata into its canonical section bytes.
///
/// # Errors
///
/// [`DerivationError`] if the metadata is past a bound decode enforces, so
/// that whatever this returns decodes back to an equal value.
pub fn encode_metadata(metadata: &PackageMetadata) -> Result<Vec<u8>, DerivationError> {
    encode_canonical(metadata).map_err(|error| DerivationError::Refused(error.to_string()))
}

/// Decode a metadata section's canonical bytes.
///
/// # Errors
///
/// [`DerivationError`] if the payload is oversized, not canonical, or not
/// metadata at all.
pub fn decode_metadata(bytes: &[u8]) -> Result<PackageMetadata, DerivationError> {
    decode_canonical(bytes).map_err(|error| DerivationError::Refused(error.to_string()))
}
