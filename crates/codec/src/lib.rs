//! Codec facade for Hyperscale.
//!
//! All crates should import codec traits and functions through this crate
//! rather than depending on `sbor` directly. This centralizes the codec
//! dependency so a future migration has one place to change.

// Re-export everything from sbor's root (traits, functions, derive macros).
pub use sbor::*;

// Re-export the prelude module for `use hyperscale_codec::prelude::*;` patterns.
pub mod prelude {
    pub use sbor::prelude::*;
}

/// Implement SBOR Encode/Decode/Categorize/Describe for a struct whose fields
/// may include `Arc<T>` (which doesn't derive BasicSbor).
///
/// # Syntax
///
/// ```ignore
/// impl_sbor_for_generic_struct! {
///     struct TransactionGossip<C: TypeConfig> ["TransactionGossip"] {
///         // Encoded by deref through Arc, decoded into Arc::new(...)
///         transaction: Arc<C::Transaction>,
///         // Normal field — encoded/decoded directly
///         trace_context: TraceContext,
///     }
/// }
/// ```
///
/// - The string literal after the type params is the SBOR type name for `Describe`.
/// - Fields with type `Arc<...>` are automatically unwrapped for encode (`.as_ref()`)
///   and wrapped on decode (`Arc::new(...)`).
/// - All other fields are encoded/decoded directly.
#[macro_export]
macro_rules! impl_sbor_for_generic_struct {
    (
        struct $name:ident < $($gen:ident : $bound:path),+ > [ $type_name:literal ] {
            $( $field:ident : Arc< $inner:ty > ),+ $(,)?
            $(; $( $plain_field:ident : $plain_ty:ty ),+ $(,)? )?
        }
    ) => {
        impl<'__enc, $($gen: $bound),+>
            $crate::Encode<$crate::NoCustomValueKind, $crate::BasicEncoder<'__enc>>
            for $name<$($gen),+>
        {
            fn encode_value_kind(
                &self,
                encoder: &mut $crate::BasicEncoder<'__enc>,
            ) -> Result<(), $crate::EncodeError> {
                encoder.write_value_kind($crate::ValueKind::Tuple)
            }

            fn encode_body(
                &self,
                encoder: &mut $crate::BasicEncoder<'__enc>,
            ) -> Result<(), $crate::EncodeError> {
                let count = $crate::impl_sbor_for_generic_struct!(@count $($field),+ $($(, $plain_field)+)?);
                encoder.write_size(count)?;
                $(
                    $crate::Encoder::encode(encoder, self.$field.as_ref())?;
                )+
                $($(
                    $crate::Encoder::encode(encoder, &self.$plain_field)?;
                )+)?
                Ok(())
            }
        }

        impl<'__dec, $($gen: $bound),+>
            $crate::Decode<$crate::NoCustomValueKind, $crate::BasicDecoder<'__dec>>
            for $name<$($gen),+>
        {
            fn decode_body_with_value_kind(
                decoder: &mut $crate::BasicDecoder<'__dec>,
                value_kind: $crate::ValueKind<$crate::NoCustomValueKind>,
            ) -> Result<Self, $crate::DecodeError> {
                decoder.check_preloaded_value_kind(value_kind, $crate::ValueKind::Tuple)?;
                let length = decoder.read_size()?;
                let expected = $crate::impl_sbor_for_generic_struct!(@count $($field),+ $($(, $plain_field)+)?);
                if length != expected {
                    return Err($crate::DecodeError::UnexpectedSize {
                        expected,
                        actual: length,
                    });
                }
                Ok(Self {
                    $( $field: ::std::sync::Arc::new($crate::Decoder::decode(decoder)?), )+
                    $( $( $plain_field: $crate::Decoder::decode(decoder)?, )+ )?
                })
            }
        }

        impl<$($gen: $bound),+> $crate::Categorize<$crate::NoCustomValueKind>
            for $name<$($gen),+>
        {
            fn value_kind() -> $crate::ValueKind<$crate::NoCustomValueKind> {
                $crate::ValueKind::Tuple
            }
        }

        impl<$($gen: $bound),+> $crate::Describe<$crate::NoCustomTypeKind>
            for $name<$($gen),+>
        {
            const TYPE_ID: $crate::RustTypeId =
                $crate::RustTypeId::novel_with_code($type_name, &[], &[]);

            fn type_data() -> $crate::TypeData<$crate::NoCustomTypeKind, $crate::RustTypeId> {
                $crate::TypeData::unnamed($crate::TypeKind::Any)
            }
        }
    };

    // Count helper — counts comma-separated identifiers.
    (@count $head:ident $(, $tail:ident)*) => {
        1 + $crate::impl_sbor_for_generic_struct!(@count $($tail),*)
    };
    (@count) => { 0usize };
}
