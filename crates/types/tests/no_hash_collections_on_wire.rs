//! Wire-determinism guard: no SBOR-encoded type may carry a `HashMap` or
//! `HashSet` field. SBOR upstream provides `Encode`/`Decode` impls for both,
//! but their iteration order isn't defined — encoding produces different
//! bytes across runs, and any merkle root or signature over the bytes
//! diverges. Use `BTreeMap`/`BTreeSet` (or a sorted `Vec`) instead.
//!
//! The test scans `crates/types/src/` and `crates/messages/src/` (every
//! wire type lives in one of those two), and considers a type "SBOR-encoded"
//! if it either:
//! - derives one of `Encode`, `Decode`, `BasicEncode`, `BasicDecode`,
//!   `BasicSbor`, or `Sbor`, **or**
//! - has a manual `impl <SborTrait>` block in the same file.
//!
//! Anything else (e.g. `TopologySnapshot`, which lives in-process behind an
//! `ArcSwap` and is never serialized) is ignored without an allowlist
//! entry.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::{Visit, visit_path_segment};
use syn::{Attribute, Fields, Item, ItemImpl, ItemMod, PathSegment, Type, parse_file};

const SBOR_TRAITS: &[&str] = &[
    "Encode",
    "Decode",
    "BasicEncode",
    "BasicDecode",
    "BasicSbor",
    "Sbor",
];

#[test]
fn no_hash_collections_in_wire_types() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR has a workspace root two levels up");

    let mut violations = Vec::new();
    for crate_name in ["types", "messages"] {
        let src = workspace_root.join("crates").join(crate_name).join("src");
        scan_dir(&src, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "\nWire types must not use HashMap/HashSet (non-deterministic encoding).\n\
         Use BTreeMap/BTreeSet or a sorted Vec instead.\n\n  {}\n",
        violations.join("\n  ")
    );
}

fn scan_dir(dir: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).expect("read crates/{types,messages}/src") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            scan_file(&path, out);
        }
    }
}

fn scan_file(path: &Path, out: &mut Vec<String>) {
    let src = fs::read_to_string(path).expect("read .rs file");
    let file = parse_file(&src).expect("parse .rs file");

    let mut encoded = HashSet::new();
    collect_encoded(&file.items, &mut encoded);
    check_items(&file.items, &encoded, path, out);
}

fn collect_encoded(items: &[Item], encoded: &mut HashSet<String>) {
    for item in items {
        match item {
            Item::Struct(s) if has_sbor_derive(&s.attrs) => {
                encoded.insert(s.ident.to_string());
            }
            Item::Enum(e) if has_sbor_derive(&e.attrs) => {
                encoded.insert(e.ident.to_string());
            }
            Item::Impl(i) => {
                if let Some(name) = sbor_impl_target(i) {
                    encoded.insert(name);
                }
            }
            Item::Mod(ItemMod {
                content: Some((_, items)),
                ..
            }) => collect_encoded(items, encoded),
            _ => {}
        }
    }
}

fn check_items(items: &[Item], encoded: &HashSet<String>, path: &Path, out: &mut Vec<String>) {
    for item in items {
        match item {
            Item::Struct(s) if encoded.contains(&s.ident.to_string()) => {
                check_fields(&s.fields, &s.ident.to_string(), path, out);
            }
            Item::Enum(e) if encoded.contains(&e.ident.to_string()) => {
                let owner_base = e.ident.to_string();
                for variant in &e.variants {
                    let owner = format!("{owner_base}::{}", variant.ident);
                    check_fields(&variant.fields, &owner, path, out);
                }
            }
            Item::Mod(ItemMod {
                content: Some((_, items)),
                ..
            }) => check_items(items, encoded, path, out),
            _ => {}
        }
    }
}

fn has_sbor_derive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|nested| {
            if let Some(seg) = nested.path.segments.last()
                && SBOR_TRAITS.contains(&seg.ident.to_string().as_str())
            {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn sbor_impl_target(i: &ItemImpl) -> Option<String> {
    let (_, trait_path, _) = i.trait_.as_ref()?;
    let trait_name = trait_path.segments.last()?.ident.to_string();
    if !SBOR_TRAITS.contains(&trait_name.as_str()) {
        return None;
    }
    type_path_name(&i.self_ty)
}

fn type_path_name(ty: &Type) -> Option<String> {
    if let Type::Path(p) = ty {
        return p.path.segments.last().map(|s| s.ident.to_string());
    }
    None
}

fn check_fields(fields: &Fields, owner: &str, path: &Path, out: &mut Vec<String>) {
    for field in fields {
        if let Some(kind) = type_uses_hash_collection(&field.ty) {
            let field_name = field
                .ident
                .as_ref()
                .map_or_else(|| "<unnamed>".to_string(), ToString::to_string);
            out.push(format!(
                "{owner} (field `{field_name}: {kind}<…>`) in {}",
                path.display()
            ));
        }
    }
}

fn type_uses_hash_collection(ty: &Type) -> Option<&'static str> {
    struct Finder(Option<&'static str>);
    impl<'ast> Visit<'ast> for Finder {
        fn visit_path_segment(&mut self, seg: &'ast PathSegment) {
            if self.0.is_none() {
                match seg.ident.to_string().as_str() {
                    "HashMap" => self.0 = Some("HashMap"),
                    "HashSet" => self.0 = Some("HashSet"),
                    _ => {}
                }
            }
            visit_path_segment(self, seg);
        }
    }
    let mut f = Finder(None);
    f.visit_type(ty);
    f.0
}
