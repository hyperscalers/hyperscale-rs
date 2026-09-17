#!/usr/bin/env bash
# Build the browser bundle into demo/vendor/.
#
# wasm-bindgen's `web` target emits a plain ES module, so the page loads it
# with a <script type="module"> and there is no bundler in the loop.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

# Must match the wasm-bindgen crate version, or the generated glue and the
# module disagree about their ABI.
want="$(sed -n 's/^wasm-bindgen = "=\{0,1\}\(.*\)"$/\1/p' "$root/Cargo.toml")"
have="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen CLI is ${have:-missing}, need $want" >&2
  echo "  cargo install wasm-bindgen-cli --version $want" >&2
  exit 1
fi

cargo build --manifest-path "$root/Cargo.toml" \
  -p hyperscale-demo --profile wasm --target wasm32-unknown-unknown

wasm-bindgen --target web --out-dir "$here/vendor" \
  "$root/target/wasm32-unknown-unknown/wasm/hyperscale_demo.wasm"

size=$(wc -c < "$here/vendor/hyperscale_demo_bg.wasm")
printf 'built %s (%.2f MiB)\n' "$here/vendor/hyperscale_demo_bg.wasm" \
  "$(echo "$size / 1048576" | bc -l)"
