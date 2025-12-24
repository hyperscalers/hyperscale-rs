#!/bin/bash
#
# Audit script for finding public exports that aren't used elsewhere in the workspace.
# Run from the workspace root.
#
# Usage:
#   ./scripts/audit-exports.sh              # Full audit of all crates
#   ./scripts/audit-exports.sh --ci         # Exit with code 1 if unused exports found
#   ./scripts/audit-exports.sh --json       # Output results as JSON
#   ./scripts/audit-exports.sh <crate>      # Audit a specific crate only
#
# Pre-commit hook usage:
#   Add to .git/hooks/pre-commit or .pre-commit-config.yaml:
#   ./scripts/audit-exports.sh --ci
#

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKSPACE_ROOT"

CI_MODE=false
SPECIFIC_CRATE=""
VERBOSE=false
JSON_MODE=false
ALLOWLIST_FILE="${WORKSPACE_ROOT}/.export-allowlist"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ci)
            CI_MODE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --json)
            JSON_MODE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [crate-name]"
            echo ""
            echo "Options:"
            echo "  --ci       Exit with code 1 if unused exports are found"
            echo "  --json     Output results as JSON (for tooling integration)"
            echo "  --verbose  Show detailed output including where exports ARE used"
            echo "  <crate>    Audit only the specified crate (directory name under crates/)"
            echo ""
            echo "Allowlist:"
            echo "  Create .export-allowlist in workspace root to whitelist intentional exports."
            echo "  Format: one 'crate::Export' per line. Lines starting with # are comments."
            echo ""
            echo "Example .export-allowlist:"
            echo "  # Public API types"
            echo "  hyperscale-types::UserTransaction"
            echo "  hyperscale-production::ProductionRunner"
            exit 0
            ;;
        *)
            SPECIFIC_CRATE="$1"
            shift
            ;;
    esac
done

# Colors for output (disabled if not a tty or in JSON mode)
if [[ -t 1 ]] && [[ "$JSON_MODE" != "true" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Track results
TOTAL_UNUSED=0
SUMMARY=""
JSON_RESULTS=""

# Load allowlist if it exists
load_allowlist() {
    if [[ -f "$ALLOWLIST_FILE" ]]; then
        grep -v '^#' "$ALLOWLIST_FILE" 2>/dev/null | grep -v '^$' || true
    fi
}
ALLOWLIST=$(load_allowlist)

# Check if an export is in the allowlist
is_allowlisted() {
    local crate_name="$1"
    local export_name="$2"
    local pattern="${crate_name}::${export_name}"

    if [[ -n "$ALLOWLIST" ]] && echo "$ALLOWLIST" | grep -qF "$pattern"; then
        return 0  # Is allowlisted
    fi
    return 1  # Not allowlisted
}

# Get list of workspace crates (directory names)
get_crates() {
    if [[ -n "$SPECIFIC_CRATE" ]]; then
        echo "$SPECIFIC_CRATE"
    else
        # Parse workspace members from Cargo.toml - stop at first blank line or ]
        sed -n '/^members/,/^]/p' Cargo.toml | \
            grep -oE '"crates/[^"]+"' | \
            sed 's/"//g' | \
            sed 's|crates/||'
    fi
}

# Extract the crate name (with hyphens) from directory name
crate_name() {
    local dir="$1"
    # Read the actual crate name from Cargo.toml
    grep '^name' "crates/$dir/Cargo.toml" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)".*/\1/'
}

# Extract public exports from a crate's lib.rs
extract_exports() {
    local crate_dir="$1"
    local lib_rs="crates/$crate_dir/src/lib.rs"

    if [[ ! -f "$lib_rs" ]]; then
        return
    fi

    # Extract items from pub use statements
    # Handles: pub use module::{A, B, C};
    #          pub use module::Item;
    grep -E '^\s*pub use' "$lib_rs" 2>/dev/null | \
        sed 's/.*:://' | \
        sed 's/[{};]/ /g' | \
        tr ',' '\n' | \
        sed 's/as [a-zA-Z_]*//g' | \
        grep -oE '[A-Z][a-zA-Z0-9_]*' | \
        sort -u || true

    # Extract direct pub declarations from lib.rs
    # pub struct Name, pub enum Name, pub trait Name, pub fn name, etc.
    grep -E '^\s*pub\s+(struct|enum|trait|fn|const|type|static)\s+' "$lib_rs" 2>/dev/null | \
        grep -oE '(struct|enum|trait|fn|const|type|static)\s+[A-Za-z_][A-Za-z0-9_]*' | \
        awk '{print $2}' | \
        sort -u || true

    # Extract pub mod (public modules are also exports)
    grep -E '^\s*pub\s+mod\s+' "$lib_rs" 2>/dev/null | \
        grep -oE 'mod\s+[a-z_][a-z0-9_]*' | \
        awk '{print $2}' | \
        sort -u || true
}

# Check if an export is used elsewhere in the workspace
# Returns 0 if used, 1 if not used
check_usage() {
    local crate_name="$1"
    local export_name="$2"
    local crate_dir="$3"

    # Convert crate name to underscore version for Rust imports
    local crate_underscore
    crate_underscore=$(echo "$crate_name" | tr '-' '_')

    # Search patterns:
    # 1. use crate_name::...export_name (with hyphens converted to underscores)
    # 2. crate_name::export_name (direct path usage)

    # Search in other crates + bin/ directories of same crate
    local count
    count=$(grep -r \
        --include="*.rs" \
        -E "(use\s+${crate_underscore}::.*\b${export_name}\b|${crate_underscore}::${export_name})" \
        crates/ 2>/dev/null | \
        grep -v "crates/${crate_dir}/src/lib.rs" | \
        grep -v "crates/${crate_dir}/src/[a-z]*.rs" | \
        wc -l | tr -d ' ')

    # Note: We exclude lib.rs and top-level module files but INCLUDE bin/ files
    # because binaries use `use crate_name::` to import from their own lib

    if [[ "$count" -gt 0 ]]; then
        return 0  # Used
    else
        return 1  # Not used
    fi
}

# Get usage locations for verbose mode
get_usage_locations() {
    local crate_name="$1"
    local export_name="$2"
    local crate_dir="$3"

    local crate_underscore
    crate_underscore=$(echo "$crate_name" | tr '-' '_')

    grep -r \
        --include="*.rs" \
        -l \
        -E "(use\s+${crate_underscore}::.*\b${export_name}\b|${crate_underscore}::${export_name})" \
        crates/ 2>/dev/null | \
        grep -v "crates/${crate_dir}/src/lib.rs" | \
        grep -v "crates/${crate_dir}/src/[a-z]*.rs" | \
        head -3 || true
}

# Audit a single crate
audit_crate() {
    local crate_dir="$1"
    local name
    name=$(crate_name "$crate_dir")

    if [[ -z "$name" ]]; then
        [[ "$JSON_MODE" != "true" ]] && echo -e "${YELLOW}Skipping $crate_dir (cannot determine crate name)${NC}"
        return
    fi

    if [[ ! -f "crates/$crate_dir/src/lib.rs" ]]; then
        [[ "$JSON_MODE" != "true" ]] && echo -e "${YELLOW}Skipping $name (no lib.rs)${NC}"
        return
    fi

    [[ "$JSON_MODE" != "true" ]] && echo -e "${BLUE}Auditing ${name}...${NC}"

    local exports
    exports=$(extract_exports "$crate_dir" | sort -u)

    if [[ -z "$exports" ]]; then
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${GREEN}No public exports found${NC}"
        return
    fi

    local unused_count=0
    local unused_list=""
    local unused_json_items=""

    while IFS= read -r export; do
        [[ -z "$export" ]] && continue

        # Skip if allowlisted
        if is_allowlisted "$name" "$export"; then
            [[ "$VERBOSE" == "true" ]] && [[ "$JSON_MODE" != "true" ]] && \
                echo -e "  ${GREEN}✓${NC} $export (allowlisted)"
            continue
        fi

        if check_usage "$name" "$export" "$crate_dir"; then
            if [[ "$VERBOSE" == "true" ]] && [[ "$JSON_MODE" != "true" ]]; then
                local locations
                locations=$(get_usage_locations "$name" "$export" "$crate_dir")
                echo -e "  ${GREEN}✓${NC} $export (used in: $(echo "$locations" | tr '\n' ' '))"
            fi
        else
            unused_list="${unused_list}    ${export}\n"
            unused_count=$((unused_count + 1))

            # Build JSON array items
            if [[ -n "$unused_json_items" ]]; then
                unused_json_items="${unused_json_items},"
            fi
            unused_json_items="${unused_json_items}\"${export}\""
        fi
    done <<< "$exports"

    if [[ $unused_count -gt 0 ]]; then
        if [[ "$JSON_MODE" != "true" ]]; then
            echo -e "  ${RED}Found $unused_count potentially unused exports:${NC}"
            echo -e "${YELLOW}${unused_list}${NC}"
        fi
        TOTAL_UNUSED=$((TOTAL_UNUSED + unused_count))
        SUMMARY="${SUMMARY}  - ${name}: ${unused_count} unused\n"

        # Add to JSON results
        if [[ -n "$JSON_RESULTS" ]]; then
            JSON_RESULTS="${JSON_RESULTS},"
        fi
        JSON_RESULTS="${JSON_RESULTS}{\"crate\":\"${name}\",\"unused\":[${unused_json_items}]}"
    else
        [[ "$JSON_MODE" != "true" ]] && echo -e "  ${GREEN}All exports are used elsewhere ✓${NC}"
    fi
}

# Main
if [[ "$JSON_MODE" != "true" ]]; then
    echo "========================================"
    echo " Workspace Export Audit"
    echo "========================================"
    if [[ -f "$ALLOWLIST_FILE" ]]; then
        echo " (using allowlist: .export-allowlist)"
    fi
    echo ""
fi

for crate in $(get_crates); do
    audit_crate "$crate"
    [[ "$JSON_MODE" != "true" ]] && echo ""
done

if [[ "$JSON_MODE" == "true" ]]; then
    echo "{\"total_unused\":${TOTAL_UNUSED},\"crates\":[${JSON_RESULTS}]}"
else
    echo "========================================"
    echo " Summary"
    echo "========================================"

    if [[ $TOTAL_UNUSED -gt 0 ]]; then
        echo -e "${RED}Total potentially unused exports: $TOTAL_UNUSED${NC}"
        echo ""
        echo "Crates with unused exports:"
        echo -e "$SUMMARY"
        echo ""
        echo "Note: Some exports may be:"
        echo "  - Used in tests (check with --verbose)"
        echo "  - Part of the intentional public API (add to .export-allowlist)"
        echo "  - Re-exported through other crates"
        echo ""
        echo "To allowlist intentional exports, create .export-allowlist with:"
        echo "  crate-name::ExportName"
        echo ""
        echo "Consider changing unused items to pub(crate) or removing them."

        if [[ "$CI_MODE" == "true" ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}All exports are used across the workspace! ✓${NC}"
    fi
fi
