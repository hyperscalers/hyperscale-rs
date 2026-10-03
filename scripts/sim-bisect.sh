#!/bin/bash
#
# `git bisect run` driver for a simulation test failing at one seed.
#
#   git bisect start <bad> <good>
#   git bisect run scripts/sim-bisect.sh <test> <seed> [features] [profile]
#
# <test> is the exact test name (e.g. `round_timer_tracks_a_fast_shard_sim::seed_7`),
# <features> the simulation features the failure needs (e.g. `production-epochs`),
# <profile> `release` (default) or `ci` to keep CI's debug assertions.
#
# Exits 125 (skip) when the commit does not build or the seed no longer
# produces the test's setup (a SIM-DISCARD), 0 when the test passes, 1 when
# it fails.

set -u

test_name=${1:?test name}
seed=${2:?seed}
features=${3:-}
profile=${4:-release}

cd "$(git rev-parse --show-toplevel)" || exit 125
git submodule update --init vm >/dev/null 2>&1 || exit 125

if [ "$profile" = release ]; then
    profile_args=(--release)
else
    profile_args=(--cargo-profile "$profile")
fi
feature_args=()
if [ -n "$features" ]; then
    feature_args=(--features "$features")
fi

cargo nextest list "${profile_args[@]}" -p hyperscale-simulation ${feature_args[@]+"${feature_args[@]}"} \
    -E "test(=$test_name)" >/dev/null 2>&1 || exit 125

output=$(HYPERSCALE_SIM_SEED=$seed cargo nextest run "${profile_args[@]}" \
    -p hyperscale-simulation ${feature_args[@]+"${feature_args[@]}"} -E "test(=$test_name)" 2>&1)
status=$?
if grep -q "SIM-DISCARD:" <<<"$output"; then
    exit 125
fi
if [ $status -ne 0 ]; then
    grep -m1 "panicked at" <<<"$output"
    exit 1
fi
exit 0
