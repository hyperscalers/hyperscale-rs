#!/usr/bin/env python3
"""Sweep simulation tests across seeds and bucket what fails.

Builds the simulation test binaries once, then runs every matching test at
every seed as a process of its own, with HYPERSCALE_SIM_SEED naming the seed.
Each run lands in one of four verdicts:

  pass        the test passed
  fail        the test panicked
  discard     the seed did not produce the setup the test needs (SIM-DISCARD)
  unresolved  the run outlived --timeout; every sim wait is a simulated
              budget, so a real stall panics on its own and a run killed
              here is only slow, never a verdict

A `seeded!` module runs through one of its cells: every cell takes the
swept seed, so the others would repeat it. The test column names that cell,
which is what a replay filters on.

Each failure is rerun once in a fresh process. A rerun that disagrees marks
the result nondeterministic, which is a bug in its own right.

Writes results.tsv to the output directory and prints failures bucketed by
the test and the source location that panicked.

Examples:
  scripts/sim-sweep.py --seeds 1..200 -E 'test(/round_timer/)'
  scripts/sim-sweep.py --seeds 1..50 --features production-epochs \\
      -E 'test(halted_shard_straddler_atomic)'
  scripts/sim-sweep.py --seeds 7,11,42 --profile ci --features bls,production-epochs
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SEED_VAR = "HYPERSCALE_SIM_SEED"
DISCARD = "SIM-DISCARD:"
PANIC_AT = re.compile(r"panicked at (\S+?:\d+):\d+:")
SIM_TIME = re.compile(r"simulation failed: seed \d+ at (\S+)")
SEEDED_CELL = re.compile(r"^(.*)::seed_\d+$")


def parse_seeds(text):
    seeds = []
    for part in text.split(","):
        if ".." in part:
            lo, hi = part.split("..")
            seeds.extend(range(int(lo), int(hi) + 1))
        else:
            seeds.append(int(part))
    return seeds


def cargo_profile_args(profile):
    return ["--release"] if profile == "release" else ["--cargo-profile", profile]


def list_tests(args):
    cmd = [
        "cargo", "nextest", "list", *cargo_profile_args(args.profile),
        "-p", args.package, "--message-format", "json", "-E", args.filter,
    ]
    if args.features:
        cmd += ["--features", args.features]
    listed = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    if listed.returncode != 0:
        sys.stderr.write(listed.stderr)
        sys.exit("build or listing failed")
    tests = []
    swept = set()
    for suite in json.loads(listed.stdout)["rust-suites"].values():
        for name, case in suite["testcases"].items():
            if case["filter-match"]["status"] != "matches" or case["ignored"]:
                continue
            # Every cell of a `seeded!` module runs the swept seed, so one
            # cell per module covers it.
            cell = SEEDED_CELL.match(name)
            if cell:
                module = (suite["binary-id"], cell.group(1))
                if module in swept:
                    continue
                swept.add(module)
            tests.append((suite["binary-id"], suite["binary-path"], suite["cwd"], name))
    return tests


def run_one(test, seed, timeout):
    binary_id, binary, cwd, name = test
    env = dict(os.environ, **{SEED_VAR: str(seed)})
    started = time.monotonic()
    try:
        done = subprocess.run(
            [binary, "--exact", name, "--nocapture", "--test-threads", "1"],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"verdict": "unresolved", "wall": time.monotonic() - started,
                "location": "", "sim_time": "", "output": ""}
    output = done.stdout + done.stderr
    if done.returncode == 0:
        verdict = "pass"
    elif DISCARD in output:
        verdict = "discard"
    else:
        verdict = "fail"
    location = PANIC_AT.search(output)
    sim_time = SIM_TIME.search(output)
    return {
        "verdict": verdict,
        "wall": time.monotonic() - started,
        "location": location.group(1) if location else "",
        "sim_time": sim_time.group(1) if sim_time else "",
        "output": output,
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", required=True, help="e.g. 1..100 or 7,11,42 or 1..10,99")
    parser.add_argument("-E", "--filter", default="all()", help="nextest filterset")
    parser.add_argument("-p", "--package", default="hyperscale-simulation")
    parser.add_argument("--features", default="", help="e.g. production-epochs or bls,production-epochs")
    parser.add_argument("--profile", default="release",
                        help="cargo profile: release, or ci to match CI's debug assertions")
    parser.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--timeout", type=float, default=3600,
                        help="seconds before a run is recorded unresolved; a deadlock guard only")
    parser.add_argument("--out", type=Path, help="output directory (default target/sim-sweep/<time>)")
    parser.add_argument("--keep-output", action="store_true",
                        help="write every failing run's output to the output directory")
    args = parser.parse_args()

    seeds = parse_seeds(args.seeds)
    tests = list_tests(args)
    if not tests:
        sys.exit("no test matches the filter")
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO,
                            capture_output=True, text=True).stdout.strip()
    out = args.out or REPO / "target" / "sim-sweep" / datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    print(f"{len(tests)} tests x {len(seeds)} seeds on {commit}, {args.jobs} at a time -> {out}")

    runs = [(test, seed) for seed in seeds for test in tests]
    results = {}
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        futures = {pool.submit(run_one, test, seed, args.timeout): (test, seed) for test, seed in runs}
        for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
            test, seed = futures[future]
            result = future.result()
            results[(test, seed)] = result
            if result["verdict"] != "pass":
                print(f"[{count}/{len(runs)}] {result['verdict']:<10} seed {seed:<6} {test[3]} "
                      f"{result['location']}", flush=True)

        failed = [key for key, result in results.items() if result["verdict"] == "fail"]
        reruns = {key: pool.submit(run_one, key[0], key[1], args.timeout) for key in failed}
        for key, future in reruns.items():
            again = future.result()
            first = results[key]
            first["deterministic"] = (again["verdict"], again["location"]) == (
                first["verdict"], first["location"])

    with open(out / "results.tsv", "w") as tsv:
        tsv.write("commit\tfeatures\tprofile\tbinary\ttest\tseed\tverdict\tdeterministic\t"
                  "location\tsim_time\twall_s\n")
        for (test, seed), result in sorted(results.items(), key=lambda kv: (kv[0][0][3], kv[0][1])):
            tsv.write(f"{commit}\t{args.features}\t{args.profile}\t{test[0]}\t{test[3]}\t{seed}\t"
                      f"{result['verdict']}\t{result.get('deterministic', '')}\t"
                      f"{result['location']}\t{result['sim_time']}\t{result['wall']:.1f}\n")
            if args.keep_output and result["verdict"] == "fail":
                (out / f"{test[3].replace('::', '.')}-{seed}.log").write_text(result["output"])

    tally = defaultdict(int)
    buckets = defaultdict(list)
    for (test, seed), result in results.items():
        tally[result["verdict"]] += 1
        if result["verdict"] == "fail":
            buckets[(test[3], result["location"])].append(
                (seed, result.get("deterministic", True)))
    print("\n" + ", ".join(f"{verdict} {n}" for verdict, n in sorted(tally.items())))
    for (name, location), hits in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        seeds_text = ", ".join(f"{seed}{'' if det else '*'}" for seed, det in sorted(hits))
        print(f"  {len(hits):>4}  {name}  {location or '(no panic location)'}\n        seeds {seeds_text}")
    if any(not det for hits in buckets.values() for _, det in hits):
        print("  * the rerun disagreed: nondeterministic")
    print(f"\nresults: {out / 'results.tsv'}")
    sys.exit(1 if buckets else 0)


if __name__ == "__main__":
    main()
