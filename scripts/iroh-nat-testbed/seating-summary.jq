# Pair times of one seating round, from every host's report (jq -s).
#
# A pair is direct once both of its hosts have seen the other on a direct
# path; its time is the later of the two, in milliseconds after seating.
# A pair that never got there is counted by what each side ended on.

def pct(p): sort | if length == 0 then null else .[((length - 1) * p | floor)] end;

[ .[] as $r | $r.members[]
  | {a: $r.index, b: .validator, type: $r.label, direct: .direct_ms,
     bound: .bound_ms, end: .end, after: .relayed_after_direct_ms} ] as $rows
| ($rows | map({key: "\(.a)-\(.b)", value: .}) | from_entries) as $seen
| ($rows | map(.a) | unique | length) as $reports
| [ $rows[] | select(.a < .b) | . as $x | ($seen["\(.b)-\(.a)"] // {}) as $y
    | {types: ([$x.type, ($y.type // "?")] | sort | join("+")),
       direct: (if $x.direct and $y.direct then ([$x.direct, $y.direct] | max) else null end),
       bound: (if $x.bound and $y.bound then ([$x.bound, $y.bound] | max) else null end),
       end: ([$x.end, $y.end] | map(. // "unbound") | sort | join("/")),
       relayed_after_direct_ms: ([$x.after, ($y.after // 0)] | max)} ] as $pairs
| ($pairs | map(select(.direct)) | map(.direct)) as $times
| {
    reports: $reports,
    pairs: ($pairs | length),
    bound: ($pairs | map(select(.bound)) | length),
    direct: ($times | length),
    never_direct: ($pairs | map(select(.direct == null)) | length),
    never_direct_by_end: ($pairs | map(select(.direct == null)) | group_by(.end)
        | map({key: .[0].end, value: length}) | from_entries),
    direct_ms: {p50: ($times | pct(0.5)), p95: ($times | pct(0.95)), max: ($times | max)},
    bound_ms: {p50: ($pairs | map(.bound // empty) | pct(0.5)),
               p95: ($pairs | map(.bound // empty) | pct(0.95)),
               max: ($pairs | map(.bound // empty) | max)},
    fell_back_after_direct: ($pairs | map(select(.relayed_after_direct_ms > 0)) | length),
    by_types: ($pairs | group_by(.types) | map({key: .[0].types, value: {
        pairs: length,
        direct: (map(select(.direct)) | length),
        direct_p50_ms: (map(.direct // empty) | pct(0.5)),
        direct_max_ms: (map(.direct // empty) | max)}}) | from_entries)
  }
