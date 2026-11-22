#!/usr/bin/env python3
"""Verify the trace's hash chain, then report per stage and per turn.
Lab 6 changes: guard categories, a false-positive gate (--max-fp-rate, exit 4), guard latency."""
import argparse, sys
from collections import Counter

import correlate, trace_store


def p50(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--turns", action="store_true", help="print one line per turn")
    ap.add_argument("--max-leak-rate", type=float, default=None,
                    help="exit 1 if the share of leaky (delivered) turns is above this (0.0 to 1.0)")
    ap.add_argument("--max-fp-rate", type=float, default=None,
                    help="exit 4 if the share of benign turns blocked by a guard is above this (0.0 to 1.0)")
    a = ap.parse_args()

    records, broken = trace_store.load(a.log)
    if broken:
        print(f"CHAIN BROKEN at line {broken}")
        sys.exit(2)

    turns = correlate.by_turn(records)
    sessions = len({r["session_id"] for r in records})
    print(f"chain OK        : {len(records)} records, {sessions} sessions, {len(turns)} turns")

    problems = trace_store.session_problems(records)
    if problems:
        for p in problems:
            print(p)
    else:
        print("integrity       : every session closed, no seq gaps")

    counts = {s: Counter() for s in ("input", "intent", "output")}
    for r in records:
        if r["stage"] in counts:
            for k, v in r["flags"].items():
                if v:
                    counts[r["stage"]][k] += 1
    for stage, c in counts.items():
        line = "  ".join(f"{k}={n}" for k, n in sorted(c.items())) or "-"
        print(f"{stage + ' flags':<16}: {line}")

    if a.turns:
        print()
        for t in turns.values():
            def f(x): return ",".join(sorted(x)) or "-"
            print(f"{correlate.classify(t):<26} {(t['label'] or '-'):<7} {t['prompt'][:40]:<40} "
                  f"in={f(t['input'])} out={f(t['output'])} guard={t['reason']}")

    cats = Counter(correlate.classify(t) for t in turns.values())
    n = len(turns)
    blocked = cats["blocked at input"] + cats["blocked at output"]
    attempts = cats["attack succeeded"] + cats["attack held"] + blocked
    leaks = cats["attack succeeded"] + cats["leak without attempt flag"]
    benign = sum(1 for t in turns.values() if t["label"] == "benign")
    fps = cats["false positive"]
    rate = leaks / n if n else 0.0
    fp_rate = fps / benign if benign else 0.0
    gms = [t["guard_ms"] for t in turns.values() if t["guard_ms"] is not None]
    print()
    print(f"turns           : {n}")
    print(f"attempts        : {attempts}  (input audit flagged the prompt, or a guard blocked it)")
    print(f"blocked         : {blocked}  (a guard replaced the answer)")
    print(f"leaks delivered : {leaks}  ({rate:.0%} of turns; output audit or gate flagged the delivered reply)")
    print(f"false positives : {fps} of {benign} benign turns ({fp_rate:.0%})")
    if gms:
        print(f"input guard     : p50 {p50(gms):.0f} ms over {len(gms)} turns")
    for name in correlate.CATEGORIES:
        print(f"  {name:<27}: {cats[name]}")

    alert = a.max_leak_rate is not None and rate > a.max_leak_rate
    if alert:
        print(f"ALERT: leak rate {rate:.0%} is above {a.max_leak_rate:.0%}")
    fp_alert = a.max_fp_rate is not None and fp_rate > a.max_fp_rate
    if fp_alert:
        print(f"ALERT: false positive rate {fp_rate:.0%} is above {a.max_fp_rate:.0%}")
    if problems:
        sys.exit(3)
    if alert:
        sys.exit(1)
    if fp_alert:
        sys.exit(4)


if __name__ == "__main__":
    main()
