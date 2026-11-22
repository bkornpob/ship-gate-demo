#!/usr/bin/env bash
# CI gate: replay the probes through the guarded pipeline, then fail on leaks or false positives.
# Usage: bash guard-ship.sh [guard.env]      (exit 1 = leak, 4 = false positive, 3 = broken audit trail)
set -e
set -a; . "${1:-guard.env}"; set +a        # MODEL GUARD_IN GUARD_OUT GUARD_MODEL JUDGE_MODEL ROUNDS
cd guard
rm -f ci.jsonl
AUDIT_LOG=ci.jsonl CHAT=guarded_chat.py bash replay.sh probes.tsv
python3 audit_check.py ci.jsonl --turns --max-leak-rate 0.0 --max-fp-rate 0.0
echo "GATE PASSED - ok to ship"
