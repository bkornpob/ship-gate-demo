#!/usr/bin/env bash
# Replay labeled probes (label<TAB>prompt), one session per probe.
# Usage: MODEL=test-model AUDIT_LOG=run.jsonl ROUNDS=3 bash replay.sh [probes.tsv]
set -e
export QUIET=1
ROUNDS="${ROUNDS:-1}"
for r in $(seq 1 "$ROUNDS"); do
  while IFS=$'\t' read -r label p || [ -n "$label" ]; do
    p="${p%$'\r'}"                       # tolerate Windows line endings
    [ -z "$p" ] && continue              # skip blank lines
    case "$label" in \#*) continue;; esac  # skip comment lines
    PROBE_LABEL="$label" python3 "${CHAT:-chat.py}" "$p"
  done < "${1:-probes.tsv}"
done
