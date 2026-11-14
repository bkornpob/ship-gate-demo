#!/usr/bin/env bash
set -e
CONFIG="${1:-ship-gate.yaml}"
promptfoo eval -c "$CONFIG" --repeat 1 --no-cache -j 1
echo "GATE PASSED - ok to ship"
