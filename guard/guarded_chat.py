#!/usr/bin/env python3
"""One guarded chat turn: input guard -> model -> output gate -> reply.
The guards ENFORCE (block); the Lab 5 audit still only observes the events.

Env: MODEL, AUDIT_LOG, QUIET, PROBE_LABEL as in Lab 5.
     GUARD_IN=0|1|shadow  input guard (1 = enforced, shadow = evaluated and logged but never blocks,
                          0 = skipped: no call, no latency)
     GUARD_OUT=0|1  output gate (0 = shadow: still evaluated and logged, but nothing is blocked)
"""
import os, sys, time

import guard_input, guard_output
from chat import MODEL, LOG, QUIET, call, harness_info, sha256    # Lab 5 harness, reused
from session import Session

GUARD_IN = os.environ.get("GUARD_IN", "1")
GUARD_OUT = os.environ.get("GUARD_OUT", "1") == "1"
LABEL = os.environ.get("PROBE_LABEL")


def deliver(s, reply, blocked, raw_sha=None):
    """The user gets `reply`; `blocked` says which guard replaced the model's answer (None = nobody)."""
    s.emit("output", "output.sent",
           {"reply": reply, "reply_sha256": sha256(reply), "reply_chars": len(reply),
            "blocked": blocked, "raw_sha256": raw_sha})
    if not QUIET:
        print(reply)
    s.close()
    print(s.summary())


def main():
    prompt = " ".join(sys.argv[1:])
    s = Session(LOG)
    s.new_turn()
    s.emit("input", "input.received",
           {"prompt": prompt, "prompt_sha256": sha256(prompt), "prompt_chars": len(prompt), "label": LABEL})

    if GUARD_IN in ("1", "shadow"):                  # 1. input guard: when enforced, a block never reaches the model
        d = guard_input.check(prompt)
        s.emit("input", "guard.input", {"enforced": GUARD_IN == "1", **d})
        if GUARD_IN == "1" and not d["allow"]:
            return deliver(s, guard_input.REFUSAL, "input")

    digest, system_sha = harness_info(MODEL)         # 2. model, as in Lab 5
    s.emit("intent", "context.assembled",
           {"model": MODEL, "model_digest": digest, "system_sha256": system_sha,
            "messages": 1, "history_turns": 0})
    t0 = time.time()
    try:
        data = call("/api/chat", {"model": MODEL, "stream": False,
                                  "messages": [{"role": "user", "content": prompt}]})
    except Exception as e:
        s.emit("intent", "model.error", {"error": repr(e)})
        s.close()
        sys.exit(f"model call failed: {e}")
    raw = data["message"]["content"]
    s.emit("intent", "model.response",
           {"latency_s": round(time.time() - t0, 2), "prompt_tokens": data.get("prompt_eval_count"),
            "output_tokens": data.get("eval_count"), "done_reason": data.get("done_reason")})

    g = guard_output.check(raw)                      # 3. output gate (always evaluated, enforced only if GUARD_OUT=1)
    s.emit("output", "guard.output",
           {"enforced": GUARD_OUT, "allow": g["allow"], "reason": g["reason"], "hits": g["hits"],
            "layers": g["layers"], "raw_flagged": not g["allow"], "latency_ms": g["latency_ms"]})
    if GUARD_OUT and not g["allow"]:
        deliver(s, guard_output.REFUSAL, "output", raw_sha=sha256(raw))
    else:
        deliver(s, raw, None)


if __name__ == "__main__":
    main()
