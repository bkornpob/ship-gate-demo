#!/usr/bin/env python3
"""Input guard: layer B (deterministic rules) + layer A (guard model).
Enforces: returns a decision; the caller must not call the chat model when allow is False.

  python3 guard_input.py "some prompt"      -> one JSON decision
  python3 guard_input.py --tsv probes.tsv   -> label, decision, reason, ms, votes, prompt

Env: LAYERS=ab|a|b   GUARD_BOTH=1 (run every layer/model even after a block)
     GUARD_MODEL=llama-guard3:1b                one guard model, or several separated by commas:
     GUARD_MODEL=llama-guard3:1b,qwen3guard:4b
     GUARD_POLICY=any|all|majority   how several guard models combine (any = block if one says block)
     GUARD_BLOCK=unsafe,controversial   verdicts that count as a block vote
     GUARD_FAIL=closed|open             a guard that is unreachable or unreadable votes block (closed) or allow (open)
"""
import json, os, re, sys, time, urllib.request

from audit_input import INJECTION          # Lab 5: same regex, reused

BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")
GUARDS = [m.strip() for m in os.environ.get("GUARD_MODEL", "llama-guard3:1b").split(",") if m.strip()]
POLICY = os.environ.get("GUARD_POLICY", "any")
LAYERS = os.environ.get("LAYERS", "ab")     # a = guard model, b = rules
BOTH = os.environ.get("GUARD_BOTH") == "1"
BLOCK_ON = set(os.environ.get("GUARD_BLOCK", "unsafe,controversial").split(","))
FAIL = os.environ.get("GUARD_FAIL", "closed")
REFUSAL = "Sorry, I can't help with that request."   # distinct text, so a block is easy to spot in the trace


def rules(prompt):
    """Layer B: cheap, deterministic. Alcohol is NOT blocked here: that is the model's and the output gate's job."""
    letters = re.sub(r"[^a-z]", "", prompt.lower())   # s-e-c-r-e-t c-o-d-e -> secretcode
    hits = []
    if INJECTION.search(prompt):
        hits.append("injection_phrase")
    if "secretcode" in letters:
        hits.append("secret_probe")
    return hits


def parse_verdict(text):
    """Llama Guard 3: 'safe' or 'unsafe' + 'S1'.  Qwen3Guard-Gen: 'Safety: Safe|Unsafe|Controversial' + 'Categories: ...'."""
    m = re.search(r"Safety:\s*(Safe|Unsafe|Controversial)", text, re.I)
    if m:
        c = re.search(r"Categories:\s*([^\n]+)", text, re.I)
        return m.group(1).lower(), (c.group(1).strip() if c else None)
    w = text.split()
    if w and w[0].lower() in ("safe", "unsafe"):
        return w[0].lower(), (w[1] if len(w) > 1 else None)
    raise ValueError("unreadable guard output: " + text[:60])


def guard_model(model, prompt):
    """Layer A: ask one guard model to classify the prompt (temperature 0)."""
    t0 = time.time()
    body = {"model": model, "stream": False, "options": {"temperature": 0},
            "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(BASE + "/api/chat", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        verdict, category = parse_verdict(json.load(r)["message"]["content"])
    return {"model": model, "verdict": verdict, "category": category,
            "latency_ms": int((time.time() - t0) * 1000)}


def check(prompt):
    t0 = time.time()
    d = {"allow": True, "reason": "ok", "layers": {}}

    def block(reason):
        if d["allow"]:                       # first blocking layer names the reason
            d["allow"], d["reason"] = False, reason

    if "b" in LAYERS:
        hits = rules(prompt)
        d["layers"]["rules"] = {"hits": hits}
        if hits:
            block("rule:" + ",".join(hits))
    if "a" in LAYERS and (d["allow"] or BOTH):
        votes = []                                   # one entry per guard model: True = block
        d["layers"]["guards"] = []
        for m in GUARDS:
            try:
                g = guard_model(m, prompt)
                vote = g["verdict"] in BLOCK_ON
            except Exception as e:
                g = {"model": m, "verdict": "error", "category": None, "error": repr(e)}
                vote = FAIL == "closed"              # an enforcing guard that cannot decide blocks
            d["layers"]["guards"].append(g)
            votes.append(vote)
            if POLICY == "any" and vote and not BOTH:
                break                                # one block vote is enough; skip the other models
        blocking = [g for g, v in zip(d["layers"]["guards"], votes) if v]
        n = len(GUARDS)
        if POLICY == "all":
            verdict_block = len(blocking) == n
        elif POLICY == "majority":
            verdict_block = len(blocking) * 2 > n
        else:
            verdict_block = bool(blocking)
        if verdict_block:
            names = [f"{g['model'].split(':')[0]}={g.get('category') or g['verdict']}" for g in blocking]
            block("guard_error" if all(g["verdict"] == "error" for g in blocking) else "guard:" + ",".join(names))
    d["latency_ms"] = int((time.time() - t0) * 1000)
    return d


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--tsv":
        with open(sys.argv[2]) as f:
            for line in f:
                label, _, p = line.rstrip("\r\n").partition("\t")
                if not p or label.startswith("#"):
                    continue
                d = check(p)
                votes = " ".join(f"{g['model'].split(':')[0]}:{g['verdict']}" for g in d["layers"].get("guards", [])) or "-"
                print(label, "allow" if d["allow"] else "block", d["reason"], d["latency_ms"], votes, p[:50], sep="\t")
    else:
        print(json.dumps(check(" ".join(sys.argv[1:])), indent=2))