#!/usr/bin/env python3
"""Run one chat turn through an audited session. The audit only observes: the user gets the reply."""
import hashlib, json, os, re, sys, time, urllib.request

from session import Session

BASE = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("MODEL", "test-model")
LOG = os.environ.get("AUDIT_LOG", "trace.jsonl")
QUIET = os.environ.get("QUIET") == "1"      # replay.sh sets this so 7 replies do not flood the screen


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def call(path, body=None, timeout=300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def system_from_modelfile(text):
    m = (re.search(r'^SYSTEM\s+"""(.*?)"""', text, re.S | re.M)
         or re.search(r"^SYSTEM\s+(.+)$", text, re.M))
    return m.group(1) if m else None


def harness_info(model):
    """What the harness can see about the model's config. Hashes only: never store the system prompt."""
    digest = system = None
    try:
        for m in call("/api/tags", timeout=30).get("models", []):
            if m.get("name") in (model, model + ":latest"):
                digest = m.get("digest")
    except Exception:
        pass
    try:
        info = call("/api/show", {"model": model, "name": model}, timeout=30)
        system = info.get("system") or system_from_modelfile(info.get("modelfile", ""))
    except Exception:
        pass
    return digest, (sha256(system) if system else None)


def main():
    prompt = " ".join(sys.argv[1:])
    s = Session(LOG)
    s.new_turn()

    # 1. input: the audit starts in parallel, the model call does not wait for it
    s.emit("input", "input.received",
           {"prompt": prompt, "prompt_sha256": sha256(prompt), "prompt_chars": len(prompt)})

    # 2. intent: what the harness assembled for the model
    digest, system_sha = harness_info(MODEL)
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
    reply = data["message"]["content"]
    s.emit("intent", "model.response",
           {"latency_s": round(time.time() - t0, 2),
            "prompt_tokens": data.get("prompt_eval_count"),
            "output_tokens": data.get("eval_count"),
            "done_reason": data.get("done_reason")})

    # 3. output: the user gets the reply no matter what the audit says
    s.emit("output", "output.sent",
           {"reply": reply, "reply_sha256": sha256(reply), "reply_chars": len(reply)})
    if not QUIET:
        print(reply)

    s.close()
    print(s.summary())


if __name__ == "__main__":
    main()