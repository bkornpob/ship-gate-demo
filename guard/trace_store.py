"""The only writer of the trace: one hash chain for every stage, plus the verifier."""
import hashlib, json, threading

ZERO = "0" * 64
SENSITIVE_FLAGS = {"canary_leak"}   # a record with one of these flags never stores the reply
_lock = threading.Lock()            # auditors run in threads; the chain needs one writer at a time


def digest(rec):
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def last_hash(path):
    try:
        with open(path) as f:
            lines = f.read().splitlines()
        return json.loads(lines[-1])["hash"] if lines else ZERO
    except FileNotFoundError:
        return ZERO


def redact(payload, flags):
    # the trace is a second leak path, so the store (not the auditors) enforces redaction
    if any(flags.get(k) for k in SENSITIVE_FLAGS) and "reply" in payload:
        return dict(payload, reply="[REDACTED: canary]")
    return payload


def append(path, ev, flags):
    with _lock:
        rec = dict(ev)
        rec["payload"] = redact(ev["payload"], flags)
        rec["flags"] = flags
        rec["prev"] = last_hash(path)
        rec["hash"] = digest(rec)
        with open(path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    return rec


def load(path):
    """Return (records, broken_line). broken_line is None when the whole chain is intact."""
    prev, records = ZERO, []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            try:
                rec = json.loads(line)
                if rec["prev"] != prev or digest(rec) != rec["hash"]:
                    return records, i
            except (ValueError, KeyError):
                return records, i
            prev = rec["hash"]
            records.append(rec)
    return records, None


def session_problems(records):
    """Per session: it must be closed, and no seq number may be missing."""
    by = {}
    for r in records:
        by.setdefault(r["session_id"], []).append(r)
    problems = []
    for sid, recs in by.items():
        seqs = {r["seq"] for r in recs}
        closed = [r for r in recs if r["type"] == "session.closed"]
        if closed:
            expected = closed[0]["seq"]
        else:
            problems.append(f"UNCLOSED session {sid[:8]}: no session.closed record")
            expected = max(seqs)
        missing = sorted(set(range(1, expected + 1)) - seqs)
        if missing:
            problems.append(f"SEQ GAP session {sid[:8]}: missing seq {missing}")
    return problems