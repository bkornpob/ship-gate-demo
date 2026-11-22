"""A thin session: stamps ids and order, emits events, and never waits on the auditors."""
import os, sys, threading, uuid

import audit_input, audit_intent, audit_output, trace_store
from events import make_event

AUDITORS = {"input": audit_input, "intent": audit_intent, "output": audit_output}


class Session:
    def __init__(self, log):
        self.log = log
        self.sid = str(uuid.uuid4())
        self.turn = 0
        self.seq = 0
        self.events = []
        self.threads = []
        self.seen = {"input": set(), "intent": set(), "output": set()}
        self._m = threading.Lock()

    def new_turn(self):
        self.turn += 1

    def emit(self, stage, type_, payload):
        self.seq += 1                                   # true order, stamped here
        ev = make_event(self.sid, self.turn, self.seq, stage, type_, payload)
        self.events.append(ev)
        t = threading.Thread(target=self._audit, args=(ev, list(self.events)))
        t.start()                                       # fire and continue: no waiting
        self.threads.append(t)
        return ev

    def _audit(self, ev, history):
        flags = {}
        try:
            if os.environ.get("AUDIT_BREAK") == ev["stage"]:
                raise RuntimeError("injected fault")    # lab step: prove audit failures are visible
            mod = AUDITORS.get(ev["stage"])
            if mod:
                flags = mod.audit(ev, history)          # history = read-only events so far
        except Exception as e:                          # fail open for the chat, loud in the trace
            flags = {"audit_error": True}
            print(f"[audit] {ev['stage']} auditor failed: {e}", file=sys.stderr)
        try:
            trace_store.append(self.log, ev, flags)
        except Exception as e:
            print(f"[audit] could not write trace: {e}", file=sys.stderr)
        with self._m:
            if ev["stage"] in self.seen:
                self.seen[ev["stage"]].update(k for k, v in flags.items() if v)

    def close(self):
        for t in self.threads:
            t.join()
        self.seq += 1
        ev = make_event(self.sid, self.turn, self.seq, "session", "session.closed",
                        {"events": self.seq - 1})
        trace_store.append(self.log, ev, {})

    def summary(self):
        def f(stage):
            return "[" + ", ".join(sorted(self.seen[stage])) + "]"
        return (f"[audit] session={self.sid[:8]} input={f('input')} "
                f"intent={f('intent')} output={f('output')}")