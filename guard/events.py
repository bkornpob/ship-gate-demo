"""The event envelope: every step of a session is described as one event."""
from datetime import datetime, timezone

STAGES = ("input", "intent", "output", "session")


def make_event(session_id, turn, seq, stage, type_, payload):
    return {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "session_id": session_id,
        "turn": turn,
        "seq": seq,          # stamped by the session at emit time = the true order
        "stage": stage,      # input | intent | output | session
        "type": type_,       # e.g. input.received, tool.call, output.sent
        "payload": payload,
    }