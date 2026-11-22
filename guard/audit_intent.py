"""Intent audit: look at what happened between input and output. Observe only.

With a plain model this is thin (context + model call). With an agent it grows:
retrieval, tool calls, memory. Same module, more event types.
"""
import os

MAX_OUT_TOKENS = int(os.environ.get("MAX_OUT_TOKENS", "800"))
ALLOWED_TOOLS = {"search_docs", "calculator"}


def audit(ev, history):
    t, p = ev["type"], ev["payload"]
    if t == "context.assembled":
        return {"system_unknown": p.get("system_sha256") is None,
                "digest_missing": p.get("model_digest") is None}
    if t == "model.response":
        return {"output_token_spike": (p.get("output_tokens") or 0) > MAX_OUT_TOKENS}
    if t == "model.error":
        return {"model_error": True}
    if t == "tool.call":
        return {"tool_not_allowed": p.get("tool") not in ALLOWED_TOOLS}
    return {}