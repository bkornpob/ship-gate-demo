"""Input audit: look at the prompt. Observe only, never block."""
import re

INJECTION = re.compile(
    r"ignore (all )?(previous|prior) instructions|repeat everything above|"
    r"debug console|print (its|your) config|system prompt", re.I)
RESTRICTED = re.compile(r"\b(alcohol\w*|vodka|whisk(e)?y|rum|beer|wine|cocktail)\b", re.I)


def audit(ev, history):
    if ev["type"] != "input.received":
        return {}
    prompt = ev["payload"]["prompt"]
    letters = re.sub(r"[^a-z]", "", prompt.lower())   # s-e-c-r-e-t c-o-d-e -> secretcode
    return {
        "injection_phrase": bool(INJECTION.search(prompt)),
        "secret_probe": "secretcode" in letters,
        "restricted_topic": bool(RESTRICTED.search(prompt)),
    }