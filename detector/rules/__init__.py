# Detection rules — Sigma-style YAML definitions.
#
# Rules live in detector/rules/sigma/*.yml and follow the Sigma open
# standard for metadata, logsource, and event matching, with a custom:
# extension block for windowing, thresholds, and evidence computation.
#
# The YAML format gives us: a vendor-agnostic standard that security
# teams recognize, declarative rule definitions that separate "what to
# detect" from "how to evaluate", and git-friendly files that work with
# detection-as-code workflows (PR per rule, CI validation, schema checks).


from pathlib import Path


class Rule:
    """Base detection rule. Subclass and implement match() + trigger()."""

    id: str
    name: str
    severity: str  # low | medium | high | critical
    window_seconds: int

    def match(self, event: dict) -> bool:
        """Return True if this event should be counted in the rule's window."""
        raise NotImplementedError

    def trigger(self, events: list[dict]) -> bool:
        """Given all matching events in the current window, should we alert?"""
        raise NotImplementedError

    def evidence(self, events: list[dict]) -> dict:
        """Summarize evidence from window events for downstream triage."""
        return {}

    def group_key(self, event: dict) -> str:
        """Windowing key. Default: per-user. Override for per-org, per-IP, etc."""
        return event["user_id"]


from detector.rules.loader import load_rules  # noqa: E402

ALL_RULES = load_rules(Path(__file__).parent / "sigma")
