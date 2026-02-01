# Detection rules as Python classes, not YAML.
#
# Why: YAML detection rules inevitably grow into a bespoke DSL as rule
# complexity increases (conditional logic, field aggregations, cross-event
# correlation). Panther Labs went through exactly this migration path —
# YAML → YAML+Python → all-Python (pypanther, now archived).
#
# Python classes give us full expressiveness, pytest testability, IDE
# support, and inheritance — for free. Each rule lives in its own file,
# so detection-as-code workflows (PR per rule, git blame, CI gating) work
# out of the box with zero custom tooling.


class Rule:
    """Base detection rule. Subclass and implement match() + trigger()."""

    id: str
    name: str
    severity: str  # low | medium | high | critical
    window_seconds: int

    # TODO: event is a raw dict for now. Next iteration: normalize to OCSF
    # (or at minimum a typed dataclass) so rules get schema guarantees instead
    # of stringly-typed key lookups.

    def match(self, event: dict) -> bool:
        """Return True if this event should be counted in the rule's window."""
        raise NotImplementedError

    def trigger(self, events: list[dict]) -> bool:
        """Given all matching events in the current window, should we alert?"""
        raise NotImplementedError

    # Evidence ≠ enrichment. Evidence is derived from the detection window
    # itself (event counts, rates, field aggregates). Enrichment adds
    # external context (threat intel, user history, asset inventory) and
    # happens downstream in the triage service.
    def evidence(self, events: list[dict]) -> dict:
        """Summarize evidence from window events for downstream triage.

        Each rule overrides this to compute rule-specific statistics that
        give an LLM (or human analyst) the context needed to classify the
        alert — mirroring the evidence-packaging step in a real SOC alert
        pipeline (NIST SP 800-61 §3.2: "capture sufficient detail for the
        triage analyst to assess without re-querying raw telemetry").
        """
        return {}

    def group_key(self, event: dict) -> str:
        """Windowing key. Default: per-user. Override for per-org, per-IP, etc."""
        return event["user_id"]


from detector.rules.rate_abuse import RateAbuse
from detector.rules.prompt_injection import PromptInjection
from detector.rules.token_abuse import TokenAbuse

ALL_RULES = [RateAbuse(), PromptInjection(), TokenAbuse()]
