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

    def group_key(self, event: dict) -> str:
        """Windowing key. Default: per-user. Override for per-org, per-IP, etc."""
        return event["user_id"]


from detector.rules.rate_abuse import RateAbuse
from detector.rules.prompt_injection import PromptInjection
from detector.rules.token_abuse import TokenAbuse

ALL_RULES = [RateAbuse(), PromptInjection(), TokenAbuse()]
