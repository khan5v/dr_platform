"""Sigma-compatible rule loaded from YAML.

Implements the same interface as the Rule base class (match, trigger,
evidence, group_key) so the DetectionEngine works without changes.
The YAML schema follows standard Sigma fields for metadata and event
matching, with a ``custom:`` extension block for windowing, thresholds,
and evidence computation.
"""

from detector.rules import Rule

# Sigma 'level' → our severity vocabulary.  Sigma uses 'informational'
# where we use 'low'; everything else maps 1:1.
_LEVEL_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Comparison operators used in trigger conditions.
_OPS = {
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "eq": lambda a, b: a == b,
}


class SigmaRule(Rule):
    """A detection rule parsed from a Sigma-style YAML definition."""

    def __init__(self, definition: dict):
        self._def = definition
        self._custom = definition["custom"]
        self._detection = definition["detection"]

        # Standard Sigma metadata → Rule interface.
        # Sigma spec requires id to be a UUID. Our internal pipeline uses
        # short slug identifiers (rate_abuse, prompt_injection, …) for
        # alert routing, triage, and dashboards. custom.rule_id carries
        # the slug; the standard id field holds the UUID.
        self.id = self._custom.get("rule_id", definition["id"])
        self.name = definition["title"]
        self.severity = _LEVEL_MAP.get(definition["level"], definition["level"])
        self.window_seconds = self._custom["window_seconds"]
        self.description = definition.get("description", "")

        # Pre-parse the selection for fast matching.
        # Sigma selection: each key is a field name, value is exact match
        # or list (OR).  All keys must match (AND).
        self._selection = self._detection.get("selection", {})

    # ------------------------------------------------------------------
    # Rule interface
    # ------------------------------------------------------------------

    def match(self, event: dict) -> bool:
        """Evaluate detection.selection against a single event.

        Standard Sigma semantics: each field in the selection must match.
        A scalar value is an exact match; a list is OR (any value matches).
        """
        for field, expected in self._selection.items():
            actual = event.get(field)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True

    def trigger(self, events: list[dict]) -> bool:
        """Evaluate custom.trigger against the accumulated window."""
        spec = self._custom["trigger"]
        trigger_type = spec["type"]

        if trigger_type == "count":
            return self._trigger_count(events, spec)
        elif trigger_type == "compound":
            return self._trigger_compound(events, spec)
        else:
            raise ValueError(f"Unknown trigger type: {trigger_type}")

    def evidence(self, events: list[dict]) -> dict:
        """Compute evidence from custom.evidence definitions."""
        if not events:
            return {}
        result = {}
        for item in self._custom.get("evidence", []):
            key = item["output_key"]
            result[key] = self._eval_evidence(events, item)
        return result

    def group_key(self, event: dict) -> str:
        field = self._custom.get("group_key", "user_id")
        return event[field]

    # ------------------------------------------------------------------
    # Trigger implementations
    # ------------------------------------------------------------------

    def _trigger_count(self, events, spec):
        op = _OPS[spec["operator"]]
        return op(len(events), spec["threshold"])

    def _trigger_compound(self, events, spec):
        min_events = spec.get("min_events", 0)
        if len(events) < min_events:
            return False
        for cond in spec["conditions"]:
            if not self._eval_metric_condition(events, cond):
                return False
        return True

    def _eval_metric_condition(self, events, cond):
        metric = cond["metric"]
        op = _OPS[cond["operator"]]
        threshold = cond["threshold"]

        if metric == "avg":
            field = cond["field"]
            values = [e.get(field, 0) for e in events]
            return op(sum(values) / len(values), threshold)

        elif metric == "ratio_where":
            field = cond["field"]
            where = cond["where"]
            matching = sum(1 for e in events if self._where_check(e, field, where))
            ratio = matching / len(events)
            return op(ratio, threshold)

        else:
            raise ValueError(f"Unknown metric: {metric}")

    # ------------------------------------------------------------------
    # Evidence implementations
    # ------------------------------------------------------------------

    def _eval_evidence(self, events, item):
        operation = item["operation"]
        rounding = item.get("round")

        if operation == "count":
            return len(events)

        elif operation == "count_where":
            field = item["field"]
            where_value = item["where_value"]
            val = sum(1 for e in events if e.get(field) == where_value)
            return val

        elif operation == "avg":
            field = item["field"]
            values = [e.get(field, 0) for e in events]
            val = sum(values) / len(values)
            return round(val, int(rounding)) if rounding is not None else val

        elif operation == "max":
            field = item["field"]
            return max(e.get(field, 0) for e in events)

        elif operation == "ratio_where":
            field = item["field"]
            where_value = item.get("where_value")
            where = item.get("where")
            if where_value is not None:
                matching = sum(1 for e in events if e.get(field) == where_value)
            elif where is not None:
                matching = sum(
                    1 for e in events if self._where_check(e, field, where)
                )
            else:
                matching = 0
            val = matching / max(len(events), 1)
            return round(val, int(rounding)) if rounding is not None else val

        elif operation == "unique_list":
            field = item["field"]
            return list({e.get(field, "unknown") for e in events})

        elif operation == "events_per_second":
            timestamps = [e.get("timestamp", 0) for e in events]
            span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1
            return round(len(events) / max(span, 1), 2)

        else:
            raise ValueError(f"Unknown evidence operation: {operation}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _where_check(event: dict, field: str, where: str) -> bool:
        """Evaluate a where clause against an event field."""
        value = event.get(field, 0)
        if where == "gt0":
            return value > 0
        elif where == "eq0":
            return value == 0
        else:
            raise ValueError(f"Unknown where clause: {where}")
