"""Detection engine — evaluates events against all rules.

Pure business logic, no Kafka dependency.  The consumer service feeds
events in and publishes the resulting alerts.

State: dict[rule_id, dict[group_key, SlidingWindow]]
"""

import time
from detector.rules import Rule, ALL_RULES
from detector.sliding_window import SlidingWindow


class DetectionEngine:

    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules or ALL_RULES

        # Each rule gets its own dict of windows, keyed by group (usually user_id).
        # Windows are created on first access with that rule's duration.
        self._state: dict[str, dict[str, SlidingWindow]] = {}
        for rule in self.rules:
            self._state[rule.id] = {}
        self._window_duration: dict[str, int] = {
            r.id: r.window_seconds for r in self.rules
        }

    def evaluate(self, event: dict) -> list[dict]:
        """Feed one event, get back zero or more alerts.

        For each rule:
          1. Filter — does this event type match the rule?
          2. Route  — find (or create) the window for this rule + group key
          3. Accumulate — add the event to that window
          4. Evaluate — ask the rule if the window contents should fire
          5. Alert  — if yes, emit an alert and clear the window (simple dedup)
        """
        ts = event.get("timestamp", time.time())
        now = time.time()
        alerts = []

        for rule in self.rules:
            # 1. Filter: skip events this rule doesn't care about
            if not rule.match(event):
                continue

            # 2. Route: each (rule, group_key) pair has its own sliding window
            #    e.g. _state["rate_abuse"]["user_001"] -> SlidingWindow(60)
            key = rule.group_key(event)
            windows = self._state[rule.id]
            if key not in windows:
                windows[key] = SlidingWindow(self._window_duration[rule.id])
            window = windows[key]

            # 3. Accumulate
            window.add(ts, event)

            # 4-5. Evaluate and alert
            current_events = window.events(now)
            if rule.trigger(current_events):
                alerts.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "user_id": event.get("user_id"),
                    "org_id": event.get("org_id"),
                    "timestamp": now,
                    "window_seconds": rule.window_seconds,
                    "event_count": len(window),
                    # Evidence summary for downstream triage — gives the LLM
                    # (or human analyst) rule-specific statistics without
                    # needing to replay the raw event window.
                    "evidence": rule.evidence(current_events),
                })
                window.clear()  # simple dedup: must re-accumulate to fire again

        return alerts
