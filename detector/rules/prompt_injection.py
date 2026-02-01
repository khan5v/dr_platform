"""Prompt injection cluster — repeated safety triggers from a single user.

A single safety trigger can be accidental.  A cluster of 4+ in a 5-minute
window indicates deliberate probing — the attacker is iterating on payloads
to find what gets through.
"""

from detector.rules import Rule


class PromptInjection(Rule):
    id = "prompt_injection"
    name = "Prompt Injection Cluster"
    severity = "critical"
    window_seconds = 300

    def match(self, event):
        return event["event_type"] == "safety_trigger"

    def trigger(self, events):
        return len(events) > 3
