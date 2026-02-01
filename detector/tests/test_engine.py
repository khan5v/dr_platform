"""Tests for DetectionEngine — end-to-end wiring, dedup, malformed data."""

import time
import pytest

from detector.engine import DetectionEngine
from detector.rules.rate_abuse import RateAbuse
from detector.rules.prompt_injection import PromptInjection
from detector.rules.token_abuse import TokenAbuse


def _event(event_type="api_request", user_id="user_001", org_id="org_001",
           ts_offset=0, **extra):
    """Helper to build an event dict with sane defaults."""
    e = {
        "event_type": event_type,
        "timestamp": time.time() + ts_offset,
        "user_id": user_id,
        "org_id": org_id,
    }
    e.update(extra)
    return e


# ---------------------------------------------------------------------------
# End-to-end: each rule fires when it should
# ---------------------------------------------------------------------------

class TestEndToEnd:
    def setup_method(self):
        self.engine = DetectionEngine()

    def test_rate_abuse_fires(self):
        alerts = []
        for i in range(62):
            alerts.extend(self.engine.evaluate(
                _event(ts_offset=-30 + i * 0.4, user_id="attacker")
            ))
        rule_ids = [a["rule_id"] for a in alerts]
        assert "rate_abuse" in rule_ids

    def test_prompt_injection_fires(self):
        alerts = []
        for i in range(5):
            alerts.extend(self.engine.evaluate(
                _event("safety_trigger", ts_offset=-60 + i * 10, user_id="prober")
            ))
        rule_ids = [a["rule_id"] for a in alerts]
        assert "prompt_injection" in rule_ids

    def test_token_abuse_fires(self):
        alerts = []
        for i in range(6):
            alerts.extend(self.engine.evaluate(
                _event(ts_offset=-300 + i * 50, user_id="stuffer",
                       input_tokens=160_000, cache_read_input_tokens=0)
            ))
        rule_ids = [a["rule_id"] for a in alerts]
        assert "token_abuse" in rule_ids

    def test_normal_user_no_alerts(self):
        alerts = []
        for i in range(10):
            alerts.extend(self.engine.evaluate(
                _event(ts_offset=-10 + i, user_id="good_user",
                       input_tokens=2000, cache_read_input_tokens=1000)
            ))
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Dedup: window clears after alert, must re-accumulate to fire again
# ---------------------------------------------------------------------------

class TestDedup:
    def test_window_clears_after_alert(self):
        engine = DetectionEngine(rules=[PromptInjection()])
        alerts = []
        # Fire once with 4 events
        for i in range(5):
            alerts.extend(engine.evaluate(
                _event("safety_trigger", ts_offset=-60 + i * 10, user_id="u")
            ))
        assert len(alerts) == 1

        # Next event alone should NOT fire again (window was cleared)
        new_alerts = engine.evaluate(
            _event("safety_trigger", ts_offset=0, user_id="u")
        )
        assert len(new_alerts) == 0

    def test_re_accumulation_fires_again(self):
        engine = DetectionEngine(rules=[PromptInjection()])
        # First burst
        for i in range(5):
            engine.evaluate(
                _event("safety_trigger", ts_offset=-60 + i * 10, user_id="u")
            )
        # Second burst — enough to re-trigger
        alerts = []
        for i in range(5):
            alerts.extend(engine.evaluate(
                _event("safety_trigger", ts_offset=-10 + i, user_id="u")
            ))
        assert len(alerts) == 1


# ---------------------------------------------------------------------------
# User isolation: different users have independent windows
# ---------------------------------------------------------------------------

class TestUserIsolation:
    def test_different_users_independent(self):
        engine = DetectionEngine(rules=[PromptInjection()])
        # user_a gets 3 events (below threshold)
        for i in range(3):
            engine.evaluate(
                _event("safety_trigger", ts_offset=-10 + i, user_id="user_a")
            )
        # user_b gets 3 events (below threshold)
        for i in range(3):
            engine.evaluate(
                _event("safety_trigger", ts_offset=-10 + i, user_id="user_b")
            )
        # Neither should have fired (3+3=6 total but 3 each)
        # One more event for user_a should bring them to 4 → fire
        alerts = engine.evaluate(
            _event("safety_trigger", ts_offset=0, user_id="user_a")
        )
        assert len(alerts) == 1
        assert alerts[0]["user_id"] == "user_a"


# ---------------------------------------------------------------------------
# Malformed / poisoned data
# ---------------------------------------------------------------------------

class TestMalformedEvents:
    def setup_method(self):
        self.engine = DetectionEngine()

    def test_missing_event_type_raises(self):
        with pytest.raises(KeyError):
            self.engine.evaluate({"timestamp": time.time(), "user_id": "u"})

    def test_missing_timestamp_uses_current_time(self):
        """Events without timestamp should still be processed (engine falls back to now)."""
        alerts = self.engine.evaluate({
            "event_type": "api_request",
            "user_id": "u",
            "org_id": "o",
        })
        # Should not crash; may or may not produce alert
        assert isinstance(alerts, list)

    def test_missing_user_id_raises_on_group_key(self):
        with pytest.raises(KeyError):
            self.engine.evaluate({
                "event_type": "api_request",
                "timestamp": time.time(),
                "org_id": "o",
            })

    def test_future_timestamp_events_are_dropped(self):
        """Events with far-future timestamps should be silently dropped by the window."""
        engine = DetectionEngine(rules=[RateAbuse()])
        alerts = []
        for i in range(100):
            alerts.extend(engine.evaluate({
                "event_type": "api_request",
                "timestamp": time.time() + 9999,  # way in the future
                "user_id": "u",
                "org_id": "o",
            }))
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Alert schema
# ---------------------------------------------------------------------------

class TestAlertSchema:
    def test_alert_contains_required_fields(self):
        engine = DetectionEngine(rules=[PromptInjection()])
        alerts = []
        for i in range(5):
            alerts.extend(engine.evaluate(
                _event("safety_trigger", ts_offset=-10 + i, user_id="u", org_id="org_x")
            ))
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_id"] == "prompt_injection"
        assert alert["rule_name"] == "Prompt Injection Cluster"
        assert alert["severity"] == "critical"
        assert alert["user_id"] == "u"
        assert alert["org_id"] == "org_x"
        assert "timestamp" in alert
        assert "window_seconds" in alert
        assert "event_count" in alert
        assert isinstance(alert["event_count"], int)
