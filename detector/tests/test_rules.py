"""Tests for detection rules — match filtering, trigger boundaries, malformed data."""

import pytest

from detector.rules.rate_abuse import RateAbuse
from detector.rules.prompt_injection import PromptInjection
from detector.rules.token_abuse import TokenAbuse


# ---------------------------------------------------------------------------
# RateAbuse
# ---------------------------------------------------------------------------

class TestRateAbuseMatch:
    def setup_method(self):
        self.rule = RateAbuse()

    def test_matches_api_request(self):
        assert self.rule.match({"event_type": "api_request", "user_id": "u"})

    def test_matches_rate_limit_event(self):
        assert self.rule.match({"event_type": "rate_limit_event", "user_id": "u"})

    def test_rejects_safety_trigger(self):
        assert not self.rule.match({"event_type": "safety_trigger", "user_id": "u"})

    def test_rejects_unknown_event_type(self):
        assert not self.rule.match({"event_type": "unknown_garbage", "user_id": "u"})


class TestRateAbuseTrigger:
    def setup_method(self):
        self.rule = RateAbuse()

    def test_60_events_does_not_fire(self):
        """Boundary: exactly 60 is within normal range."""
        assert not self.rule.trigger([{}] * 60)

    def test_61_events_fires(self):
        assert self.rule.trigger([{}] * 61)

    def test_0_events_does_not_fire(self):
        assert not self.rule.trigger([])

    def test_1_event_does_not_fire(self):
        assert not self.rule.trigger([{}])


# ---------------------------------------------------------------------------
# PromptInjection
# ---------------------------------------------------------------------------

class TestPromptInjectionMatch:
    def setup_method(self):
        self.rule = PromptInjection()

    def test_matches_safety_trigger(self):
        assert self.rule.match({"event_type": "safety_trigger", "user_id": "u"})

    def test_rejects_api_request(self):
        assert not self.rule.match({"event_type": "api_request", "user_id": "u"})

    def test_rejects_rate_limit(self):
        assert not self.rule.match({"event_type": "rate_limit_event", "user_id": "u"})


class TestPromptInjectionTrigger:
    def setup_method(self):
        self.rule = PromptInjection()

    def test_3_events_does_not_fire(self):
        """Boundary: exactly 3 is not suspicious enough."""
        assert not self.rule.trigger([{}] * 3)

    def test_4_events_fires(self):
        assert self.rule.trigger([{}] * 4)

    def test_0_events_does_not_fire(self):
        assert not self.rule.trigger([])


# ---------------------------------------------------------------------------
# TokenAbuse
# ---------------------------------------------------------------------------

class TestTokenAbuseMatch:
    def setup_method(self):
        self.rule = TokenAbuse()

    def test_matches_api_request(self):
        assert self.rule.match({"event_type": "api_request", "user_id": "u"})

    def test_rejects_safety_trigger(self):
        assert not self.rule.match({"event_type": "safety_trigger", "user_id": "u"})


class TestTokenAbuseTrigger:
    def setup_method(self):
        self.rule = TokenAbuse()

    def _events(self, n, input_tokens=160_000, cache_read=0):
        return [
            {"input_tokens": input_tokens, "cache_read_input_tokens": cache_read}
            for _ in range(n)
        ]

    def test_minimum_sample_size(self):
        """4 events is below the minimum sample — never fires regardless of values."""
        assert not self.rule.trigger(self._events(4, input_tokens=200_000))

    def test_5_events_at_boundary_fires(self):
        """Exactly 5 high-token, no-cache events should fire."""
        assert self.rule.trigger(self._events(5, input_tokens=160_000))

    def test_high_tokens_with_cache_does_not_fire(self):
        """High tokens but good cache rate = legitimate power user."""
        assert not self.rule.trigger(self._events(10, input_tokens=160_000, cache_read=50_000))

    def test_low_tokens_no_cache_does_not_fire(self):
        """Low tokens even with no cache = normal small requests."""
        assert not self.rule.trigger(self._events(10, input_tokens=5_000))

    def test_exactly_150k_does_not_fire(self):
        """Boundary: avg of exactly 150K should NOT fire (> not >=)."""
        assert not self.rule.trigger(self._events(5, input_tokens=150_000))

    def test_150001_fires(self):
        assert self.rule.trigger(self._events(5, input_tokens=150_001))

    def test_cache_rate_boundary(self):
        """4% cache rate with high tokens should still fire (< 5%)."""
        events = self._events(100, input_tokens=160_000)
        # Give 4 out of 100 events a cache hit → 4%
        for i in range(4):
            events[i]["cache_read_input_tokens"] = 50_000
        assert self.rule.trigger(events)

    def test_5_percent_cache_does_not_fire(self):
        """Exactly 5% cache rate should NOT fire (< not <=)."""
        events = self._events(100, input_tokens=160_000)
        for i in range(5):
            events[i]["cache_read_input_tokens"] = 50_000
        assert not self.rule.trigger(events)

    def test_missing_input_tokens_treated_as_zero(self):
        """Events missing input_tokens should not crash, treated as 0."""
        events = [{"cache_read_input_tokens": 0}] * 5
        assert not self.rule.trigger(events)  # avg 0 < 150K

    def test_missing_cache_field_treated_as_zero(self):
        """Events missing cache_read_input_tokens should not crash."""
        events = [{"input_tokens": 160_000}] * 5
        assert self.rule.trigger(events)


# ---------------------------------------------------------------------------
# group_key
# ---------------------------------------------------------------------------

class TestGroupKey:
    def test_default_groups_by_user_id(self):
        for rule in [RateAbuse(), PromptInjection(), TokenAbuse()]:
            assert rule.group_key({"user_id": "user_007"}) == "user_007"

    def test_missing_user_id_raises(self):
        """Malformed event without user_id should raise, not silently pass."""
        with pytest.raises(KeyError):
            RateAbuse().group_key({"org_id": "org_001"})
