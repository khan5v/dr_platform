"""Tests for the mock triage engine."""

from triage.mock import mock_triage

_REQUIRED_FIELDS = {"verdict", "confidence", "tier", "risk_score",
                     "reasoning", "recommended_actions"}


def _alert(rule_id="rate_abuse", severity="high", event_count=62, **evidence):
    return {
        "rule_id": rule_id,
        "rule_name": "Test Rule",
        "severity": severity,
        "user_id": "user_001",
        "org_id": "org_001",
        "timestamp": 1700000000.0,
        "window_seconds": 60,
        "event_count": event_count,
        "evidence": evidence,
    }


class TestMockTriage:
    def test_returns_all_required_fields(self):
        result = mock_triage(_alert())
        assert _REQUIRED_FIELDS.issubset(result.keys())

    def test_critical_severity_is_gold(self):
        result = mock_triage(_alert(
            rule_id="prompt_injection", severity="critical", event_count=5,
            trigger_types=["prompt_injection"], blocked_count=3,
            total_triggers=5, block_rate=0.6,
        ))
        assert result["tier"] == "gold"
        assert result["verdict"] == "true_positive"
        assert result["confidence"] == "high"

    def test_high_severity_high_count_is_gold(self):
        result = mock_triage(_alert(
            severity="high", event_count=62,
            api_request_count=44, rate_limit_count=18,
            events_per_second=1.03,
        ))
        assert result["tier"] == "gold"
        assert result["verdict"] == "true_positive"

    def test_high_severity_low_count_is_silver(self):
        result = mock_triage(_alert(severity="high", event_count=5))
        assert result["tier"] == "silver"
        assert result["verdict"] == "needs_investigation"

    def test_risk_score_range(self):
        for severity, count in [("critical", 5), ("high", 62), ("high", 5)]:
            result = mock_triage(_alert(severity=severity, event_count=count))
            assert 1 <= result["risk_score"] <= 10

    def test_reasoning_is_nonempty(self):
        result = mock_triage(_alert(
            events_per_second=1.5, rate_limit_count=20,
        ))
        assert len(result["reasoning"]) > 20

    def test_recommended_actions_is_list(self):
        result = mock_triage(_alert())
        assert isinstance(result["recommended_actions"], list)
        assert len(result["recommended_actions"]) >= 1

    def test_token_abuse_triage(self):
        result = mock_triage(_alert(
            rule_id="token_abuse", severity="high", event_count=6,
            avg_input_tokens=160000, cache_hit_rate=0.0,
            sample_size=6, models_used=["claude-sonnet-4-5-20250929"],
        ))
        assert result["verdict"] in ("true_positive", "needs_investigation")
        assert result["tier"] in ("gold", "silver")

    def test_unknown_rule_doesnt_crash(self):
        result = mock_triage(_alert(rule_id="unknown_rule"))
        assert _REQUIRED_FIELDS.issubset(result.keys())
