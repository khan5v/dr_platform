"""Prompt construction for LLM-assisted alert triage.

Mirrors the SOC automation pyramid: most alerts should be auto-resolved at
the Bronze tier (analyst never sees them), freeing human attention for Silver
(investigation queue) and Gold (immediate escalation).  The LLM acts as a
Tier-1 analyst — classifying alerts and assigning a response tier so the
right alerts reach the right humans at the right speed.

References:
  - NIST SP 800-61r2 §3.2 (Incident Analysis)
  - Anthropic RSA 2025: 90% investigation-time reduction via LLM triage
  - MITRE ATT&CK T1190 (Exploit Public-Facing Application) for rate abuse
  - MITRE ATT&CK T1059.006 (Command and Scripting Interpreter: Python)
    for prompt injection probing
"""

# ---------------------------------------------------------------------------
# Rule context — gives the LLM analyst background on what each rule detects
# and why it matters, so it can reason about true/false positives.
# ---------------------------------------------------------------------------
_RULE_CONTEXT = {
    "rate_abuse": (
        "This rule fires when a single user generates >60 API requests + "
        "rate-limit hits within a 60-second sliding window.  Common causes: "
        "automated scraping, credential-stuffing proxies, runaway retry loops, "
        "or load-testing tools pointed at production.  Evidence includes the "
        "request rate and rate-limit hit frequency.  A high rate_limit_count "
        "relative to api_request_count suggests the user is intentionally "
        "pushing past limits rather than accidentally bursting."
    ),
    "prompt_injection": (
        "This rule fires when a user triggers 3+ safety violations in a "
        "5-minute window.  A single safety trigger can be accidental, but a "
        "cluster indicates deliberate probing — the attacker is iterating on "
        "payloads to find what gets through the safety layer.  Evidence "
        "includes the types of safety triggers (prompt_injection, "
        "harmful_content, policy_violation) and the block rate.  A low block "
        "rate is more concerning — it means some payloads are succeeding."
    ),
    "token_abuse": (
        "This rule fires when a user's average input tokens exceed 150K with "
        "<5% cache utilization over a 15-minute window (minimum 5 requests).  "
        "Legitimate high-token users almost always leverage prompt caching.  "
        "Near-max context with zero caching suggests denial-of-wallet attacks "
        "(maximizing compute cost) or data exfiltration through the context "
        "window.  Evidence includes token statistics and model distribution."
    ),
}


# ---------------------------------------------------------------------------
# Tier definitions — Bronze/Silver/Gold response model
# ---------------------------------------------------------------------------
TIER_DESCRIPTIONS = {
    "gold": "Immediate escalation — page on-call, block user, preserve evidence",
    "silver": "Investigation queue — assign to analyst, gather context, correlate",
    "bronze": "Auto-acknowledge — log, update metrics, no human action needed",
}


def build_system_prompt() -> str:
    """Static system prompt establishing the LLM's analyst persona."""
    return (
        "You are a Tier-1 security analyst on the Detection & Response team "
        "at a company that operates a large-scale LLM API platform.  You "
        "triage alerts from the automated abuse detection pipeline.\n\n"
        "Your job is to classify each alert and assign a response tier:\n"
        "  - GOLD: Immediate escalation — page on-call engineer, block the "
        "user, preserve forensic evidence.  Reserved for confirmed attacks "
        "with active impact (prompt injection clusters, coordinated abuse).\n"
        "  - SILVER: Investigation queue — assign to a human analyst for "
        "deeper investigation.  Used when the alert is likely real but needs "
        "context (e.g., is this a legitimate power user or a bot?).\n"
        "  - BRONZE: Auto-acknowledge — log the alert, update metrics, but "
        "take no human action.  Used for known-benign patterns, single-event "
        "spikes, or low-confidence signals.\n\n"
        "Respond ONLY with a JSON object.  No markdown, no explanation "
        "outside the JSON."
    )


def build_triage_prompt(alert: dict) -> str:
    """Format an alert + evidence into a structured triage request."""
    rule_id = alert.get("rule_id", "unknown")
    context = _RULE_CONTEXT.get(rule_id, "No rule context available.")

    evidence_lines = ""
    evidence = alert.get("evidence", {})
    if evidence:
        evidence_lines = "\n".join(
            f"  {k}: {v}" for k, v in evidence.items()
        )

    return (
        f"Triage the following detection alert.\n\n"
        f"RULE: {rule_id} ({alert.get('rule_name', 'unknown')})\n"
        f"SEVERITY: {alert.get('severity', 'unknown')}\n"
        f"USER: {alert.get('user_id', 'unknown')}\n"
        f"ORG: {alert.get('org_id', 'unknown')}\n"
        f"WINDOW: {alert.get('window_seconds', 0)}s, "
        f"{alert.get('event_count', 0)} events\n\n"
        f"EVIDENCE:\n{evidence_lines}\n\n"
        f"RULE CONTEXT:\n{context}\n\n"
        f"Respond with a JSON object containing exactly these fields:\n"
        f'{{\n'
        f'  "verdict": "true_positive" | "false_positive" | "needs_investigation",\n'
        f'  "confidence": "high" | "medium" | "low",\n'
        f'  "tier": "gold" | "silver" | "bronze",\n'
        f'  "risk_score": <integer 1-10>,\n'
        f'  "reasoning": "<2-3 sentences>",\n'
        f'  "recommended_actions": ["<action 1>", "<action 2>"]\n'
        f'}}'
    )
