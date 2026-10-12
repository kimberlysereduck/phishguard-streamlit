from intent_analyzer import IntentAnalyzer


def test_analyze_uses_heuristics_when_no_api_client_is_configured():
    result = IntentAnalyzer().analyze(
        body="Your password expires immediately. Sign in now.",
        sender="security@example.com",
        subject="Urgent action required",
    )

    assert result["threat_score"] == 75
    assert result["verdict"] == "PHISHING"
    assert result["intent_analysis"]["primary_intent"] == "Credential Harvesting"
    assert result["recommended_actions"]


def test_analyze_returns_safe_result_for_unremarkable_content():
    result = IntentAnalyzer().analyze(
        body="The team meeting is scheduled for next Tuesday.",
        sender="colleague@example.com",
        subject="Meeting schedule",
    )

    assert result["threat_score"] == 0
    assert result["verdict"] == "SAFE"
    assert result["intent_analysis"]["primary_intent"] == "Legitimate Communication"
