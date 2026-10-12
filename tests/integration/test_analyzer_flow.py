from analyzer import PhishingAnalyzer


def test_analyzer_combines_link_forensics_and_intent_assessment():
    analyzer = PhishingAnalyzer()
    email_body = (
        "URGENT: Your password expires immediately. "
        "Verify credentials and sign in now: "
        '<a href="http://micros0ft.xyz/login">'
        "https://microsoft.com</a>"
    )

    result = analyzer.analyze(
        body=email_body,
        sender="helpdesk@example.com",
        subject="Urgent action required",
        headers="Authentication-Results: spf=fail",
    )

    assert result["threat_score"] >= 65
    assert result["verdict"] == "PHISHING"
    phishing_link = next(
        link for link in result["links"] if link["url"] == "http://micros0ft.xyz/login"
    )
    assert phishing_link["risk_level"] == "CRITICAL"
    assert phishing_link["mismatched_anchor"] is True
    assert result["intent"]["primary_intent"] == "Credential Harvesting"
    assert result["recommended_actions"]
    assert "technical_indicators" in result


def test_analyzer_returns_expected_result_shape_for_clean_email():
    result = PhishingAnalyzer().analyze(
        body="The team meeting is scheduled for next Tuesday.",
        sender="colleague@example.com",
        subject="Meeting schedule",
    )

    assert result["threat_score"] == 0
    assert result["verdict"] == "SAFE"
    assert result["links"] == []
    assert result["intent"]["primary_intent"] == "Legitimate Communication"
    assert result["recommended_actions"]
