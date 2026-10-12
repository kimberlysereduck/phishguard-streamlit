import json
from types import SimpleNamespace

from intent_analyzer import IntentAnalyzer


def test_gemini_request_parses_response_and_sends_email_context():
    expected = {
        "threat_score": 82,
        "verdict": "PHISHING",
        "intent_analysis": {"primary_intent": "Credential Harvesting"},
    }
    requests = []

    def generate_content(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(text=json.dumps(expected))

    analyzer = IntentAnalyzer()
    analyzer.client = SimpleNamespace(
        models=SimpleNamespace(generate_content=generate_content)
    )

    result = analyzer.analyze(
        body="Verify your password now",
        sender="alerts@example.com",
        subject="Urgent account action",
        headers="Authentication-Results: spf=fail",
        links_summary=[{"url": "https://example.xyz/login"}],
    )

    assert result == expected
    assert len(requests) == 1
    request = requests[0]
    assert request["model"] == "gemini-3.8-flash"
    assert request["config"] == {
        "response_mime_type": "application/json",
        "temperature": 0.1,
    }
    assert "alerts@example.com" in request["contents"]
    assert "Urgent account action" in request["contents"]
    assert "Authentication-Results: spf=fail" in request["contents"]
    assert "Verify your password now" in request["contents"]


def test_gemini_api_failure_falls_back_to_local_heuristics(capsys):
    def generate_content(**kwargs):
        raise RuntimeError("service unavailable")

    analyzer = IntentAnalyzer()
    analyzer.client = SimpleNamespace(
        models=SimpleNamespace(generate_content=generate_content)
    )

    result = analyzer.analyze(
        body="Urgent action required: immediately reset your password and sign in"
    )

    assert result["verdict"] == "PHISHING"
    assert result["intent_analysis"]["primary_intent"] == "Credential Harvesting"
    assert "falling back to heuristics" in capsys.readouterr().out
