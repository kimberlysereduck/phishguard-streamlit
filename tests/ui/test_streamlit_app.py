from pathlib import Path

from streamlit.testing.v1 import AppTest


APP_PATH = Path(__file__).resolve().parents[2] / "app.py"
ANALYZE_BUTTON = "🚀 Analyze Threat Now"


def _element_by_label(elements, label):
    return next(element for element in elements if element.label == label)


def test_app_renders_without_an_analysis():
    app = AppTest.from_file(str(APP_PATH), default_timeout=10).run()

    assert not app.exception
    assert _element_by_label(app.button, ANALYZE_BUTTON)
    assert len(app.tabs) == 4


def test_app_requires_subject_or_body_before_analysis(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    app = AppTest.from_file(str(APP_PATH), default_timeout=10).run()

    _element_by_label(app.button, ANALYZE_BUTTON).click().run()

    assert not app.exception
    assert app.warning
    assert "Please provide email subject or body text to analyze." in app.warning[0].value
    assert app.session_state["analysis_result"] is None


def test_app_analyzes_email_and_renders_report_without_api_key(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "")
    app = AppTest.from_file(str(APP_PATH), default_timeout=10).run()
    _element_by_label(app.text_area, "Email Body Content (Raw text or HTML)").set_value(
        "Urgent password reset required"
    )
    _element_by_label(app.text_input, "Email Subject").set_value(
        "Action required"
    )

    app.run()
    _element_by_label(app.button, ANALYZE_BUTTON).click().run()

    assert not app.exception
    assert app.session_state["analysis_result"]["verdict"] == "PHISHING"
    assert len(app.metric) == 4
    assert len(app.download_button) == 1
