"""
Phishing Analyzer Orchestrator
Coordinates link heuristics, sender verification, and AI intent models.
"""

from typing import Dict, Any, Optional
from link_scanner import LinkScanner
from intent_analyzer import IntentAnalyzer

class PhishingAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.link_scanner = LinkScanner()
        self.intent_analyzer = IntentAnalyzer(api_key=api_key)

    def analyze(
        self,
        body: str,
        sender: str = "",
        subject: str = "",
        headers: str = "",
        threshold: int = 65
    ) -> Dict[str, Any]:
        """Runs multi-layer inspection on the email."""
        # 1. Forensic Link Inspection
        links = self.link_scanner.scan(body + " " + headers)

        # 2. Intent & Psychological Modeling
        intent_data = self.intent_analyzer.analyze(
            body=body,
            sender=sender,
            subject=subject,
            headers=headers,
            links_summary=links
        )

        # 3. Calculate Composite Score
        link_max_risk = 0
        for l in links:
            if l["risk_level"] == "CRITICAL":
                link_max_risk = max(link_max_risk, 45)
            elif l["risk_level"] == "HIGH":
                link_max_risk = max(link_max_risk, 30)
            elif l["risk_level"] == "MEDIUM":
                link_max_risk = max(link_max_risk, 15)

        base_ai_score = intent_data.get("threat_score", 0)
        final_score = max(base_ai_score, min(100, base_ai_score + (link_max_risk // 2)))

        # Determine Verdict
        if final_score >= threshold:
            verdict = intent_data.get("verdict", "PHISHING")
        elif final_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "threat_score": final_score,
            "verdict": verdict,
            "summary": intent_data.get("summary", "Analysis completed."),
            "links": links,
            "intent": intent_data.get("intent_analysis", {}),
            "sender_analysis": intent_data.get("sender_analysis", {}),
            "recommended_actions": intent_data.get("recommended_actions", []),
            "technical_indicators": intent_data.get("technical_indicators", [])
        }
