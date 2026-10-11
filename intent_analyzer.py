"""
Intent Analyzer Module
Analyzes psychological triggers (Urgency, Authority, Fear, Greed)
and social engineering tactics using Google Gemini API.
"""

import json
from typing import Dict, Any, Optional, List

class IntentAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.client = None
        if api_key:
            try:
                # Modern google-genai SDK
                from google import genai
                self.client = genai.Client(api_key=api_key)
            except Exception as e:
                print(f"Warning: Failed to initialize google-genai client: {e}")

    def analyze(
        self,
        body: str,
        sender: str = "",
        subject: str = "",
        headers: str = "",
        links_summary: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Analyzes intent via Gemini AI or heuristic rule engine."""
        if self.client:
            try:
                return self._analyze_with_gemini(body, sender, subject, headers, links_summary)
            except Exception as e:
                print(f"Gemini API call failed, falling back to heuristics: {e}")

        return self._analyze_heuristics(body, sender, subject)

    def _analyze_with_gemini(
        self,
        body: str,
        sender: str,
        subject: str,
        headers: str,
        links_summary: Optional[List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        prompt = f"""You are a Principal Cybersecurity SOC Analyst specializing in Phishing and BEC analysis.
Analyze this email thoroughly and output STRICT JSON only:
{{
  "threat_score": number (0-100),
  "verdict": "SAFE" | "SUSPICIOUS" | "PHISHING" | "SPEAR_PHISHING" | "BEC_WIRE_FRAUD",
  "confidence": number (0-100),
  "summary": "Crisp 1-2 sentence executive assessment",
  "intent_analysis": {{
    "primary_intent": "Credential Harvesting" | "Financial Wire Coercion" | "Malware Delivery" | "Legitimate",
    "psychological_triggers": [
      {{ "name": "Urgency", "level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL", "explanation": "..." }},
      {{ "name": "Authority", "level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL", "explanation": "..." }},
      {{ "name": "Fear", "level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL", "explanation": "..." }},
      {{ "name": "Greed", "level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL", "explanation": "..." }}
    ],
    "deception_techniques": ["list of detected tactics"]
  }},
  "sender_analysis": {{
    "is_spoofed": boolean,
    "anomalies": ["sender red flags"]
  }},
  "recommended_actions": ["concrete action steps for recipient and SOC team"]
}}

EMAIL DATA:
Sender: {sender}
Subject: {subject}
Headers: {headers}
Body:
{body}
"""
        response = self.client.models.generate_content(
            model='gemini-3.8-flash',
            contents=prompt,
            config={
                'response_mime_type': 'application/json',
                'temperature': 0.1
            }
        )
        return json.loads(response.text)

    def _analyze_heuristics(self, body: str, sender: str, subject: str) -> Dict[str, Any]:
        """Local rule-based heuristic fallback if API key is not present."""
        text = (body + " " + sender + " " + subject).lower()

        urgency_terms = ["urgent", "immediately", "24 hours", "suspended", "action required"]
        cred_terms = ["password", "verify credentials", "sign in", "reset", "login"]
        fin_terms = ["wire", "invoice", "bank", "payment", "gift card", "refund"]

        urgency_hits = [t for t in urgency_terms if t in text]
        cred_hits = [t for t in cred_terms if t in text]
        fin_hits = [t for t in fin_terms if t in text]

        score = 0
        score += min(40, len(urgency_hits) * 15)
        score += min(35, len(cred_hits) * 18)
        score += min(35, len(fin_hits) * 15)

        primary = "Legitimate Communication"
        if cred_hits:
            primary = "Credential Harvesting"
        elif fin_hits:
            primary = "Financial Coercion"
        elif urgency_hits:
            primary = "Urgent Social Engineering"

        return {
            "threat_score": min(100, score),
            "verdict": "PHISHING" if score >= 65 else "SUSPICIOUS" if score >= 35 else "SAFE",
            "confidence": 75,
            "summary": f"Heuristic evaluation detected {len(urgency_hits) + len(cred_hits) + len(fin_hits)} suspicious intent triggers.",
            "intent_analysis": {
                "primary_intent": primary,
                "psychological_triggers": [
                    {"name": "Urgency", "level": "HIGH" if urgency_hits else "LOW", "explanation": f"Found: {', '.join(urgency_hits) or 'None'}"},
                    {"name": "Fear", "level": "HIGH" if "suspended" in text else "LOW", "explanation": "Threat of account suspension or penalty"},
                    {"name": "Authority", "level": "MEDIUM" if "it" in text or "admin" in text else "LOW", "explanation": "Impersonation of corporate administration"}
                ],
                "deception_techniques": [f"Keyword triggers: {', '.join(urgency_hits + cred_hits + fin_hits)}"]
            },
            "sender_analysis": {"is_spoofed": False, "anomalies": []},
            "recommended_actions": [
                "Verify sender via out-of-band communication (phone/Slack)",
                "Do not click hyperlinks or download attachments",
                "Forward sample to enterprise SOC or security team"
            ]
        }
