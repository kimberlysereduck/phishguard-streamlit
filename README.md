# PhishGuard AI - AI-Powered Phishing Email Analyzer

An intelligent cybersecurity application with a Streamlit web interface that detects suspicious links, spoofed headers, and deceptive psychological intent using **Google Gemini AI** and deterministic threat heuristics.

---

## 🚀 Features

- **🔗 Deep Link Forensic Inspection**:
  - Homograph / Punycode (IDN) attack detection
  - Typosquatting / Levenshtein distance check against Fortune 500 & tech brands (Microsoft, Google, Apple, PayPal, etc.)
  - Visual Anchor Mismatch (e.g., text displays `https://paypal.com` but points to an attacker IP)
  - Raw numeric IP address hosts & high-abuse phishing TLDs
  - URL shortener resolution flag
- **🧠 AI Cognitive Intent Analysis**:
  - Powered by the official `google-genai` SDK
  - Classifies primary attack intent (Credential Harvesting, BEC Wire Fraud, Malware Delivery)
  - Breaks down psychological manipulation triggers (Urgency, Authority, Fear of Consequence, Greed)
- **📊 SOC Dashboard**:
  - Composite 0-100 threat score and verdict
  - Actionable defensive response checklist for recipients and SOC analysts
  - Exportable JSON incident report & Indicators of Compromise (IOCs)
- **⚡ Local Heuristic Fallback**:
  - Works out of the box even without an API key using rule-based pattern matching!

---

## 🛠️ Quickstart (3 Steps)

### 1. Clone & Set Up Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate on Linux/macOS:
source venv/bin/activate

# Or on Windows:
venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key & Run

```bash
# Copy environment configuration
cp .env.example .env

# Edit .env and paste your Gemini API key:
# GEMINI_API_KEY="your_api_key_here"

# Launch Streamlit web app
streamlit run app.py
```

The app will immediately open in your browser at `http://localhost:8501`!

---

## 📁 Project Architecture

```
├── app.py              # Main Streamlit web UI & SOC dashboard
├── analyzer.py         # Multi-layer threat scoring & coordination
├── link_scanner.py     # Forensic URL parsing & typosquatting detection
├── intent_analyzer.py  # Gemini AI & heuristic intent modeling
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable sample
└── README.md           # Documentation
```

---

## 🛡️ License & Disclaimer

For defensive cybersecurity analysis, educational training, and authorized threat investigation only.
