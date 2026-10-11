"""
PhishGuard AI - AI-Powered Phishing Email Analyzer
Web interface built with Streamlit and Gemini AI.
Detects suspicious links, spoofed headers, and deceptive intent.
"""

import streamlit as st
import pandas as pd
import json
import os
from dotenv import load_dotenv
from analyzer import PhishingAnalyzer

# Load environment variables
load_dotenv()

# Streamlit Page Configuration
st.set_page_config(
    page_title="PhishGuard AI - Email Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark-Themed Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #f59e0b, #ef4444);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #94a3b8;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px;
    }
    .badge-critical {
        background-color: #ef444420;
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
    }
    .badge-safe {
        background-color: #10b98120;
        color: #10b981;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #0f172a;
        border-radius: 6px;
        padding: 8px 16px;
    }
</style>
""", unsafe_allow_html=True)

# Preloaded Samples for Quick Demonstration
SAMPLES = {
    "Select a preloaded attack template...": {
        "sender": "",
        "subject": "",
        "body": "",
        "headers": ""
    },
    "Microsoft 365 Credential Harvest (Deceptive Anchor & Lookalike Domain)": {
        "sender": '"Microsoft IT Helpdesk" <support@micros0ft-security-portal.xyz>',
        "subject": "CRITICAL: Your Microsoft 365 password expires in 2 hours - Immediate action required",
        "body": """Hello Team Member,

Your Microsoft Office 365 corporate account password will expire today at 18:00 PM EST. Failure to update your credentials will result in immediate termination of Outlook, OneDrive, and Teams access.

To prevent disruption to your workstation, please retain your current password or reset your login credentials immediately using the official corporate single sign-on link below:

<a href="http://login.micros0ft-security-portal.xyz/auth/login.php?user=target">https://login.microsoftonline.com/common/oauth2/v2.0/authorize</a>

If you do not complete this verification within 2 hours, your account will be locked.

Best regards,
Global IT Support & Security Operations Center""",
        "headers": "From: support@micros0ft-security-portal.xyz\nAuthentication-Results: spf=fail; dkim=none"
    },
    "CEO Urgent Wire Transfer (BEC / Social Engineering)": {
        "sender": '"David Sterling (CEO)" <ceo.davidsterling.exec@gmail.com>',
        "subject": "CONFIDENTIAL: Urgent Wire Transfer for Project Vanguard - Need this done before 4 PM",
        "body": """Hi,

Are you at your desk right now?

I am currently in an executive closed-door meeting for the strategic acquisition we discussed last month. Our legal counsel has reached an agreement, but we need an initial escrow retainer of $48,500.00 wired before the financial cut-off at 4:00 PM today.

Due to strict SEC compliance and NDA stipulations, please do NOT discuss this with anyone in the office or call my cell phone, as I am presenting in the boardroom.

Please confirm that you can process an immediate domestic ACH/Wire from our operating reserve. Once you reply, I will send over the routing details.

David Sterling
Chief Executive Officer""",
        "headers": "From: ceo.davidsterling.exec@gmail.com\nReply-To: david.sterling.private@contractor-holdings.ru"
    },
    "PayPal Suspicious Payment Refund (Homograph IP & Fear)": {
        "sender": '"PayPal Security Alert" <service-notice@paypa1-resolution-center.com>',
        "subject": "Security Alert: We detected an unauthorized payment of $1,429.00 on your account",
        "body": """Dear PayPal Customer,

We detected an unauthorized payment of $1,429.00 USD to 'Coinbase International Ltd' from an unrecognized device in Vladivostok.

If you DID NOT authorize this transaction, click below to open the dispute resolution center and cancel this charge:

[https://www.paypal.com/dispute-resolution/cancel-charge](http://192.168.1.105/paypal-fake-login/dispute.html)

Failure to cancel within 24 hours will result in the funds being permanently cleared.

PayPal Security Team""",
        "headers": "From: service-notice@paypa1-resolution-center.com"
    },
    "Legitimate GitHub Advisory (Clean Sample)": {
        "sender": "GitHub Security <notifications@github.com>",
        "subject": "[GitHub] Dependabot alert: Regular expression denial of service in express",
        "body": """Hi developer,

Dependabot has detected a vulnerability in your repository.
Severity: Moderate
Package: express (npm)

You can review this advisory directly on GitHub:
https://github.com/company/api-gateway/security/dependabot/14

Manage notification preferences at https://github.com/settings/notifications""",
        "headers": "From: notifications@github.com\nAuthentication-Results: spf=pass; dkim=pass"
    }
}

# Sidebar Configuration
with st.sidebar:
    st.image("https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&q=80", use_container_width=True)
    st.title("🛡️ SOC Threat Controls")
    
    # API Key Configuration
    env_key = os.getenv("GEMINI_API_KEY", "")
    api_key_input = st.text_input(
        "Gemini API Key (Optional)",
        value=env_key,
        type="password",
        help="Provide your Google Gemini API key for deep cognitive intent analysis. If empty, local heuristic rules will be used."
    )
    
    st.markdown("---")
    st.subheader("⚙️ Detection Parameters")
    risk_threshold = st.slider("Phishing Alert Threshold", min_value=30, max_value=90, value=65, step=5)
    deep_link_scan = st.checkbox("Enable Homograph & Typosquat Heuristics", value=True)
    
    st.markdown("---")
    st.subheader("📂 Quick Load Attack Sample")
    selected_sample_name = st.selectbox("Select Attack Scenario", list(SAMPLES.keys()))
    
    if st.button("Load Selected Template into Editor"):
        sample_data = SAMPLES[selected_sample_name]
        st.session_state["sender_input"] = sample_data["sender"]
        st.session_state["subject_input"] = sample_data["subject"]
        st.session_state["body_input"] = sample_data["body"]
        st.session_state["headers_input"] = sample_data["headers"]
        st.rerun()

# Header
st.markdown('<div class="main-header">PhishGuard AI Threat Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Automated forensic email analysis detecting suspicious links, typosquatting domains, and psychological manipulation intent.</div>', unsafe_allow_html=True)

# Main UI Tabs
tab_scan, tab_links, tab_intent, tab_export = st.tabs([
    "📥 Email Threat Scanner",
    "🔗 Suspicious Link Inspector",
    "🧠 Intent & Threat Psychology",
    "📋 SOC Playbook & Export"
])

# Initialize Session State
if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None

with tab_scan:
    col_input, col_meta = st.columns([3, 1])
    
    with col_input:
        subject = st.text_input(
            "Email Subject",
            value=st.session_state.get("subject_input", ""),
            placeholder="e.g., URGENT: Verify your account immediately"
        )
        body = st.text_area(
            "Email Body Content (Raw text or HTML)",
            value=st.session_state.get("body_input", ""),
            height=240,
            placeholder="Paste suspicious email text, HTML, or markdown message here..."
        )
    
    with col_meta:
        sender = st.text_input(
            "Sender (From header)",
            value=st.session_state.get("sender_input", ""),
            placeholder="e.g., CEO <ceo@fakemail.com>"
        )
        headers = st.text_area(
            "Raw Email Headers (Optional)",
            value=st.session_state.get("headers_input", ""),
            height=130,
            placeholder="From: ...\nReceived: ...\nAuthentication-Results: ..."
        )
        
        analyze_clicked = st.button("🚀 Analyze Threat Now", type="primary", use_container_width=True)

    if analyze_clicked:
        if not body and not subject:
            st.warning("⚠️ Please provide email subject or body text to analyze.")
        else:
            with st.spinner("🔍 Running link forensic inspection and intent cognitive analysis..."):
                active_api_key = api_key_input.strip() or None
                analyzer = PhishingAnalyzer(api_key=active_api_key)
                
                result = analyzer.analyze(
                    body=body,
                    sender=sender,
                    subject=subject,
                    headers=headers,
                    threshold=risk_threshold
                )
                st.session_state["analysis_result"] = result

    # Display Analysis Dashboard
    result = st.session_state.get("analysis_result")
    if result:
        st.markdown("---")
        score = result["threat_score"]
        verdict = result["verdict"]
        
        # Threat KPI Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric(
                label="Overall Threat Score",
                value=f"{score} / 100",
                delta=f"-{score} Risk" if score > 50 else "+Safe",
                delta_color="inverse" if score > 50 else "normal"
            )
        with m2:
            st.metric(label="Verdict Assessment", value=verdict)
        with m3:
            st.metric(label="Suspicious Links Found", value=len(result["links"]))
        with m4:
            primary_intent = result.get("intent", {}).get("primary_intent", "Unknown")
            st.metric(label="Detected Attack Intent", value=primary_intent)

        # Threat Alert Banner
        if score >= 70:
            st.error(f"🚨 **CRITICAL THREAT DETECTED:** {result.get('summary', 'High confidence phishing indicators detected.')}")
        elif score >= 40:
            st.warning(f"⚠️ **SUSPICIOUS EMAIL:** {result.get('summary', 'Anomalous indicators present. Exercise extreme caution.')}")
        else:
            st.success(f"✅ **LEGITIMATE / CLEAN:** {result.get('summary', 'No obvious malicious indicators detected.')}")

        # Quick Overview Cards
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("🎯 Primary Threat Vectors")
            techniques = result.get("intent", {}).get("deception_techniques", [])
            if techniques:
                for tech in techniques:
                    st.markdown(f"• **{tech}**")
            else:
                st.info("No overt deception tactics detected.")

        with c2:
            st.subheader("🛡️ Immediate Recommended Actions")
            actions = result.get("recommended_actions", [])
            if actions:
                for act in actions:
                    st.markdown(f"✅ {act}")
            else:
                st.write("No mitigation actions required for clean emails.")

with tab_links:
    st.subheader("🔗 Extracted Links & Domain Forensics")
    result = st.session_state.get("analysis_result")
    if result and result.get("links"):
        links_data = []
        for l in result["links"]:
            links_data.append({
                "Target URL": l["url"],
                "Domain": l["domain"],
                "Risk": l["risk_level"],
                "IP Address": "Yes" if l["is_ip"] else "No",
                "Typosquatting": "Yes" if l["is_typosquat"] else "No",
                "Homograph/Punycode": "Yes" if l["is_punycode"] else "No",
                "Anchor Mismatch": "Yes" if l["mismatched_anchor"] else "No",
                "Identified Flags": ", ".join(l["threats"]) if l["threats"] else "Clean"
            })
        
        df_links = pd.DataFrame(links_data)
        st.dataframe(df_links, use_container_width=True)
        
        for idx, l in enumerate(result["links"], 1):
            with st.expander(f"Link #{idx}: {l['domain']} ({l['risk_level']})"):
                st.write(f"**Full URL:** `{l['url']}`")
                if l.get("anchor_text"):
                    st.write(f"**Visible Anchor Text:** `{l['anchor_text']}`")
                if l["threats"]:
                    st.write("**Threat Breakdown:**")
                    for t in l["threats"]:
                        st.markdown(f"- 🔴 {t}")
                else:
                    st.success("No anomalies detected for this destination.")
    else:
        st.info("No links found in current message. Run a scan on an email containing links.")

with tab_intent:
    st.subheader("🧠 Cognitive Intent & Social Engineering Analysis")
    result = st.session_state.get("analysis_result")
    if result:
        intent_info = result.get("intent", {})
        triggers = intent_info.get("psychological_triggers", [])
        
        if triggers:
            trigger_df = pd.DataFrame(triggers)
            st.dataframe(trigger_df, use_container_width=True)
            
            st.subheader("Psychological Coercion Profile")
            for t in triggers:
                level = t.get("level", "LOW")
                name = t.get("name", "")
                desc = t.get("explanation", "")
                
                color = "#ef4444" if level in ["CRITICAL", "HIGH"] else "#f59e0b" if level == "MEDIUM" else "#10b981"
                st.markdown(f"**{name}** - <span style='color:{color}; font-weight:bold;'>{level}</span>", unsafe_allow_html=True)
                st.caption(desc)
        else:
            st.info("Run analysis to inspect psychological manipulation triggers.")
    else:
        st.info("No intent analysis available yet. Analyze an email first.")

with tab_export:
    st.subheader("📋 SOC Incident Report & Threat Intelligence Export")
    result = st.session_state.get("analysis_result")
    if result:
        st.download_button(
            label="💾 Download Forensic Report (JSON)",
            data=json.dumps(result, indent=2),
            file_name="phishguard_threat_report.json",
            mime="application/json",
            use_container_width=True
        )
        
        st.subheader("Raw JSON Telemetry")
        st.json(result)
    else:
        st.info("Execute an email scan first to generate SOC incident artifacts.")
