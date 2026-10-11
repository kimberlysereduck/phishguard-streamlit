"""
Link Scanner Module
Performs deep forensic link inspection:
- Typosquatting / Levenshtein distance check against major targets
- Punycode & IDN homograph detection
- Numeric IP address detection
- Anchor text vs target href mismatch verification
- High-abuse TLD and URL shortener detection
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "chase",
    "bankofamerica", "wellsfargo", "facebook", "instagram", "dropbox",
    "docusign", "fedex", "dhl", "usps", "ups", "citibank", "outlook"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".ru", ".country", ".work", ".gq",
    ".tk", ".ml", ".cf", ".ga", ".surf", ".monster", ".cam", ".sbs", ".cfd"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "buff.ly", "cutt.ly"
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class LinkScanner:
    def scan(self, text: str) -> List[Dict[str, Any]]:
        links: List[Dict[str, Any]] = []
        seen = set()

        # 1. HTML Anchor Tags <a href="...">text</a>
        html_regex = re.compile(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE)
        for match in html_regex.finditer(text):
            url = match.group(1).strip()
            anchor = re.sub(r'<[^>]*>', '', match.group(2)).strip()
            if url and url not in seen:
                seen.add(url)
                links.append(self._inspect_link(url, anchor))

        # 2. Markdown Links [anchor](url)
        md_regex = re.compile(r'\[([^\]]+)\]\((https?://[^\s)]+)\)', re.IGNORECASE)
        for match in md_regex.finditer(text):
            anchor = match.group(1).strip()
            url = match.group(2).strip()
            if url and url not in seen:
                seen.add(url)
                links.append(self._inspect_link(url, anchor))

        # 3. Raw Plaintext URLs
        raw_regex = re.compile(r'(https?://[^\s<>"\'{}|\\^]+)', re.IGNORECASE)
        for match in raw_regex.finditer(text):
            url = match.group(1).strip()
            if url and url not in seen:
                seen.add(url)
                links.append(self._inspect_link(url))

        return links

    def _inspect_link(self, url: str, anchor_text: Optional[str] = None) -> Dict[str, Any]:
        threats = []
        is_ip = False
        is_punycode = False
        is_typosquat = False
        is_shortener = False
        suspicious_tld = False
        mismatched_anchor = False

        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or "").lower()

            # IP address check
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if ip_pattern.match(domain):
                is_ip = True
                threats.append("Numeric raw IP address host detected instead of registered domain")

            # Punycode / IDN check
            if domain.startswith("xn--") or any(ord(c) > 127 for c in domain):
                is_punycode = True
                threats.append("Punycode / Homograph internationalized domain spoofing indicator")

            # Suspicious TLD check
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious_tld = True
                    threats.append(f"High-abuse top-level domain ({tld}) commonly seen in phishing")
                    break

            # Shortener check
            if domain in SHORTENERS or any(domain.endswith("." + s) for s in SHORTENERS):
                is_shortener = True
                threats.append("URL shortener obscures destination landing page")

            # Typosquatting check
            domain_parts = domain.split(".")
            primary_name = domain_parts[-2] if len(domain_parts) >= 2 else domain
            for brand in TARGETED_BRANDS:
                if primary_name != brand and len(primary_name) >= 4:
                    dist = levenshtein_distance(primary_name, brand)
                    if dist == 1 or (dist == 2 and len(primary_name) > 5):
                        is_typosquat = True
                        threats.append(f"Typosquatting alert: Domain closely mimics legitimate brand '{brand}'")
                        break

            # Subdomain spoofing (e.g. microsoft.com.attacker.com)
            if len(domain_parts) > 3:
                for brand in TARGETED_BRANDS:
                    if brand in domain_parts[:-2]:
                        threats.append(f"Subdomain impersonation: Brand '{brand}' used as subdomain prefix")

            # Anchor text mismatch
            if anchor_text:
                anchor_match = re.search(r'https?://([^\s/]+)', anchor_text)
                if anchor_match:
                    anchor_domain = anchor_match.group(1).lower()
                    if anchor_domain != domain and not domain.endswith("." + anchor_domain):
                        mismatched_anchor = True
                        threats.append(f"Visual Anchor Mismatch: Displays '{anchor_text}' but links to '{url}'")

        except Exception as e:
            domain = "invalid-url"
            threats.append(f"Malformed URL structure: {str(e)}")

        # Risk level determination
        if is_ip or is_punycode or is_typosquat or mismatched_anchor or len(threats) >= 3:
            risk_level = "CRITICAL"
        elif suspicious_tld or is_shortener or len(threats) >= 1:
            risk_level = "HIGH"
        elif threats:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "url": url,
            "anchor_text": anchor_text,
            "domain": domain,
            "risk_level": risk_level,
            "threats": threats,
            "is_ip": is_ip,
            "is_punycode": is_punycode,
            "is_typosquat": is_typosquat,
            "is_shortener": is_shortener,
            "suspicious_tld": suspicious_tld,
            "mismatched_anchor": mismatched_anchor
        }
