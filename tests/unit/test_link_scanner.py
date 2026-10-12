from link_scanner import LinkScanner, levenshtein_distance


def test_levenshtein_distance_handles_equal_empty_and_different_strings():
    assert levenshtein_distance("phish", "phish") == 0
    assert levenshtein_distance("", "mail") == 4
    assert levenshtein_distance("kitten", "sitting") == 3


def test_scan_extracts_html_markdown_and_plain_urls():
    scanner = LinkScanner()

    html_link = scanner.scan(
        '<a href="https://example.com/account">Open account</a>'
    )[0]
    markdown_link = scanner.scan("[account](https://example.com/account)")[0]
    plain_link = scanner.scan("Visit https://example.com/account")[0]

    assert html_link["url"] == "https://example.com/account"
    assert html_link["anchor_text"] == "Open account"
    assert markdown_link["url"] == "https://example.com/account"
    assert plain_link["url"] == "https://example.com/account"


def test_scan_flags_typosquatting_suspicious_tld_and_anchor_mismatch():
    link = LinkScanner().scan(
        '<a href="http://micros0ft.xyz/login">'
        "https://microsoft.com</a>"
    )[0]

    assert link["is_typosquat"] is True
    assert link["suspicious_tld"] is True
    assert link["mismatched_anchor"] is True
    assert link["risk_level"] == "CRITICAL"


def test_scan_leaves_a_legitimate_domain_low_risk():
    link = LinkScanner().scan("Visit https://www.example.com/help")[0]

    assert link["domain"] == "www.example.com"
    assert link["risk_level"] == "LOW"
    assert link["threats"] == []
