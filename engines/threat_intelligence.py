from engines.url_analyzer import analyze_url
from engines.fake_website_detector import analyze_fake_website
from engines.malware_link_detector import analyze_malware_link
from engines.domain_intelligence import analyze_domain
from engines.ssl_intelligence import analyze_ssl
from engines.reputation_engine import check_reputation


def _merge_lists(*lists):
    merged = []

    for lst in lists:
        if lst:
            merged.extend(lst)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(merged))


def _merge_dicts(*dicts):
    merged = {}

    for d in dicts:
        if d:
            merged.update(d)

    return merged


def _calculate_overall_score(scores):

    valid_scores = [s for s in scores if isinstance(s, (int, float))]

    if not valid_scores:
        return 0

    # Weighted average
    weights = {
        "url": 0.25,
        "fake": 0.20,
        "malware": 0.20,
        "domain": 0.15,
        "ssl": 0.10,
        "reputation": 0.10,
    }

    overall = (
        scores[0] * weights["url"]
        + scores[1] * weights["fake"]
        + scores[2] * weights["malware"]
        + scores[3] * weights["domain"]
        + scores[4] * weights["ssl"]
        + scores[5] * weights["reputation"]
    )

    return round(min(overall, 100), 2)


def analyze_threat_intelligence(url):
    """
    Unified Threat Intelligence Engine.

    Combines all URL-related security modules.
    """

    # -------------------------------
    # URL Analyzer
    # -------------------------------

    url_score, url_findings = analyze_url(url)

    # -------------------------------
    # Fake Website
    # -------------------------------

    fake = analyze_fake_website(url)

    # -------------------------------
    # Malware
    # -------------------------------

    malware = analyze_malware_link(url)

    # -------------------------------
    # Domain
    # -------------------------------

    domain = analyze_domain(url)

    # -------------------------------
    # SSL
    # -------------------------------

    ssl = analyze_ssl(url)

    # -------------------------------
    # Reputation
    # -------------------------------

    reputation = check_reputation(url)

    # -------------------------------
    # Overall Score
    # -------------------------------

    overall_score = _calculate_overall_score(
        [
            url_score,
            fake["score"],
            malware["score"],
            domain["score"],
            ssl["score"],
            reputation["score"],
        ]
    )

    # -------------------------------
    # Combined Findings
    # -------------------------------

    findings = _merge_lists(
        url_findings,
        fake["findings"],
        malware["findings"],
        domain["findings"],
        ssl["findings"],
        reputation["findings"],
    )

    # -------------------------------
    # Combined Recommendations
    # -------------------------------

    recommendations = _merge_lists(
        fake["recommendations"],
        malware["recommendations"],
        domain["recommendations"],
        ssl["recommendations"],
        reputation["recommendations"],
    )

    # -------------------------------
    # Threat DNA
    # -------------------------------

    threat_dna = _merge_dicts(
        fake["threat_dna"],
        malware["threat_dna"],
        domain["threat_dna"],
        ssl["threat_dna"],
    )

    # -------------------------------
    # Threat Level
    # -------------------------------

    if overall_score >= 90:
        risk_level = "CRITICAL"

    elif overall_score >= 70:
        risk_level = "HIGH"

    elif overall_score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "url_score": url_score,
        "fake_site_score": fake["score"],
        "malware_score": malware["score"],
        "domain_score": domain["score"],
        "ssl_score": ssl["score"],
        "reputation_score": reputation["score"],
        "reputation": reputation["reputation"],
        "findings": findings,
        "recommendations": recommendations,
        "threat_dna": threat_dna,
    }
