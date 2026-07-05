from engines.dashboard_manager import get_dashboard


def get_ai_intelligence():

    dashboard = get_dashboard()

    top_threat = max(dashboard["top_threats"], key=dashboard["top_threats"].get)

    top_brand = max(dashboard["targeted_brands"], key=dashboard["targeted_brands"].get)

    top_tld = max(dashboard["suspicious_tlds"], key=dashboard["suspicious_tlds"].get)

    high_risk = dashboard["high_risk_alerts"]

    if high_risk >= 20:
        threat_level = "🔴 HIGH"

    elif high_risk >= 10:
        threat_level = "🟠 MEDIUM"

    else:
        threat_level = "🟢 LOW"

    return {
        "threat_level": threat_level,
        "top_threat": top_threat,
        "top_brand": top_brand,
        "top_tld": top_tld,
    }
