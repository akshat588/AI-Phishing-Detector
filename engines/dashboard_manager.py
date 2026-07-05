import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_FILE = os.path.join(BASE_DIR, "data", "dashboard_data.json")


def load_dashboard():

    if not os.path.exists(DATA_FILE):

        return {
            "total_scans": 0,
            "threats_detected": 0,
            "high_risk_alerts": 0,
            "safe_analyses": 0,
            "recent_activity": [],
        }

    with open(DATA_FILE, "r") as f:

        return json.load(f)


def save_dashboard(data):

    with open(DATA_FILE, "w") as f:

        json.dump(data, f, indent=4)


def update_dashboard(analyzer, score, severity):

    data = load_dashboard()

    data["total_scans"] += 1

    if score >= 35:
        data["threats_detected"] += 1
    else:
        data["safe_analyses"] += 1

    if score >= 65:
        data["high_risk_alerts"] += 1

    timestamp = datetime.now().strftime("%I:%M %p")

    activity = {"time": timestamp, "message": f"{analyzer} detected {severity}"}

    data["recent_activity"].insert(0, activity)

    data["recent_activity"] = data["recent_activity"][:10]

    save_dashboard(data)


def get_dashboard():

    return load_dashboard()


def add_hunting_record(record):

    data = load_dashboard()

    if "hunting_data" not in data:

        data["hunting_data"] = []

    data["hunting_data"].insert(0, record)

    data["hunting_data"] = data["hunting_data"][:100]

    save_dashboard(data)

    print("Threat Hunting Record Saved:", record)


def update_threat_type(threat_name):

    data = load_dashboard()

    if threat_name in data["top_threats"]:
        data["top_threats"][threat_name] += 1

    save_dashboard(data)


def update_brand(brand_name):

    data = load_dashboard()

    if brand_name in data["targeted_brands"]:
        data["targeted_brands"][brand_name] += 1

    save_dashboard(data)


def update_tld(tld):

    data = load_dashboard()

    if tld in data["suspicious_tlds"]:
        data["suspicious_tlds"][tld] += 1

    save_dashboard(data)
