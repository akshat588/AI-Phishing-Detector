"""
=========================================================
TrustLens AI
QR Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *
import random

QR_TEMPLATES = {

    # =====================================================
    # Safe QR Codes
    # =====================================================

    "safe_qr": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "UPI Payment",
            "content": lambda: f"upi://pay?pn={pick_upi()}&am={pick_amount()}"
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Website",
            "content": lambda: f"https://{pick_safe_domain()}"
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "WiFi",
            "content": lambda: "WIFI:T:WPA;S:TrustLens;P:TrustLens@123;;"
        }

    ],

    # =====================================================
    # Malicious QR
    # =====================================================

    "malicious_qr": [

        {
            "label": "malicious",
            "risk": "CRITICAL",
            "category": "Credential Theft",
            "content": lambda: f"https://{pick_fake_domain()}"
        },

        {
            "label": "malicious",
            "risk": "CRITICAL",
            "category": "Bank Login",
            "content": lambda: f"https://{pick_fake_domain()}/login"
        }

    ],

    # =====================================================
    # UPI Scam QR
    # =====================================================

    "upi_qr": [

        {
            "label": "upi_scam",
            "risk": "CRITICAL",
            "category": "Collect Request",
            "content": lambda: f"upi://pay?pn=Cashback&am={pick_amount()}"
        },

        {
            "label": "upi_scam",
            "risk": "CRITICAL",
            "category": "Refund",
            "content": lambda: f"upi://pay?pn=Refund&am={pick_amount()}"
        }

    ],

    # =====================================================
    # URL QR
    # =====================================================

    "url_qr": [

        {
            "label": "url_qr",
            "risk": "HIGH",
            "category": "Website",
            "content": lambda: f"https://{pick_fake_domain()}"
        },

        {
            "label": "url_qr",
            "risk": "HIGH",
            "category": "Lottery",
            "content": lambda: f"https://{pick_fake_domain()}/reward"
        }

    ],

    # =====================================================
    # WiFi QR Scam
    # =====================================================

    "wifi_qr": [

        {
            "label": "wifi_qr",
            "risk": "MEDIUM",
            "category": "WiFi",
            "content": lambda: "WIFI:T:WPA;S:Free_Public_WiFi;P:12345678;;"
        },

        {
            "label": "wifi_qr",
            "risk": "MEDIUM",
            "category": "WiFi",
            "content": lambda: "WIFI:T:WPA2;S:Airport_Free;P:password123;;"
        }

    ]

}


# =====================================================
# Helper Functions
# =====================================================

def get_qr_categories():
    return list(QR_TEMPLATES.keys())


def get_templates(category):
    return QR_TEMPLATES.get(category, [])


def random_template(category):

    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)