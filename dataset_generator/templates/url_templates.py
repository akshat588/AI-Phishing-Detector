"""
=========================================================
TrustLens AI
URL Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *
import random

URL_TEMPLATES = {

    # =====================================================
    # Legitimate URLs
    # =====================================================

    "legitimate": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Bank",
            "url": lambda: f"https://{pick_safe_domain()}"
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Government",
            "url": lambda: "https://uidai.gov.in"
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "UPI",
            "url": lambda: "https://www.npci.org.in"
        }

    ],

    # =====================================================
    # Banking Phishing
    # =====================================================

    "banking_phishing": [

        {
            "label": "phishing",
            "risk": "CRITICAL",
            "category": "Bank Login",
            "url": lambda: f"https://{pick_fake_domain()}/login"
        },

        {
            "label": "phishing",
            "risk": "CRITICAL",
            "category": "Verify Account",
            "url": lambda: f"https://{pick_fake_domain()}/verify"
        },

        {
            "label": "phishing",
            "risk": "CRITICAL",
            "category": "KYC",
            "url": lambda: f"https://{pick_fake_domain()}/kyc"
        }

    ],

    # =====================================================
    # Government Scam
    # =====================================================

    "government_scam": [

        {
            "label": "government_scam",
            "risk": "HIGH",
            "category": "Income Tax",
            "url": lambda: f"https://{pick_fake_domain()}/refund"
        },

        {
            "label": "government_scam",
            "risk": "HIGH",
            "category": "Aadhaar",
            "url": lambda: f"https://{pick_fake_domain()}/aadhaar"
        },

        {
            "label": "government_scam",
            "risk": "HIGH",
            "category": "PAN",
            "url": lambda: f"https://{pick_fake_domain()}/pan"
        }

    ],

    # =====================================================
    # Courier Scam
    # =====================================================

    "courier_scam": [

        {
            "label": "courier_scam",
            "risk": "HIGH",
            "category": "Tracking",
            "url": lambda: f"https://{pick_fake_domain()}/tracking"
        },

        {
            "label": "courier_scam",
            "risk": "HIGH",
            "category": "Parcel",
            "url": lambda: f"https://{pick_fake_domain()}/parcel"
        }

    ],

    # =====================================================
    # Reward Scam
    # =====================================================

    "reward_scam": [

        {
            "label": "reward_scam",
            "risk": "HIGH",
            "category": "Reward",
            "url": lambda: f"https://{pick_fake_domain()}/reward"
        },

        {
            "label": "reward_scam",
            "risk": "HIGH",
            "category": "Cashback",
            "url": lambda: f"https://{pick_fake_domain()}/cashback"
        }

    ],

    # =====================================================
    # Lottery Scam
    # =====================================================

    "lottery_scam": [

        {
            "label": "lottery_scam",
            "risk": "CRITICAL",
            "category": "Lottery",
            "url": lambda: f"https://{pick_fake_domain()}/winner"
        },

        {
            "label": "lottery_scam",
            "risk": "CRITICAL",
            "category": "Prize",
            "url": lambda: f"https://{pick_fake_domain()}/claim"
        }

    ],

    # =====================================================
    # Crypto Scam
    # =====================================================

    "crypto_scam": [

        {
            "label": "crypto_scam",
            "risk": "CRITICAL",
            "category": "Investment",
            "url": lambda: f"https://{pick_fake_domain()}/crypto"
        },

        {
            "label": "crypto_scam",
            "risk": "CRITICAL",
            "category": "Trading",
            "url": lambda: f"https://{pick_fake_domain()}/trade"
        }

    ]

}


# =====================================================
# Helper Functions
# =====================================================

def get_url_categories():
    return list(URL_TEMPLATES.keys())


def get_templates(category):
    return URL_TEMPLATES.get(category, [])


def random_template(category):

    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)