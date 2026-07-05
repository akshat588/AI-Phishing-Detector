"""
=========================================================
TrustLens AI
UPI Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *
import random

UPI_TEMPLATES = {

    # =====================================================
    # Genuine UPI
    # =====================================================

    "legitimate": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Payment",
            "message": lambda: f"""
Payment of {pick_amount()} received successfully via {pick_upi()}.
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Transfer",
            "message": lambda: f"""
You have successfully transferred {pick_amount()} using {pick_upi()}.
"""
        }

    ],

    # =====================================================
    # Collect Request Scam
    # =====================================================

    "collect_request": [

        {
            "label": "collect_request",
            "risk": "CRITICAL",
            "category": "Collect Request",
            "message": lambda: f"""
Receive cashback of {pick_amount()}.

Approve Collect Request in {pick_upi()}.
"""
        },

        {
            "label": "collect_request",
            "risk": "CRITICAL",
            "category": "Collect Request",
            "message": lambda: f"""
Reward waiting.

Click Accept on Collect Request to receive money.
"""
        }

    ],

    # =====================================================
    # Refund Scam
    # =====================================================

    "refund_scam": [

        {
            "label": "refund_scam",
            "risk": "HIGH",
            "category": "Refund",
            "message": lambda: f"""
Refund of {pick_amount()} pending.

Approve request in {pick_upi()}.
"""
        },

        {
            "label": "refund_scam",
            "risk": "HIGH",
            "category": "Refund",
            "message": lambda: f"""
Refund failed.

Verify account:

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Cashback Scam
    # =====================================================

    "cashback_scam": [

        {
            "label": "cashback_scam",
            "risk": "HIGH",
            "category": "Cashback",
            "message": lambda: f"""
Congratulations!

Cashback of {pick_amount()} available.

Claim immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "cashback_scam",
            "risk": "HIGH",
            "category": "Reward",
            "message": lambda: f"""
Exclusive cashback offer.

Approve payment request to receive reward.
"""
        }

    ],

    # =====================================================
    # Merchant Scam
    # =====================================================

    "merchant_scam": [

        {
            "label": "merchant_scam",
            "risk": "HIGH",
            "category": "Merchant",
            "message": lambda: f"""
Merchant verification failed.

Verify payment immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "merchant_scam",
            "risk": "HIGH",
            "category": "Merchant",
            "message": lambda: f"""
Pending merchant settlement.

Click below.

https://{pick_fake_domain()}
"""
        }

    ]

}


# =====================================================
# Helper Functions
# =====================================================

def get_upi_categories():
    return list(UPI_TEMPLATES.keys())


def get_templates(category):
    return UPI_TEMPLATES.get(category, [])


def random_template(category):

    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)