"""
=========================================================
TrustLens AI
SMS Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *
import random

SMS_TEMPLATES = {

    # =====================================================
    # Legitimate SMS
    # =====================================================

    "legitimate": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Bank",
            "message": lambda: f"""
Your account has been credited with {pick_amount()}.

-{pick_bank()}
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "OTP",
            "message": lambda: f"""
OTP for your transaction is {pick_otp()}.

Do not share this OTP.

-{pick_bank()}
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "UPI",
            "message": lambda: f"""
Payment of {pick_amount()} via {pick_upi()} successful.
"""
        }

    ],

    # =====================================================
    # OTP Scam
    # =====================================================

    "otp_scam": [

        {
            "label": "otp_scam",
            "risk": "HIGH",
            "category": "OTP",
            "message": lambda: f"""
Your account will be blocked.

Verify immediately:

https://{pick_fake_domain()}
"""
        },

        {
            "label": "otp_scam",
            "risk": "HIGH",
            "category": "OTP",
            "message": lambda: f"""
OTP verification failed.

Update details now.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Banking Scam
    # =====================================================

    "banking_scam": [

        {
            "label": "banking_scam",
            "risk": "HIGH",
            "category": "Bank",
            "message": lambda: f"""
Dear Customer,

Your {pick_bank()} account has been suspended.

Verify:

https://{pick_fake_domain()}
"""
        },

        {
            "label": "banking_scam",
            "risk": "HIGH",
            "category": "Bank",
            "message": lambda: f"""
KYC expired.

Update immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Electricity Scam
    # =====================================================

    "electricity_scam": [

        {
            "label": "electricity_scam",
            "risk": "HIGH",
            "category": "Electricity",
            "message": lambda: f"""
Electricity bill unpaid.

Pay immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "electricity_scam",
            "risk": "HIGH",
            "category": "Electricity",
            "message": lambda: f"""
Connection will be disconnected tonight.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Courier Scam
    # =====================================================

    "courier_scam": [

        {
            "label": "courier_scam",
            "risk": "HIGH",
            "category": "Courier",
            "message": lambda: f"""
Your parcel is on hold.

Pay delivery charges.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "courier_scam",
            "risk": "HIGH",
            "category": "Courier",
            "message": lambda: f"""
Address verification required.

https://{pick_fake_domain()}
"""
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
            "message": lambda: f"""
Congratulations!

You have won a cashback of {pick_amount()}.

Claim now:

https://{pick_fake_domain()}
"""
        },

        {
            "label": "reward_scam",
            "risk": "HIGH",
            "category": "Reward",
            "message": lambda: f"""
Exclusive reward waiting.

Verify account now.

https://{pick_fake_domain()}
"""
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
            "message": lambda: f"""
Congratulations!

You have won ₹25 Lakhs.

Pay processing fee.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "lottery_scam",
            "risk": "CRITICAL",
            "category": "Lottery",
            "message": lambda: f"""
International Lottery Winner.

Claim immediately.

https://{pick_fake_domain()}
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
Refund of {pick_amount()} is pending.

Verify bank details.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "refund_scam",
            "risk": "HIGH",
            "category": "Refund",
            "message": lambda: f"""
Refund failed.

Update your account immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # UPI Collect Request Scam
    # =====================================================

    "upi_collect_scam": [

        {
            "label": "upi_collect_scam",
            "risk": "CRITICAL",
            "category": "UPI",
            "message": lambda: f"""
Receive cashback of {pick_amount()}.

Approve Collect Request in {pick_upi()}.
"""
        },

        {
            "label": "upi_collect_scam",
            "risk": "CRITICAL",
            "category": "UPI",
            "message": lambda: f"""
Refund waiting.

Accept Collect Request to receive money.
"""
        }

    ],

    # =====================================================
    # Investment Scam
    # =====================================================

    "investment_scam": [

        {
            "label": "investment_scam",
            "risk": "CRITICAL",
            "category": "Investment",
            "message": lambda: f"""
Invest ₹1000.

Earn ₹10000 daily.

Join now.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "investment_scam",
            "risk": "CRITICAL",
            "category": "Crypto",
            "message": lambda: f"""
Bitcoin investment opportunity.

Guaranteed 500% return.

https://{pick_fake_domain()}
"""
        }

    ]

}


# =========================================================
# Helper Functions
# =========================================================

def get_sms_categories():
    return list(SMS_TEMPLATES.keys())


def get_templates(category):
    return SMS_TEMPLATES.get(category, [])


def random_template(category):
    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)