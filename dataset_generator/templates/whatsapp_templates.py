"""
=========================================================
TrustLens AI
WhatsApp Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *
import random

WHATSAPP_TEMPLATES = {

    # =====================================================
    # Legitimate Messages
    # =====================================================

    "legitimate": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "General",
            "message": lambda: f"""
Hello,

Your payment of {pick_amount()} has been received successfully.

Thank you for using {pick_upi()}.
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Bank",
            "message": lambda: f"""
Dear Customer,

Your account statement is ready.

Visit:

https://{pick_safe_domain()}
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Reminder",
            "message": lambda: f"""
Reminder:

Your appointment is confirmed.

Thank you.
"""
        }

    ],

    # =====================================================
    # Fake Customer Care
    # =====================================================

    "fake_customer_care": [

        {
            "label": "fake_customer_care",
            "risk": "HIGH",
            "category": "Support",
            "message": lambda: f"""
Welcome to {pick_bank()} Customer Care.

Share your account number and OTP
to verify your account.
"""
        },

        {
            "label": "fake_customer_care",
            "risk": "HIGH",
            "category": "Support",
            "message": lambda: f"""
Your account has been blocked.

Contact support immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "fake_customer_care",
            "risk": "HIGH",
            "category": "Support",
            "message": lambda: f"""
Hello,

This is official customer care.

Please install our support application.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # APK Scam
    # =====================================================

    "apk_scam": [

        {
            "label": "apk_scam",
            "risk": "CRITICAL",
            "category": "APK",
            "message": lambda: f"""
Install this security update.

Download APK:

https://{pick_fake_domain()}/update.apk
"""
        },

        {
            "label": "apk_scam",
            "risk": "CRITICAL",
            "category": "APK",
            "message": lambda: f"""
Your banking application expired.

Install latest APK.

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

You won ₹25,00,000.

Claim now:

https://{pick_fake_domain()}
"""
        },

        {
            "label": "lottery_scam",
            "risk": "CRITICAL",
            "category": "Lottery",
            "message": lambda: f"""
You are today's lucky winner.

Verify immediately.

https://{pick_fake_domain()}
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
Invest ₹500 today.

Earn ₹10,000 every week.

Limited Offer.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "investment_scam",
            "risk": "CRITICAL",
            "category": "Crypto",
            "message": lambda: f"""
Guaranteed crypto profit.

Join VIP group.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Fake Job Scam
    # =====================================================

    "job_scam": [

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "Job",
            "message": lambda: f"""
Congratulations!

You have been selected as a {pick_job()} at {pick_company()}.

Salary:
{pick_salary()}

Pay registration fee of {pick_amount()}.

Contact immediately.
"""
        },

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "Job",
            "message": lambda: f"""
Immediate joining available.

Company:
{pick_company()}

Deposit security amount:

{pick_amount()}
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

You received cashback of {pick_amount()}.

Claim before expiry.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "reward_scam",
            "risk": "HIGH",
            "category": "Reward",
            "message": lambda: f"""
Festival Reward.

Verify account now.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # UPI Scam
    # =====================================================

    "upi_scam": [

        {
            "label": "upi_scam",
            "risk": "CRITICAL",
            "category": "UPI",
            "message": lambda: f"""
Refund of {pick_amount()} pending.

Approve Collect Request in {pick_upi()}.
"""
        },

        {
            "label": "upi_scam",
            "risk": "CRITICAL",
            "category": "UPI",
            "message": lambda: f"""
Cashback waiting.

Click below and approve payment request.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Telegram Scam
    # =====================================================

    "telegram_scam": [

        {
            "label": "telegram_scam",
            "risk": "CRITICAL",
            "category": "Telegram",
            "message": lambda: f"""
Join our Telegram VIP group.

Daily income ₹10,000 guaranteed.

https://t.me/vipgroup
"""
        },

        {
            "label": "telegram_scam",
            "risk": "CRITICAL",
            "category": "Telegram",
            "message": lambda: f"""
Exclusive investment signals.

Join Telegram immediately.

https://t.me/investment
"""
        }

    ]

}


# =========================================================
# Helper Functions
# =========================================================

def get_whatsapp_categories():
    return list(WHATSAPP_TEMPLATES.keys())


def get_templates(category):
    return WHATSAPP_TEMPLATES.get(category, [])


def random_template(category):

    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)