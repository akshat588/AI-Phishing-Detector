"""
=========================================================
TrustLens AI
Fake Job Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *
import random

JOB_TEMPLATES = {

    # =====================================================
    # Legitimate Job Offers
    # =====================================================

    "legitimate": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Job Offer",
            "message": lambda: f"""
Congratulations!

Your application for the position of
{pick_job()} at {pick_company()} has been shortlisted.

Interview Location:
{pick_city()}

Expected Salary:
{pick_salary()}

Regards,
HR Team
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Interview",
            "message": lambda: f"""
Dear Candidate,

Your interview with {pick_company()} has been scheduled.

Role:
{pick_job()}

Location:
{pick_city()}

Best Wishes.
"""
        }

    ],

    # =====================================================
    # Registration Fee Scam
    # =====================================================

    "registration_fee": [

        {
            "label": "job_scam",
            "risk": "CRITICAL",
            "category": "Registration Fee",
            "message": lambda: f"""
Congratulations!

You are selected at {pick_company()}.

Deposit Registration Fee:

{pick_amount()}

Joining Letter will be issued immediately.
"""
        },

        {
            "label": "job_scam",
            "risk": "CRITICAL",
            "category": "Registration Fee",
            "message": lambda: f"""
Urgent Hiring.

Security Deposit:

{pick_amount()}

Pay today to confirm your seat.
"""
        }

    ],

    # =====================================================
    # Fake HR
    # =====================================================

    "fake_hr": [

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "Fake HR",
            "message": lambda: f"""
Hello Candidate,

I am HR from {pick_company()}.

Send Aadhaar,
PAN,
Resume
and OTP for verification.
"""
        },

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "Fake HR",
            "message": lambda: f"""
Immediate Hiring.

Contact HR on Telegram.

Salary:
{pick_salary()}
"""
        }

    ],

    # =====================================================
    # Telegram Recruitment Scam
    # =====================================================

    "telegram_recruitment": [

        {
            "label": "telegram_scam",
            "risk": "CRITICAL",
            "category": "Telegram",
            "message": lambda: f"""
Join our Telegram HR Group.

Daily hiring.

Salary:
{pick_salary()}

https://t.me/fakehr
"""
        },

        {
            "label": "telegram_scam",
            "risk": "CRITICAL",
            "category": "Telegram",
            "message": lambda: f"""
Congratulations.

Your interview will be conducted on Telegram.

Join immediately.
"""
        }

    ],

    # =====================================================
    # Immediate Joining Scam
    # =====================================================

    "immediate_joining": [

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "Immediate Joining",
            "message": lambda: f"""
No Interview.

Immediate Joining.

Company:
{pick_company()}

Salary:
{pick_salary()}

Pay Documentation Fee:
{pick_amount()}
"""
        },

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "Immediate Joining",
            "message": lambda: f"""
Offer Letter Ready.

Joining Tomorrow.

Deposit:
{pick_amount()}
"""
        }

    ],

    # =====================================================
    # Work From Home Scam
    # =====================================================

    "work_from_home": [

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "WFH",
            "message": lambda: f"""
Work From Home.

Earn up to
{pick_salary()}.

Registration Fee:

{pick_amount()}
"""
        },

        {
            "label": "job_scam",
            "risk": "HIGH",
            "category": "WFH",
            "message": lambda: f"""
Simple Typing Job.

Daily Income Guaranteed.

Apply Now.
"""
        }

    ]

}


# =====================================================
# Helper Functions
# =====================================================

def get_job_categories():
    return list(JOB_TEMPLATES.keys())


def get_templates(category):
    return JOB_TEMPLATES.get(category, [])


def random_template(category):

    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)