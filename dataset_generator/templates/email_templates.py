"""
=========================================================
TrustLens AI
Email Dataset Templates

Version : 1.0
=========================================================
"""

from .common import *

EMAIL_TEMPLATES = {

    # =====================================================
    # Legitimate Emails
    # =====================================================

    "legitimate": [

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "General",
            "subject": lambda: f"Welcome to {pick_bank()}",
            "message": lambda: f"""
Dear Customer,

Welcome to {pick_bank()}.

Your account has been successfully activated.

You can now access Internet Banking and Mobile Banking services.

Thank you for choosing {pick_bank()}.

Regards,
Customer Care
{pick_bank()}
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Statement",
            "subject": lambda: "Monthly Account Statement",
            "message": lambda: f"""
Dear Customer,

Your monthly account statement is ready.

Please login using the official portal:

https://{pick_safe_domain()}

Thank you.

{pick_bank()}
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Transaction",
            "subject": lambda: "Transaction Successful",
            "message": lambda: f"""
Dear Customer,

Your payment of {pick_amount()} has been processed successfully.

Reference Bank:
{pick_bank()}

No action is required.

Thank you.
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "UPI",
            "subject": lambda: "Payment Confirmation",
            "message": lambda: f"""
Dear Customer,

Your UPI payment via {pick_upi()} of
{pick_amount()} has been completed.

Thank you.

{pick_upi()}
"""
        },

        {
            "label": "legitimate",
            "risk": "SAFE",
            "category": "Security",
            "subject": lambda: "Security Tips",
            "message": lambda: f"""
Dear Customer,

Never share your OTP,
PIN,
password
or CVV with anyone.

{pick_bank()} never asks for confidential
information over email.

Stay Safe.
"""
        }

    ],

    # =====================================================
    # Banking Phishing
    # =====================================================

    "banking_phishing": [

        {
            "label": "phishing",
            "risk": "HIGH",
            "category": "Banking",
            "subject": lambda: f"URGENT: {pick_bank()} Account Suspended",
            "message": lambda: f"""
Dear Customer,

Your {pick_bank()} account has been
temporarily suspended due to unusual activity.

Verify immediately:

https://{pick_fake_domain()}

Failure to verify within 24 hours will
permanently block your account.
"""
        },

        {
            "label": "phishing",
            "risk": "HIGH",
            "category": "Banking",
            "subject": lambda: "Debit Card Blocked",
            "message": lambda: f"""
Dear Customer,

Your Debit Card has been blocked.

Update your banking information now.

https://{pick_fake_domain()}

Ignore this message and your account
will remain inaccessible.
"""
        },

        {
            "label": "phishing",
            "risk": "HIGH",
            "category": "Banking",
            "subject": lambda: "Immediate Verification Required",
            "message": lambda: f"""
Security Alert.

We detected suspicious login attempts.

Verify your account:

https://{pick_fake_domain()}

Failure may result in permanent suspension.
"""
        },

        {
            "label": "phishing",
            "risk": "HIGH",
            "category": "Banking",
            "subject": lambda: "Customer Verification Pending",
            "message": lambda: f"""
Dear User,

Your customer verification is incomplete.

Complete verification immediately:

https://{pick_fake_domain()}

Your account will otherwise be frozen.
"""
        },

        {
            "label": "phishing",
            "risk": "HIGH",
            "category": "Banking",
            "subject": lambda: "Net Banking Disabled",
            "message": lambda: f"""
Dear Customer,

Net Banking has been disabled.

Restore access immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Credential Theft
    # =====================================================

    "credential_theft": [

        {
            "label": "credential_theft",
            "risk": "CRITICAL",
            "category": "Credential Theft",
            "subject": lambda: "Password Expiring Today",
            "message": lambda: f"""
Your banking password expires today.

Reset Password:

https://{pick_fake_domain()}

Failure to reset will lock your account.
"""
        },

        {
            "label": "credential_theft",
            "risk": "CRITICAL",
            "category": "Credential Theft",
            "subject": lambda: "Microsoft Login Alert",
            "message": lambda: f"""
Someone attempted to access your account.

Verify ownership immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "credential_theft",
            "risk": "CRITICAL",
            "category": "Credential Theft",
            "subject": lambda: "Mailbox Storage Full",
            "message": lambda: f"""
Your mailbox has exceeded storage.

Login to continue receiving emails.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "credential_theft",
            "risk": "CRITICAL",
            "category": "Credential Theft",
            "subject": lambda: "Identity Verification Required",
            "message": lambda: f"""
We could not verify your identity.

Confirm your login credentials now.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # KYC Scam
    # =====================================================

    "kyc_scam": [

        {
            "label": "kyc_scam",
            "risk": "HIGH",
            "category": "KYC",
            "subject": lambda: "Complete KYC Today",
            "message": lambda: f"""
Dear Customer,

Your KYC has expired.

Complete verification now.

https://{pick_fake_domain()}

Ignoring this notice will freeze
your account.
"""
        },

        {
            "label": "kyc_scam",
            "risk": "HIGH",
            "category": "PAN",
            "subject": lambda: "PAN Verification Required",
            "message": lambda: f"""
Dear User,

Your PAN verification is pending.

Submit details immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Aadhaar Scam
    # =====================================================

    "aadhaar_scam": [

        {
            "label": "aadhaar_scam",
            "risk": "HIGH",
            "category": "Aadhaar",
            "subject": lambda: "Aadhaar Suspension Notice",
            "message": lambda: f"""
Dear Citizen,

Your Aadhaar has been temporarily suspended.

Verify immediately.

https://{pick_fake_domain()}

UIDAI Team
"""
        },

        {
            "label": "aadhaar_scam",
            "risk": "HIGH",
            "category": "Aadhaar",
            "subject": lambda: "Aadhaar KYC Failed",
            "message": lambda: f"""
Your Aadhaar verification failed.

Complete KYC within 12 hours.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "aadhaar_scam",
            "risk": "HIGH",
            "category": "UIDAI",
            "subject": lambda: "Update Aadhaar Information",
            "message": lambda: f"""
Dear User,

Update your Aadhaar details immediately.

https://{pick_fake_domain()}

Failure may deactivate your Aadhaar.
"""
        }

    ],

    # =====================================================
    # DigiLocker Scam
    # =====================================================

    "digilocker_scam": [

        {
            "label": "digilocker_scam",
            "risk": "HIGH",
            "category": "DigiLocker",
            "subject": lambda: "DigiLocker Verification Required",
            "message": lambda: f"""
Dear User,

Your DigiLocker account needs verification.

Complete verification now.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "digilocker_scam",
            "risk": "HIGH",
            "category": "Documents",
            "subject": lambda: "Documents Locked",
            "message": lambda: f"""
Your government documents have been locked.

Unlock immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Income Tax Scam
    # =====================================================

    "income_tax_scam": [

        {
            "label": "income_tax_scam",
            "risk": "HIGH",
            "category": "Income Tax",
            "subject": lambda: "Income Tax Refund Approved",
            "message": lambda: f"""
Congratulations.

Your refund of {pick_amount()} is ready.

Claim immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "income_tax_scam",
            "risk": "HIGH",
            "category": "Income Tax",
            "subject": lambda: "IT Department Notice",
            "message": lambda: f"""
A notice has been issued against your PAN.

View immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "income_tax_scam",
            "risk": "HIGH",
            "category": "Refund",
            "subject": lambda: "Refund Pending",
            "message": lambda: f"""
Refund processing failed.

Verify your bank account.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Electricity Bill Scam
    # =====================================================

    "electricity_bill_scam": [

        {
            "label": "electricity_bill_scam",
            "risk": "HIGH",
            "category": "Electricity",
            "subject": lambda: "Electricity Connection Will Be Disconnected",
            "message": lambda: f"""
Dear Consumer,

Your electricity bill remains unpaid.

Pay immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "electricity_bill_scam",
            "risk": "HIGH",
            "category": "Electricity",
            "subject": lambda: "Final Payment Reminder",
            "message": lambda: f"""
Immediate action required.

Failure to pay today will disconnect
your electricity connection.

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
            "subject": lambda: "Parcel Delivery Failed",
            "message": lambda: f"""
Your parcel delivery failed.

Reschedule delivery.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "courier_scam",
            "risk": "HIGH",
            "category": "Courier",
            "subject": lambda: "Package Held At Warehouse",
            "message": lambda: f"""
Your package has been held.

Pay customs charges now.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "courier_scam",
            "risk": "HIGH",
            "category": "Courier",
            "subject": lambda: "Courier Address Verification",
            "message": lambda: f"""
Verify your address.

https://{pick_fake_domain()}

Failure will return your parcel.
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
            "subject": lambda: "Congratulations! Reward Won",
            "message": lambda: f"""
You have won a cashback of
{pick_amount()}.

Claim reward immediately.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "reward_scam",
            "risk": "HIGH",
            "category": "Cashback",
            "subject": lambda: "Exclusive Cashback",
            "message": lambda: f"""
Limited Time Offer.

Claim cashback before it expires.

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
            "subject": lambda: "You Won ₹25,00,000",
            "message": lambda: f"""
Congratulations.

You have won ₹25,00,000.

Pay processing charges.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "lottery_scam",
            "risk": "CRITICAL",
            "category": "Prize",
            "subject": lambda: "International Lottery Winner",
            "message": lambda: f"""
Claim your international prize.

Verification Required.

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
            "subject": lambda: "Refund Initiated",
            "message": lambda: f"""
Refund of {pick_amount()} is waiting.

Complete verification.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "refund_scam",
            "risk": "HIGH",
            "category": "Refund",
            "subject": lambda: "Bank Refund Failed",
            "message": lambda: f"""
Refund processing failed.

Update account immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Business Email Compromise (BEC)
    # =====================================================

    "business_email_compromise": [

        {
            "label": "business_email_compromise",
            "risk": "CRITICAL",
            "category": "BEC",
            "subject": lambda: "URGENT Payment Required",
            "message": lambda: f"""
Dear Finance Team,

Please transfer {pick_amount()} to the new vendor account immediately.

This payment is confidential.

Regards,
CEO
"""
        },

        {
            "label": "business_email_compromise",
            "risk": "CRITICAL",
            "category": "BEC",
            "subject": lambda: "Invoice Payment",
            "message": lambda: f"""
Please clear the attached invoice today.

Delay may affect the client relationship.

Transfer Amount:
{pick_amount()}
"""
        },

        {
            "label": "business_email_compromise",
            "risk": "CRITICAL",
            "category": "BEC",
            "subject": lambda: "Confidential Transfer",
            "message": lambda: f"""
I am in an important meeting.

Transfer {pick_amount()} immediately.

Do not discuss this with anyone.

CEO
"""
        }

    ],

    # =====================================================
    # Government Scam
    # =====================================================

    "government_scam": [

        {
            "label": "government_scam",
            "risk": "HIGH",
            "category": "Government",
            "subject": lambda: "Government Subsidy Approved",
            "message": lambda: f"""
Dear Citizen,

Government subsidy has been approved.

Claim benefits now.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "government_scam",
            "risk": "HIGH",
            "category": "Government",
            "subject": lambda: "NPCI Verification Required",
            "message": lambda: f"""
NPCI requires immediate verification.

Verify here:

https://{pick_fake_domain()}
"""
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
            "subject": lambda: "Double Your Investment",
            "message": lambda: f"""
Earn guaranteed returns.

Invest today.

Limited offer.

https://{pick_fake_domain()}
"""
        },

        {
            "label": "crypto_scam",
            "risk": "CRITICAL",
            "category": "Crypto",
            "subject": lambda: "Bitcoin Giveaway",
            "message": lambda: f"""
Congratulations.

Receive free Bitcoin.

Register immediately.

https://{pick_fake_domain()}
"""
        }

    ],

    # =====================================================
    # Employment Scam
    # =====================================================

    "employment_scam": [

        {
            "label": "employment_scam",
            "risk": "HIGH",
            "category": "Job",
            "subject": lambda: f"Immediate Hiring at {pick_company()}",
            "message": lambda: f"""
Congratulations.

You have been shortlisted.

Deposit {pick_amount()} as registration fee.

Interview tomorrow.
"""
        },

        {
            "label": "employment_scam",
            "risk": "HIGH",
            "category": "Job",
            "subject": lambda: "Work From Home Opportunity",
            "message": lambda: f"""
Earn up to {pick_salary()}.

Registration Fee:

{pick_amount()}

Limited vacancies.
"""
        }

    ]

}


# =========================================================
# Helper Functions
# =========================================================

def get_email_categories():
    """
    Returns all available email categories.
    """
    return list(EMAIL_TEMPLATES.keys())


def get_templates(category):
    """
    Returns templates for a given category.
    """
    return EMAIL_TEMPLATES.get(category, [])


def random_template(category):
    """
    Returns one random template.
    """
    templates = get_templates(category)

    if not templates:
        return None

    return random.choice(templates)