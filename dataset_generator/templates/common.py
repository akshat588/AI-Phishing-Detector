"""
=========================================================
TrustLens AI
AI-Assisted Dataset Generation Pipeline

Common reusable values for dataset generation.

These values are imported by all template modules.

Version : 1.0
=========================================================
"""

import random

# =========================================================
# Indian Banks
# =========================================================

BANKS = [
    "State Bank of India",
    "HDFC Bank",
    "ICICI Bank",
    "Axis Bank",
    "Punjab National Bank",
    "Bank of Baroda",
    "Canara Bank",
    "Union Bank of India",
    "Kotak Mahindra Bank",
    "IndusInd Bank",
    "Yes Bank",
    "IDFC FIRST Bank",
    "AU Small Finance Bank"
]

# =========================================================
# UPI Applications
# =========================================================

UPI_APPS = [
    "PhonePe",
    "Google Pay",
    "Paytm",
    "BHIM",
    "Amazon Pay",
    "CRED",
    "WhatsApp Pay",
    "Freecharge",
    "Mobikwik"
]

# =========================================================
# Government Services
# =========================================================

GOVERNMENT_SERVICES = [
    "Aadhaar",
    "PAN",
    "Income Tax",
    "GST",
    "DigiLocker",
    "FASTag",
    "NPCI",
    "EPFO",
    "Passport Seva",
    "UIDAI"
]

# =========================================================
# Telecom Operators
# =========================================================

TELECOM_OPERATORS = [
    "Jio",
    "Airtel",
    "Vi",
    "BSNL"
]

# =========================================================
# Courier Companies
# =========================================================

COURIER_COMPANIES = [
    "India Post",
    "Blue Dart",
    "DTDC",
    "Delhivery",
    "XpressBees",
    "Ekart",
    "Ecom Express"
]

# =========================================================
# E-commerce
# =========================================================

ECOMMERCE = [
    "Amazon",
    "Flipkart",
    "Meesho",
    "Myntra",
    "Ajio"
]

# =========================================================
# Job Portals
# =========================================================

JOB_PORTALS = [
    "LinkedIn",
    "Naukri",
    "Indeed",
    "Foundit",
    "Internshala",
    "Apna"
]

# =========================================================
# Companies
# =========================================================

COMPANIES = [
    "Infosys",
    "TCS",
    "Wipro",
    "Tech Mahindra",
    "HCL",
    "Capgemini",
    "Google India",
    "Microsoft India",
    "Amazon India",
    "Reliance Jio"
]

# =========================================================
# Cities
# =========================================================

CITIES = [
    "Delhi",
    "Mumbai",
    "Pune",
    "Bengaluru",
    "Hyderabad",
    "Chennai",
    "Kolkata",
    "Jaipur",
    "Lucknow",
    "Chandigarh",
    "Noida",
    "Gurugram"
]

# =========================================================
# Fake Domains
# =========================================================

FAKE_DOMAINS = [
    "secure-login-now.in",
    "verify-bank-now.com",
    "upi-security-alert.in",
    "wallet-verify.net",
    "account-safe.co",
    "kyc-update.live",
    "reward-center.xyz"
]

# =========================================================
# Legitimate Domains
# =========================================================

SAFE_DOMAINS = [
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "uidai.gov.in",
    "npci.org.in",
    "incometax.gov.in",
    "digilocker.gov.in"
]

# =========================================================
# Salary Ranges
# =========================================================

SALARIES = [
    "₹25,000/month",
    "₹40,000/month",
    "₹60,000/month",
    "₹8 LPA",
    "₹12 LPA",
    "₹18 LPA",
    "₹25 LPA"
]

# =========================================================
# Amounts
# =========================================================

AMOUNTS = [
    "₹499",
    "₹999",
    "₹1,500",
    "₹2,999",
    "₹5,000",
    "₹10,000",
    "₹25,000",
    "₹50,000"
]

# =========================================================
# OTP Samples
# =========================================================

OTP_VALUES = [
    "245871",
    "982144",
    "443211",
    "674892",
    "120985",
    "551209"
]

# =========================================================
# Job Roles
# =========================================================

JOB_ROLES = [
    "Software Engineer",
    "Cyber Security Analyst",
    "SOC Analyst",
    "Python Developer",
    "Data Analyst",
    "Cloud Engineer",
    "AI Engineer",
    "Network Engineer"
]

# =========================================================
# Helper Functions
# =========================================================

def pick_bank():
    return random.choice(BANKS)

def pick_upi():
    return random.choice(UPI_APPS)

def pick_company():
    return random.choice(COMPANIES)

def pick_city():
    return random.choice(CITIES)

def pick_salary():
    return random.choice(SALARIES)

def pick_amount():
    return random.choice(AMOUNTS)

def pick_fake_domain():
    return random.choice(FAKE_DOMAINS)

def pick_safe_domain():
    return random.choice(SAFE_DOMAINS)

def pick_job():
    return random.choice(JOB_ROLES)

def pick_otp():
    return random.choice(OTP_VALUES)