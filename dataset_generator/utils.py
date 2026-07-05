"""
=========================================================
TrustLens AI
Dataset Generator Utilities

Version : 1.0
=========================================================
"""

import os
import random
import string
from datetime import datetime

# =====================================================
# Random Generators
# =====================================================


def random_digits(length=6):
    return "".join(random.choices(string.digits, k=length))


def random_phone():
    return random.choice(
        ["98", "97", "96", "95", "94", "93", "92", "91"]
    ) + random_digits(8)


def random_email():
    names = [
        "rahul",
        "amit",
        "akash",
        "rohit",
        "priya",
        "neha",
        "simran",
        "vijay",
        "arjun",
        "ankit",
    ]

    domains = ["gmail.com", "outlook.com", "yahoo.com", "proton.me"]

    return f"{random.choice(names)}{random.randint(10,999)}@{random.choice(domains)}"


def random_otp():
    return random_digits(6)


def random_upi():

    names = ["rahul", "amit", "akash", "rohit", "neha"]

    providers = ["upi", "ybl", "okaxis", "okhdfcbank", "ibl"]

    return f"{random.choice(names)}{random.randint(100,999)}@{random.choice(providers)}"


def random_amount(minimum=100, maximum=50000):

    return random.randint(minimum, maximum)


# =====================================================
# Date & Time
# =====================================================


def timestamp():

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def filename_timestamp():

    return datetime.now().strftime("%Y%m%d_%H%M%S")


# =====================================================
# Directory
# =====================================================


def ensure_directory(path):

    os.makedirs(path, exist_ok=True)

    return path


# =====================================================
# Text Cleaning
# =====================================================


def clean_text(text):

    if text is None:
        return ""

    text = str(text)

    text = text.replace("\n", " ")

    text = text.replace("\t", " ")

    text = " ".join(text.split())

    return text.strip()


# =====================================================
# Safe Filename
# =====================================================


def safe_filename(name):

    invalid = '<>:"/\\|?*'

    for ch in invalid:

        name = name.replace(ch, "_")

    return name


# =====================================================
# Dataset Information
# =====================================================


def dataset_info(dataframe):

    info = {
        "records": len(dataframe),
        "columns": list(dataframe.columns),
        "generated_at": timestamp(),
    }

    if "label" in dataframe.columns:

        info["labels"] = dataframe["label"].value_counts().to_dict()

    if "risk" in dataframe.columns:

        info["risk"] = dataframe["risk"].value_counts().to_dict()

    return info


# =====================================================
# Random Sample
# =====================================================


def random_sample(items):

    if not items:
        return None

    return random.choice(items)


# =====================================================
# Percentage
# =====================================================


def percentage(value, total):

    if total == 0:
        return 0

    return round((value / total) * 100, 2)


# =====================================================
# Dataset Preview
# =====================================================


def preview(dataframe, rows=10):

    return dataframe.head(rows)


# =====================================================
# File Exists
# =====================================================


def exists(path):

    return os.path.exists(path)


# =====================================================
# Singleton Constants
# =====================================================

SUPPORTED_DATASETS = ["email", "sms", "whatsapp", "upi", "qr", "job", "url"]

SUPPORTED_EXPORTS = ["csv", "json", "xlsx"]
