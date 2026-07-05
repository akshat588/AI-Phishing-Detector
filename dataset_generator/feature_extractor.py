"""
=========================================================
TrustLens AI
Feature Extractor

Version : 1.0
=========================================================
"""

import re


class FeatureExtractor:

    def __init__(self):

        self.bank_keywords = [
            "bank",
            "sbi",
            "hdfc",
            "icici",
            "axis",
            "kotak",
            "pnb",
            "canara",
            "bob",
        ]

        self.urgency_keywords = [
            "urgent",
            "immediately",
            "verify",
            "expire",
            "blocked",
            "suspended",
            "today",
            "alert",
            "warning",
            "deadline",
        ]

        self.kyc_keywords = ["kyc", "aadhaar", "pan", "digilocker"]

        self.reward_keywords = [
            "reward",
            "cashback",
            "lottery",
            "winner",
            "gift",
            "bonus",
            "prize",
        ]

        self.job_keywords = [
            "job",
            "interview",
            "salary",
            "joining",
            "recruitment",
            "vacancy",
            "resume",
            "hr",
        ]

        self.social_keywords = [
            "otp",
            "verify",
            "click",
            "login",
            "password",
            "account",
            "security",
        ]

    # =====================================================

    def contains_url(self, text):

        return int(bool(re.search(r"(https?://|www\.)", text.lower())))

    # =====================================================

    def contains_phone(self, text):

        return int(bool(re.search(r"\b[6-9]\d{9}\b", text)))

    # =====================================================

    def contains_email(self, text):

        return int(
            bool(re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
        )

    # =====================================================

    def contains_upi(self, text):

        return int("@upi" in text.lower() or "upi" in text.lower())

    # =====================================================

    def contains_money(self, text):

        return int(bool(re.search(r"(₹|rs\.?|inr|\d+\s*lpa)", text.lower())))

    # =====================================================

    def contains_otp(self, text):

        return int("otp" in text.lower())

    # =====================================================

    def contains_urgency(self, text):

        return int(any(k in text.lower() for k in self.urgency_keywords))

    # =====================================================

    def contains_kyc(self, text):

        return int(any(k in text.lower() for k in self.kyc_keywords))

    # =====================================================

    def contains_reward(self, text):

        return int(any(k in text.lower() for k in self.reward_keywords))

    # =====================================================

    def contains_social_engineering(self, text):

        return int(any(k in text.lower() for k in self.social_keywords))

    # =====================================================

    def contains_qr(self, text):

        return int("qr" in text.lower())

    # =====================================================

    def contains_job_keywords(self, text):

        return int(any(k in text.lower() for k in self.job_keywords))

    # =====================================================

    def contains_salary(self, text):

        return int(bool(re.search(r"(salary|lpa|month)", text.lower())))

    # =====================================================

    def contains_registration_fee(self, text):

        return int(
            "registration fee" in text.lower() or "security deposit" in text.lower()
        )

    # =====================================================

    def contains_bank_name(self, text):

        return int(any(b in text.lower() for b in self.bank_keywords))

    # =====================================================

    def contains_deadline(self, text):

        keywords = ["today", "within", "24 hours", "deadline", "expires"]

        return int(any(k in text.lower() for k in keywords))

    # =====================================================

    def contains_telegram(self, text):

        return int("telegram" in text.lower() or "t.me" in text.lower())

    # =====================================================

    def contains_apk_link(self, text):

        return int(".apk" in text.lower())

    # =====================================================

    def contains_crypto(self, text):

        keywords = ["bitcoin", "crypto", "trading", "investment"]

        return int(any(k in text.lower() for k in keywords))

    # =====================================================

    def contains_refund(self, text):

        return int("refund" in text.lower())

    # =====================================================

    def contains_collect_request(self, text):

        return int("collect request" in text.lower())

    # =====================================================

    def trust_score(self, row):

        score = 100

        deductions = [
            row["contains_url"] * 10,
            row["contains_urgency"] * 15,
            row["contains_reward"] * 15,
            row["contains_social_engineering"] * 15,
            row["contains_crypto"] * 10,
            row["contains_registration_fee"] * 15,
            row["contains_collect_request"] * 20,
        ]

        score -= sum(deductions)

        return max(score, 0)

    # =====================================================

    def risk_level(self, score):

        if score >= 80:
            return "SAFE"

        elif score >= 60:
            return "LOW"

        elif score >= 40:
            return "MEDIUM"

        elif score >= 20:
            return "HIGH"

        return "CRITICAL"

    # =====================================================

    def extract(self, dataframe):

        text_column = None

        for col in ["message", "content", "url"]:

            if col in dataframe.columns:
                text_column = col
                break

        if text_column is None:
            return dataframe

        dataframe["contains_url"] = dataframe[text_column].apply(self.contains_url)
        dataframe["contains_phone"] = dataframe[text_column].apply(self.contains_phone)
        dataframe["contains_email"] = dataframe[text_column].apply(self.contains_email)
        dataframe["contains_upi"] = dataframe[text_column].apply(self.contains_upi)
        dataframe["contains_money"] = dataframe[text_column].apply(self.contains_money)
        dataframe["contains_otp"] = dataframe[text_column].apply(self.contains_otp)
        dataframe["contains_urgency"] = dataframe[text_column].apply(
            self.contains_urgency
        )
        dataframe["contains_kyc"] = dataframe[text_column].apply(self.contains_kyc)
        dataframe["contains_reward"] = dataframe[text_column].apply(
            self.contains_reward
        )
        dataframe["contains_social_engineering"] = dataframe[text_column].apply(
            self.contains_social_engineering
        )
        dataframe["contains_qr"] = dataframe[text_column].apply(self.contains_qr)
        dataframe["contains_job_keywords"] = dataframe[text_column].apply(
            self.contains_job_keywords
        )
        dataframe["contains_salary"] = dataframe[text_column].apply(
            self.contains_salary
        )
        dataframe["contains_registration_fee"] = dataframe[text_column].apply(
            self.contains_registration_fee
        )
        dataframe["contains_bank_name"] = dataframe[text_column].apply(
            self.contains_bank_name
        )
        dataframe["contains_deadline"] = dataframe[text_column].apply(
            self.contains_deadline
        )
        dataframe["contains_telegram"] = dataframe[text_column].apply(
            self.contains_telegram
        )
        dataframe["contains_apk_link"] = dataframe[text_column].apply(
            self.contains_apk_link
        )
        dataframe["contains_crypto"] = dataframe[text_column].apply(
            self.contains_crypto
        )
        dataframe["contains_refund"] = dataframe[text_column].apply(
            self.contains_refund
        )
        dataframe["contains_collect_request"] = dataframe[text_column].apply(
            self.contains_collect_request
        )

        dataframe["trust_score"] = dataframe.apply(self.trust_score, axis=1)

        dataframe["risk_level"] = dataframe["trust_score"].apply(self.risk_level)

        return dataframe


# =====================================================
# Singleton
# =====================================================

feature_extractor = FeatureExtractor()
