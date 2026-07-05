"""
=========================================================
TrustLens AI
Dataset Validator

Version : 1.0
=========================================================
"""

import pandas as pd


class DatasetValidator:

    def __init__(self):

        self.valid_labels = [
            "legitimate",
            "phishing",
            "credential_theft",
            "kyc_scam",
            "aadhaar_scam",
            "digilocker_scam",
            "income_tax_scam",
            "electricity_bill_scam",
            "courier_scam",
            "reward_scam",
            "lottery_scam",
            "refund_scam",
            "government_scam",
            "crypto_scam",
            "employment_scam",
            "business_email_compromise",
            "otp_scam",
            "banking_scam",
            "investment_scam",
            "upi_collect_scam",
            "collect_request",
            "cashback_scam",
            "merchant_scam",
            "job_scam",
            "telegram_scam",
            "apk_scam",
            "fake_customer_care",
            "upi_scam",
            "malicious",
            "url_qr",
            "wifi_qr",
        ]

    # =====================================================
    # Remove Empty Rows
    # =====================================================

    def remove_empty_rows(self, dataframe):

        return dataframe.dropna(how="all")

    # =====================================================
    # Remove Duplicate Rows
    # =====================================================

    def remove_duplicates(self, dataframe):

        return dataframe.drop_duplicates()

    # =====================================================
    # Normalize Whitespace
    # =====================================================

    def normalize_whitespace(self, dataframe):

        for column in dataframe.columns:

            if dataframe[column].dtype == object:

                dataframe[column] = (
                    dataframe[column]
                    .astype(str)
                    .str.replace(r"\s+", " ", regex=True)
                    .str.strip()
                )

        return dataframe

    # =====================================================
    # Validate Labels
    # =====================================================

    def validate_labels(self, dataframe):

        if "label" not in dataframe.columns:

            return dataframe

        dataframe = dataframe[dataframe["label"].isin(self.valid_labels)]

        return dataframe

    # =====================================================
    # Validate Risk Values
    # =====================================================

    def validate_risk(self, dataframe):

        if "risk" not in dataframe.columns:

            return dataframe

        valid = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        dataframe = dataframe[dataframe["risk"].isin(valid)]

        return dataframe

    # =====================================================
    # Remove Short Messages
    # =====================================================

    def validate_message_length(self, dataframe, minimum=15):

        for field in ["message", "content", "url"]:

            if field in dataframe.columns:

                dataframe = dataframe[dataframe[field].astype(str).str.len() >= minimum]

        return dataframe

    # =====================================================
    # Fill Missing Values
    # =====================================================

    def fill_missing_values(self, dataframe):

        return dataframe.fillna("")

    # =====================================================
    # Reset Index
    # =====================================================

    def reset_dataframe(self, dataframe):

        return dataframe.reset_index(drop=True)

    # =====================================================
    # Balance Dataset
    # =====================================================

    def balance_dataset(self, dataframe, label_column="label"):

        if label_column not in dataframe.columns:

            return dataframe

        grouped = dataframe.groupby(label_column)

        minimum = grouped.size().min()

        balanced = []

        for _, group in grouped:

            balanced.append(group.sample(minimum, random_state=42))

        dataframe = pd.concat(balanced)

        dataframe = dataframe.sample(frac=1, random_state=42)

        dataframe.reset_index(drop=True, inplace=True)

        return dataframe

    # =====================================================
    # Complete Validation Pipeline
    # =====================================================

    def validate(self, dataframe):

        dataframe = self.remove_empty_rows(dataframe)

        dataframe = self.remove_duplicates(dataframe)

        dataframe = self.fill_missing_values(dataframe)

        dataframe = self.normalize_whitespace(dataframe)

        dataframe = self.validate_labels(dataframe)

        dataframe = self.validate_risk(dataframe)

        dataframe = self.validate_message_length(dataframe)

        dataframe = self.reset_dataframe(dataframe)

        return dataframe


# =====================================================
# Singleton
# =====================================================

validator = DatasetValidator()
