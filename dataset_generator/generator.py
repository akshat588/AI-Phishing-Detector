"""
=========================================================
TrustLens AI
Dataset Generator Engine

Version : 1.0
=========================================================
"""

import random
import pandas as pd

from dataset_generator.templates.email_templates import EMAIL_TEMPLATES
from dataset_generator.templates.sms_templates import SMS_TEMPLATES
from dataset_generator.templates.whatsapp_templates import WHATSAPP_TEMPLATES
from dataset_generator.templates.upi_templates import UPI_TEMPLATES
from dataset_generator.templates.qr_templates import QR_TEMPLATES
from dataset_generator.templates.job_templates import JOB_TEMPLATES
from dataset_generator.templates.url_templates import URL_TEMPLATES


class DatasetGenerator:

    def __init__(self):

        self.datasets = {
            "email": EMAIL_TEMPLATES,
            "sms": SMS_TEMPLATES,
            "whatsapp": WHATSAPP_TEMPLATES,
            "upi": UPI_TEMPLATES,
            "qr": QR_TEMPLATES,
            "job": JOB_TEMPLATES,
            "url": URL_TEMPLATES,
        }

    # ======================================================
    # Get Categories
    # ======================================================

    def get_categories(self, dataset_type):

        dataset = self.datasets.get(dataset_type.lower())

        if dataset is None:
            return []

        return list(dataset.keys())

    # ======================================================
    # Generate One Sample
    # ======================================================

    def generate_sample(self, dataset_type, category):

        dataset_type = dataset_type.lower()

        dataset = self.datasets.get(dataset_type)

        if dataset is None:
            return None

        templates = dataset.get(category)

        if not templates:
            return None

        template = random.choice(templates)

        sample = {
            "dataset_type": dataset_type,
            "category": category,
            "label": template.get("label"),
            "risk": template.get("risk"),
        }

        # ===============================
        # EMAIL
        # ===============================

        if dataset_type == "email":

            sample["subject"] = template["subject"]()

            sample["message"] = template["message"]()

        # ===============================
        # SMS
        # ===============================

        elif dataset_type == "sms":

            sample["message"] = template["message"]()

        # ===============================
        # WHATSAPP
        # ===============================

        elif dataset_type == "whatsapp":

            sample["message"] = template["message"]()

        # ===============================
        # UPI
        # ===============================

        elif dataset_type == "upi":

            sample["message"] = template["message"]()

        # ===============================
        # QR
        # ===============================

        elif dataset_type == "qr":

            sample["content"] = template["content"]()

        # ===============================
        # JOB
        # ===============================

        elif dataset_type == "job":

            sample["message"] = template["message"]()

        # ===============================
        # URL
        # ===============================

        elif dataset_type == "url":

            sample["url"] = template["url"]()

        return sample

    # ======================================================
    # Generate Dataset
    # ======================================================

    def generate_dataset(self, dataset_type, category, records=100):

        rows = []

        for _ in range(records):

            sample = self.generate_sample(dataset_type, category)

            if sample:
                rows.append(sample)

        return pd.DataFrame(rows)

    # ======================================================
    # Generate Dataset (All Categories)
    # ======================================================

    def generate_full_dataset(self, dataset_type, records=1000):

        dataset_type = dataset_type.lower()

        dataset = self.datasets.get(dataset_type)

        if dataset is None:
            return pd.DataFrame()

        categories = list(dataset.keys())

        rows = []

        for _ in range(records):

            category = random.choice(categories)

            sample = self.generate_sample(dataset_type, category)

            if sample:
                rows.append(sample)

        return pd.DataFrame(rows)

    # ======================================================
    # Balanced Dataset
    # ======================================================

    def generate_balanced_dataset(self, dataset_type, records_per_category=100):

        dataset_type = dataset_type.lower()

        dataset = self.datasets.get(dataset_type)

        if dataset is None:
            return pd.DataFrame()

        rows = []

        for category in dataset.keys():

            for _ in range(records_per_category):

                sample = self.generate_sample(dataset_type, category)

                if sample:
                    rows.append(sample)

        random.shuffle(rows)

        return pd.DataFrame(rows)

    # ======================================================
    # Preview
    # ======================================================

    def preview_dataset(self, dataframe, rows=10):

        return dataframe.head(rows)

    # ======================================================
    # Dataset Statistics
    # ======================================================

    def dataset_statistics(self, dataframe):

        stats = {
            "total_records": len(dataframe),
            "columns": list(dataframe.columns),
            "labels": {},
            "risk_levels": {},
        }

        if "label" in dataframe.columns:

            stats["labels"] = dataframe["label"].value_counts().to_dict()

        if "risk" in dataframe.columns:

            stats["risk_levels"] = dataframe["risk"].value_counts().to_dict()

        return stats

    # ======================================================
    # Save CSV
    # ======================================================

    def save_csv(self, dataframe, filename):

        dataframe.to_csv(filename, index=False, encoding="utf-8")

    # ======================================================
    # Save JSON
    # ======================================================

    def save_json(self, dataframe, filename):

        dataframe.to_json(filename, orient="records", indent=4, force_ascii=False)

    # ======================================================
    # Save Excel
    # ======================================================

    def save_excel(self, dataframe, filename):

        dataframe.to_excel(filename, index=False)

    # ======================================================
    # Export
    # ======================================================

    def export(self, dataframe, filename, export_type):

        export_type = export_type.lower()

        if export_type == "csv":

            self.save_csv(dataframe, filename)

        elif export_type == "json":

            self.save_json(dataframe, filename)

        elif export_type in ["xlsx", "excel"]:

            self.save_excel(dataframe, filename)

        else:

            raise ValueError("Unsupported export format.")


# ==========================================================
# Singleton Instance
# ==========================================================

generator = DatasetGenerator()
