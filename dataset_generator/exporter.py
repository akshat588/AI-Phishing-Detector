"""
=========================================================
TrustLens AI
Dataset Export Engine

Version : 1.0
=========================================================
"""

import os
import json
import pandas as pd
from datetime import datetime


class DatasetExporter:

    def __init__(self):

        self.export_folder = "generated_datasets"

        os.makedirs(self.export_folder, exist_ok=True)

    # =====================================================
    # Generate Filename
    # =====================================================

    def generate_filename(self, dataset_type, extension):

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename = f"{dataset_type}_dataset_" f"{timestamp}.{extension}"

        return os.path.join(self.export_folder, filename)

    # =====================================================
    # CSV Export
    # =====================================================

    def export_csv(self, dataframe, dataset_type):

        filename = self.generate_filename(dataset_type, "csv")

        dataframe.to_csv(filename, index=False, encoding="utf-8")

        return filename

    # =====================================================
    # JSON Export
    # =====================================================

    def export_json(self, dataframe, dataset_type):

        filename = self.generate_filename(dataset_type, "json")

        dataframe.to_json(filename, orient="records", indent=4, force_ascii=False)

        return filename

    # =====================================================
    # Excel Export
    # =====================================================

    def export_excel(self, dataframe, dataset_type):

        filename = self.generate_filename(dataset_type, "xlsx")

        dataframe.to_excel(filename, index=False)

        return filename

    # =====================================================
    # Export Metadata
    # =====================================================

    def export_metadata(self, dataframe, dataset_type):

        metadata = {
            "dataset_type": dataset_type,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_records": len(dataframe),
            "columns": list(dataframe.columns),
        }

        filename = self.generate_filename(dataset_type + "_metadata", "json")

        with open(filename, "w", encoding="utf-8") as f:

            json.dump(metadata, f, indent=4, ensure_ascii=False)

        return filename

    # =====================================================
    # Export Dispatcher
    # =====================================================

    def export(self, dataframe, dataset_type, export_format):

        export_format = export_format.lower()

        if export_format == "csv":

            dataset_file = self.export_csv(dataframe, dataset_type)

        elif export_format == "json":

            dataset_file = self.export_json(dataframe, dataset_type)

        elif export_format in ["xlsx", "excel"]:

            dataset_file = self.export_excel(dataframe, dataset_type)

        else:

            raise ValueError(f"Unsupported format: {export_format}")

        metadata_file = self.export_metadata(dataframe, dataset_type)

        return {
            "dataset_file": dataset_file,
            "metadata_file": metadata_file,
            "records": len(dataframe),
            "columns": len(dataframe.columns),
        }

    # =====================================================
    # Dataset Summary
    # =====================================================

    def summary(self, dataframe):

        summary = {
            "records": len(dataframe),
            "columns": len(dataframe.columns),
            "column_names": list(dataframe.columns),
            "labels": {},
            "risk_distribution": {},
        }

        if "label" in dataframe.columns:

            summary["labels"] = dataframe["label"].value_counts().to_dict()

        if "risk" in dataframe.columns:

            summary["risk_distribution"] = dataframe["risk"].value_counts().to_dict()

        return summary


# =====================================================
# Singleton
# =====================================================

exporter = DatasetExporter()
