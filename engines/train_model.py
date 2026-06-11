import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==========================
# Load Dataset
# ==========================

print("Loading dataset...")

data = pd.read_csv(
    "dataset/models/datasets/phishing_email.csv"
)

print("Dataset Loaded Successfully")
print("Total Emails:", len(data))

# ==========================
# Features & Labels
# ==========================

X = data["text_combined"]

y = data["label"]

# ==========================
# Train Test Split
# ==========================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# ==========================
# TF-IDF Vectorization
# ==========================

print("Vectorizing text...")

vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=10000
)

X_train_vector = vectorizer.fit_transform(
    X_train
)

X_test_vector = vectorizer.transform(
    X_test
)

# ==========================
# Train Model
# ==========================

print("Training model...")

model = LogisticRegression(
    max_iter=1000
)

model.fit(
    X_train_vector,
    y_train
)

# ==========================
# Predictions
# ==========================

predictions = model.predict(
    X_test_vector
)

# ==========================
# Accuracy
# ==========================

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\n=========================")
print("MODEL EVALUATION")
print("=========================")

print(
    "Accuracy:",
    round(accuracy * 100, 2),
    "%"
)

# ==========================
# Confusion Matrix
# ==========================

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    predictions
)

print(cm)

# ==========================
# Classification Report
# ==========================

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        predictions
    )
)

# ==========================
# Save Model
# ==========================

joblib.dump(
    model,
    "saved_model.pkl"
)

joblib.dump(
    vectorizer,
    "vectorizer.pkl"
)

print("\nModel Saved Successfully")

# ==========================
# Quick Test
# ==========================

sample = [
    """
    Verify your account immediately.
    Click here to login.
    Your account will be suspended.
    """
]

sample_vector = vectorizer.transform(
    sample
)

prediction = model.predict(
    sample_vector
)

print("\nQuick Test Result:")

if prediction[0] == 1:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")