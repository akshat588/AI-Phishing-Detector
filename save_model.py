import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Load dataset
data = pd.read_csv("dataset/models/phishing_emails.csv")

# Features and labels
X = data["email"]
y = data["label"]

# Convert text to numbers
vectorizer = TfidfVectorizer()
X_vectorized = vectorizer.fit_transform(X)

# Train model
model = LogisticRegression()
model.fit(X_vectorized, y)

# Save model and vectorizer
joblib.dump(model, "saved_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Model saved successfully!")
print("✅ saved_model.pkl created")
print("✅ vectorizer.pkl created")