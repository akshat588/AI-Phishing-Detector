import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Load dataset
data = pd.read_csv("dataset/models/phishing_emails.csv")

# Prepare data
vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(data["email"])

y = data["label"]

# Train model
model = LogisticRegression()

model.fit(X, y)

# User input
message = input("Enter email message: ")

message_vector = vectorizer.transform([message])

prediction = model.predict(message_vector)

probability = model.predict_proba(message_vector)

print("\nConfidence:", round(max(probability[0]) * 100, 2), "%")

if prediction[0] == 1:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")