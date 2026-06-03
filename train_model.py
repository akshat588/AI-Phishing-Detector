import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Load dataset
data = pd.read_csv("dataset/models/phishing_emails.csv")

# Convert text to numbers
vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(data["email"])

# Labels
y = data["label"]

# Train model
model = LogisticRegression()

model.fit(X, y)

print("Model Trained Successfully!")

# Test message
message = ["Happy birthday friend"]

message_vector = vectorizer.transform(message)

prediction = model.predict(message_vector)

if prediction[0] == 1:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")