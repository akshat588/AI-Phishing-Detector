import joblib

# Load saved files
model = joblib.load("saved_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# User input
message = input("Enter email message: ")

# Convert to numbers
message_vector = vectorizer.transform([message])

# Prediction
prediction = model.predict(message_vector)
probability = model.predict_proba(message_vector)

confidence = round(max(probability[0]) * 100, 2)

print("\nConfidence:", confidence, "%")

if prediction[0] == 1:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")