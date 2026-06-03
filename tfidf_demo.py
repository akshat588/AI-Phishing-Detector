import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer

data = pd.read_csv("dataset/models/phishing_emails.csv")

vectorizer = TfidfVectorizer()

X = vectorizer.fit_transform(data["email"])

print("Shape:", X.shape)

print("\nWords Learned:")

print(vectorizer.get_feature_names_out())