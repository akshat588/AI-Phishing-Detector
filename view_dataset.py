import pandas as pd

data = pd.read_csv("dataset/models/phishing_emails.csv")

print(data)

print("\nShape:", data.shape)
print("\nColumns:", data.columns)

print("\nFirst 5 Rows:")
print(data.head())