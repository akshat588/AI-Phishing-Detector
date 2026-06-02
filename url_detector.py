url = input("Enter URL: ").lower()

score = 0

if "-" in url:
    score += 20

if any(char.isdigit() for char in url):
    score += 20

suspicious_words = [
    "login",
    "verify",
    "secure",
    "account",
    "bank"
]

for word in suspicious_words:
    if word in url:
        score += 20

if score > 100:
    score = 100

print(f"Risk Score: {score}%")

if score >= 40:
    print("⚠ Suspicious URL")
else:
    print("✓ Safe URL")