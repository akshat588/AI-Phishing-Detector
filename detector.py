phishing_words = [
    "password",
    "otp",
    "verify",
    "urgent",
    "suspended",
    "bank",
    "click"
]

message = input("Enter message: ").lower()

score = 0

for word in phishing_words:
    if word in message:
        score += 15

if score > 100:
    score = 100

print(f"Risk Score: {score}%")

if score >= 50:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")