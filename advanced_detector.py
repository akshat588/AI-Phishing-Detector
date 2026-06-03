phishing_words = {
    "password": 25,
    "otp": 30,
    "verify": 20,
    "urgent": 15,
    "suspended": 20,
    "bank": 25,
    "click": 15
}

message = input("Enter message: ").lower()

score = 0
found_words = []

for word, points in phishing_words.items():

    if word in message:
        score += points
        found_words.append(word)

print("\nIndicators Found:")

for item in found_words:
    print("✓", item)

print("\nRisk Score:", score)

if score >= 40:
    print("⚠ PHISHING DETECTED")
else:
    print("✓ SAFE MESSAGE")