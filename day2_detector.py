phishing_words = {
    "password": 25,
    "otp": 30,
    "verify": 20,
    "urgent": 15,
    "suspended": 20,
    "bank": 25,
    "click": 15
}

def check_message(message):
    score = 0

    for word, points in phishing_words.items():
        if word in message:
            print(f"Found: {word}")
            score += points

    if score > 100:
        score = 100

    print(f"\nRisk Score: {score}%")

    if score >= 50:
        print("⚠ PHISHING DETECTED")
    else:
        print("✓ SAFE MESSAGE")

message = input("Enter message: ").lower()

check_message(message)