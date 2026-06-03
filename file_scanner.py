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
        if word in message.lower():
            score += points

    return score

with open("emails.txt", "r") as file:
    emails = file.readlines()

for email in emails:

    email = email.strip()

    if email == "":
        continue

    score = check_message(email)

    print("\nEmail:", email)
    print("Risk Score:", score)

    if score >= 40:
        print("⚠ PHISHING")
    else:
        print("✓ SAFE")