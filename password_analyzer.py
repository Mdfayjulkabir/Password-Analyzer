import re
import string
import secrets
import hashlib
import requests
from math import log2

# Common weak passwords list (can be expanded)
COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}

def calculate_entropy(password):
    """Calculates password entropy (how unpredictable it is)."""
    character_sets = 0
    if any(c.islower() for c in password):
        character_sets += 26  # Lowercase letters
    if any(c.isupper() for c in password):
        character_sets += 26  # Uppercase letters
    if any(c.isdigit() for c in password):
        character_sets += 10  # Numbers
    if any(c in string.punctuation for c in password):
        character_sets += len(string.punctuation)  # Special characters
    
    if character_sets == 0:
        return 0
    return len(password) * log2(character_sets)

def check_pwned_password(password):
    """Checks if the password has been exposed in data breaches using Have I Been Pwned API."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code == 200:
            hashes = (line.split(":") for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)  # Number of times this password has been leaked
    except requests.RequestException:
        return None  # API request failed
    return 0  # Password not found in breach list

def analyze_password(password):
    """Analyzes password strength and weaknesses."""
    weaknesses = []

    # Length check
    if len(password) < 8:
        weaknesses.append("Too short (minimum 8 characters recommended).")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        weaknesses.append("Commonly used password, easily guessable.")

    # Variety check
    if not any(c.islower() for c in password):
        weaknesses.append("Missing lowercase letters.")
    if not any(c.isupper() for c in password):
        weaknesses.append("Missing uppercase letters.")
    if not any(c.isdigit() for c in password):
        weaknesses.append("Missing numbers.")
    if not any(c in string.punctuation for c in password):
        weaknesses.append("Missing special characters.")

    # Pattern detection
    if re.search(r"(.)\1{2,}", password):  # Repeated characters
        weaknesses.append("Contains repeated characters (e.g., 'aaa', '111').")
    if re.search(r"(123|abc|password|qwerty|letmein)", password, re.IGNORECASE):
        weaknesses.append("Contains predictable sequences or dictionary words.")

    # Check if password has been exposed in a data breach
    breach_count = check_pwned_password(password)
    if breach_count is None:
        weaknesses.append("Could not verify data breach status (API issue).")
    elif breach_count > 0:
        weaknesses.append(f"Password found in data breaches {breach_count} times! Avoid using it.")

    # Strength evaluation
    entropy = calculate_entropy(password)
    if entropy < 28:
        strength = "Very Weak"
    elif entropy < 36:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    elif entropy < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return {"password": password, "strength": strength, "entropy": entropy, "weaknesses": weaknesses}

def suggest_strong_password():
    """Generates a strong, random password."""
    length = 16
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

if __name__ == "__main__":
    user_password = input("Enter a password to analyze: ")
    result = analyze_password(user_password)

    print("\n🔍 Password Analysis:")
    print(f"🔹 Strength: {result['strength']} (Entropy: {result['entropy']:.2f} bits)")
    
    if result["weaknesses"]:
        print("\n⚠ Weaknesses detected:")
        for w in result["weaknesses"]:
            print(f"- {w}")
    else:
        print("\n✅ No weaknesses detected. Great password!")

    print("\n🔑 Suggested Secure Password: " + suggest_strong_password())
