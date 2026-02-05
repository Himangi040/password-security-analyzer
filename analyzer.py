import math
import hashlib
import getpass

def estimate_entropy(password):
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32

    if pool == 0:
        return 0
    return len(password) * math.log2(pool)

def strength(entropy):
    if entropy < 35:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    else:
        return "Strong"

def main():
    password = getpass.getpass("Enter password: ")
    entropy = estimate_entropy(password)
    hashed = hashlib.sha256(password.encode()).hexdigest()

    report = f"""
Password length: {len(password)}
Entropy score: {entropy:.2f}
Strength: {strength(entropy)}
SHA-256 hash: {hashed}
"""

    print(report)

    with open("sample_output.txt", "w") as f:
        f.write(report)

if __name__ == "__main__":
    main()
