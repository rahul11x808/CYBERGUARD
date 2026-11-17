"""
CyberGuard Module 1: Password Generator & Strength Checker
Uses Python's built-in `secrets` and `string` modules.
Does NOT store generated passwords anywhere.
"""
import math
import getpass
import secrets
import string
import sys

def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
    """
    Generates a cryptographically strong random password using Python's secrets module.
    Enforces at least one character from each selected pool.
    """
    length = max(8, min(int(length), 64))

    char_pool = ""
    guaranteed = []

    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    symbol_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if exclude_ambiguous:
        # Exclude confusing characters like l, 1, I, O, 0, etc.
        ambiguous = "l1IO0o"
        upper_chars = ''.join(c for c in upper_chars if c not in ambiguous)
        lower_chars = ''.join(c for c in lower_chars if c not in ambiguous)
        digit_chars = ''.join(c for c in digit_chars if c not in ambiguous)

    if use_upper and upper_chars:
        char_pool += upper_chars
        guaranteed.append(secrets.choice(upper_chars))
    if use_lower and lower_chars:
        char_pool += lower_chars
        guaranteed.append(secrets.choice(lower_chars))
    if use_digits and digit_chars:
        char_pool += digit_chars
        guaranteed.append(secrets.choice(digit_chars))
    if use_symbols and symbol_chars:
        char_pool += symbol_chars
        guaranteed.append(secrets.choice(symbol_chars))

    if not char_pool:
        # Fallback to standard alphanumeric if nothing selected
        char_pool = string.ascii_letters + string.digits
        guaranteed = [secrets.choice(char_pool)]

    # Fill remaining characters
    remaining_length = length - len(guaranteed)
    password_chars = guaranteed + [secrets.choice(char_pool) for _ in range(remaining_length)]

    # Cryptographically shuffle the resulting character list
    shuffled = []
    while password_chars:
        idx = secrets.randbelow(len(password_chars))
        shuffled.append(password_chars.pop(idx))

    return "".join(shuffled)

def evaluate_password_strength(password):
    """
    Evaluates password strength transparently based on length, character diversity,
    and Shannon entropy in bits (log2(pool^length)).
    Returns a dict with score (0-100), label, entropy, suggestions, and crack time estimate.
    """
    if not password:
        return {
            'score': 0,
            'label': 'Empty',
            'entropy_bits': 0,
            'crack_time': 'Instant',
            'color': 'secondary',
            'feedback': ['Please enter or generate a password to evaluate.']
        }

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    pool_size = 0
    if has_upper:
        pool_size += 26
    if has_lower:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32

    pool_size = max(pool_size, 1)
    entropy_bits = round(length * math.log2(pool_size), 1)

    feedback = []
    if length < 10:
        feedback.append("Increase length to at least 12-16 characters.")
    if not has_upper:
        feedback.append("Include uppercase letters (A-Z).")
    if not has_lower:
        feedback.append("Include lowercase letters (a-z).")
    if not has_digit:
        feedback.append("Include numeric digits (0-9).")
    if not has_symbol:
        feedback.append("Include special characters (!@#$%^&*...).")

    # Estimate score out of 100
    if entropy_bits < 30:
        score = 20
        label = "Very Weak"
        color = "danger"
        crack_time = "< 1 millisecond"
    elif entropy_bits < 50:
        score = 45
        label = "Weak"
        color = "warning"
        crack_time = "Few seconds to minutes"
    elif entropy_bits < 70:
        score = 70
        label = "Moderate"
        color = "info"
        crack_time = "Several months to years"
    elif entropy_bits < 90:
        score = 90
        label = "Strong"
        color = "primary"
        crack_time = "Thousands of years"
    else:
        score = 100
        label = "Very Strong"
        color = "success"
        crack_time = "Centuries / Practically Unbreakable"

    if not feedback:
        feedback.append("Excellent combination of length and character variety!")

    return {
        'score': score,
        'label': label,
        'color': color,
        'entropy_bits': entropy_bits,
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit': has_digit,
        'has_symbol': has_symbol,
        'crack_time': crack_time,
        'feedback': feedback
    }


def main():
    print("CyberGuard Password Tools")
    print("1. Generate a password")
    print("2. Check password strength")
    choice = input("Choose 1 or 2: ").strip()

    if choice == "1":
        raw_length = input("Password length (8-64) [16]: ").strip()
        if raw_length:
            try:
                length = int(raw_length)
            except ValueError:
                print("Please enter a whole-number length.")
                return 1
            if not 8 <= length <= 64:
                print("Length must be between 8 and 64.")
                return 1
        else:
            length = 16

        password = generate_password(length)
        strength = evaluate_password_strength(password)
        print(f"Generated password: {password}")
        print(f"Strength: {strength['label']} ({strength['score']}/100)")
        return 0

    if choice == "2":
        password = getpass.getpass("Enter password (input hidden): ")
        strength = evaluate_password_strength(password)
        print(f"Strength: {strength['label']} ({strength['score']}/100)")
        print(f"Estimated entropy: {strength['entropy_bits']} bits")
        for feedback in strength['feedback']:
            print(f"- {feedback}")
        return 0

    print("Invalid choice. Enter 1 or 2.", file=sys.stderr)
    return 1


generate_password.__doc__ = generate_password.__doc__.strip()
evaluate_password_strength.__doc__ = evaluate_password_strength.__doc__.strip()


if __name__ == "__main__":
    raise SystemExit(main())
