from pyzxcvbn import zxcvbn
import re
import secrets
import string


def generate_password(length: int = 16, exclude_special: bool = False) -> str:
    """
    Generates a strong, random password of the specified length.
    Optionally excludes special characters if needed.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    characters = string.ascii_letters + string.digits
    if not exclude_special:
        characters += string.punctuation.replace('"', '').replace('\\', '')  # Avoid problematic chars

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def check_password_strength(password: str):
    """
    Evaluates password strength based on length, complexity, and zxcvbn analysis.
    """
    try:
        # Check Length
        length_score = 2 if len(password) >= 16 else (1 if len(password) >= 12 else 0)

        # Check Complexity
        complexity_criteria = [
            r'[A-Z]',  # Uppercase
            r'[a-z]',  # Lowercase
            r'\d',  # Digit
            r'[@$!%*?&]',  # Special character
        ]
        complexity_score = sum(bool(re.search(pattern, password)) for pattern in complexity_criteria)

        # Analyze Entropy using zxcvbn
        analysis = zxcvbn(password)
        entropy_score = analysis.get("score", 0)  # Default to 0 if missing

        # Weighted scoring approach
        total_score = (length_score * 1.5) + (complexity_score * 1.2) + (entropy_score * 2)

        # Determine Strength Level
        if total_score >= 8:
            strength = "Very Strong"
        elif total_score >= 6:
            strength = "Strong"
        elif total_score >= 4:
            strength = "Moderate"
        else:
            strength = "Weak"

        return {
            "strength": strength,
            "score": round(total_score, 2),
            "suggestions": analysis["feedback"]["suggestions"] or ["Consider using a longer and more complex password."]
        }

    except Exception as e:
        return {
            "strength": "Weak",
            "score": 0,
            "suggestions": ["Error analyzing password strength: " + str(e)]
        }

