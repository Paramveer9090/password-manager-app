import hashlib
import requests


def check_pwned_password(password: str, timeout: int = 5):
    """
    Checks if a password has been compromised in a data breach using HIBP API.
    Uses the k-Anonymity model to protect user privacy.

    Args:
        password (str): The password to check.
        timeout (int): Maximum time (in seconds) to wait for the API response.

    Returns:
        dict: A JSON-formatted dictionary with status and breach occurrences.
    """
    try:
        # Hash password securely using SHA-1 (HIBP API requirement)
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        # Query HIBP API
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=timeout)

        # Handle non-200 response codes
        if response.status_code != 200:
            return {"status": "Error", "message": "Failed to reach Have I Been Pwned API", "occurrences": None}

        # Process response text
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return {"status": "Compromised", "occurrences": int(count)}

        return {"status": "Safe", "occurrences": 0}

    except requests.exceptions.Timeout:
        return {"status": "Error", "message": "Request timed out. Try again later.", "occurrences": None}

    except requests.exceptions.RequestException as e:
        return {"status": "Error", "message": f"Network error: {e}", "occurrences": None}

    except Exception as e:
        return {"status": "Error", "message": f"Unexpected error: {e}", "occurrences": None}
