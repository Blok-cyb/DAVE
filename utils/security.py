import re
from werkzeug.security import generate_password_hash, check_password_hash


def is_valid_email(email):
    """
    Validate email format.
    """

    pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

    return re.match(pattern, email) is not None


def is_strong_password(password):
    """
    Password must contain:
    - At least 8 characters
    - One uppercase letter
    - One lowercase letter
    - One number
    - One special character
    """

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    return True


def hash_password(password):
    """
    Hash user password.
    """

    return generate_password_hash(password)


def verify_password(password, hashed_password):
    """
    Verify hashed password.
    """

    return check_password_hash(hashed_password, password)