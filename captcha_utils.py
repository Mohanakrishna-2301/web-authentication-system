"""
Simple server-side math CAPTCHA for SecureAuth+.
No external dependency needed.
"""

import random


def generate_captcha():
    """Return (question_text, answer) tuple."""
    a = random.randint(2, 15)
    b = random.randint(2, 15)
    ops = [("+", a + b), ("-", abs(a - b)), ("×", a * b)]
    op_symbol, answer = random.choice(ops)
    if op_symbol == "-":
        # Ensure positive result
        big, small = max(a, b), min(a, b)
        question = f"{big} {op_symbol} {small}"
        answer = big - small
    else:
        question = f"{a} {op_symbol} {b}"
    return question, str(answer)


def verify_captcha(expected, provided):
    """Compare CAPTCHA answer (string comparison)."""
    if not expected or not provided:
        return False
    return str(expected).strip() == str(provided).strip()
