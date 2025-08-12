"""Generazione password sicure (core, puro)."""

from __future__ import annotations

import secrets
import string
from typing import List

DEFAULT_UPPER = string.ascii_uppercase
DEFAULT_LOWER = string.ascii_lowercase
DEFAULT_DIGITS = string.digits
DEFAULT_SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
AMBIGUOUS = {"O", "0", "I", "l"}


def _build_charset(
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_symbols: bool,
    exclude_ambiguous: bool,
) -> dict:
    groups = {}
    if use_upper:
        groups["upper"] = DEFAULT_UPPER
    if use_lower:
        groups["lower"] = DEFAULT_LOWER
    if use_digits:
        groups["digits"] = DEFAULT_DIGITS
    if use_symbols:
        groups["symbols"] = DEFAULT_SYMBOLS
    if exclude_ambiguous:
        for k, v in list(groups.items()):
            groups[k] = "".join(ch for ch in v if ch not in AMBIGUOUS)
    return groups


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    if length < 4:
        raise ValueError("length must be >= 4")

    groups = _build_charset(
        use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous
    )
    if not groups:
        raise ValueError("At least one character group must be enabled")

    # Guarantee at least one character from each enabled group
    required_chars: List[str] = [secrets.choice(chars) for chars in groups.values()]
    remaining_len = length - len(required_chars)
    all_chars = "".join(groups.values())
    password_chars = required_chars + [
        secrets.choice(all_chars) for _ in range(remaining_len)
    ]
    # shuffle securely
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
