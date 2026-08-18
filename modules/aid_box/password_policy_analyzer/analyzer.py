"""
Core logic for the Password Policy Analyzer tool.

Two independent checks:
1. analyze_password(password) - scores a single password against
   standard strength criteria (length, character variety, entropy,
   common-password blocklist). The password itself is never logged,
   stored, or published anywhere -- only the resulting score/verdict.
2. get_system_policy() - reads the OS's own local account password
   policy (via `net accounts` on Windows) and compares it against
   recommended baseline values, so users can see if their machine's
   policy itself is weak.
"""
import math
import platform
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.settings import get_setting

# A small, well-known set of the most common passwords (public knowledge,
# used only for local client-side blocklist matching -- not a cracking list).
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "123123", "letmein", "welcome", "admin",
    "password1", "iloveyou", "monkey", "dragon", "football", "1234567",
    "sunshine", "master", "trustno1", "princess", "login", "passw0rd",
}

def _min_length() -> int:
    """Resolved fresh on each call (not cached at import time) so changes
    made in the Settings panel take effect without restarting the app."""
    return get_setting("password_min_length_recommended")


@dataclass
class PasswordAnalysis:
    length: int
    score: int                       # 0-100
    verdict: str                     # Very Weak / Weak / Fair / Strong / Very Strong
    entropy_bits: float
    checks: Dict[str, bool] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)
    is_common: bool = False


def _charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 32  # rough estimate for common special characters
    return max(size, 1)


def analyze_password(password: str) -> PasswordAnalysis:
    if not password:
        return PasswordAnalysis(
            length=0, score=0, verdict="Empty", entropy_bits=0.0,
            checks={}, suggestions=["Enter a password to analyze."],
        )

    length = len(password)
    checks = {
        "length_12plus": length >= _min_length(),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "no_repeated_chars": not bool(re.search(r"(.)\1{2,}", password)),  # aaa, 111, etc.
    }

    is_common = password.lower() in COMMON_PASSWORDS
    entropy_bits = length * math.log2(_charset_size(password))

    # Weighted scoring
    score = 0
    score += min(length, 20) * 2               # up to 40 pts for length
    score += 10 if checks["has_lowercase"] else 0
    score += 10 if checks["has_uppercase"] else 0
    score += 10 if checks["has_digit"] else 0
    score += 15 if checks["has_special"] else 0
    score += 10 if checks["no_repeated_chars"] else 0
    score += 5 if entropy_bits >= 60 else 0
    if is_common:
        score = min(score, 10)  # common passwords are never "strong", regardless of shape
    score = max(0, min(100, score))

    if is_common:
        verdict = "Very Weak (common password)"
    elif score >= 85:
        verdict = "Very Strong"
    elif score >= 65:
        verdict = "Strong"
    elif score >= 45:
        verdict = "Fair"
    elif score >= 25:
        verdict = "Weak"
    else:
        verdict = "Very Weak"

    suggestions = []
    if is_common:
        suggestions.append("This is one of the most commonly used passwords — change it immediately.")
    if not checks["length_12plus"]:
        suggestions.append(f"Use at least {_min_length()} characters.")
    if not checks["has_uppercase"]:
        suggestions.append("Add uppercase letters.")
    if not checks["has_lowercase"]:
        suggestions.append("Add lowercase letters.")
    if not checks["has_digit"]:
        suggestions.append("Add numbers.")
    if not checks["has_special"]:
        suggestions.append("Add special characters (e.g. ! @ # $ %).")
    if not checks["no_repeated_chars"]:
        suggestions.append("Avoid repeating the same character 3+ times in a row.")
    if not suggestions:
        suggestions.append("Looks solid. Consider a password manager so you never reuse it elsewhere.")

    return PasswordAnalysis(
        length=length, score=score, verdict=verdict, entropy_bits=round(entropy_bits, 1),
        checks=checks, suggestions=suggestions, is_common=is_common,
    )


@dataclass
class PolicyCheckItem:
    label: str
    current_value: str
    recommended: str
    passed: bool


@dataclass
class SystemPolicyResult:
    platform: str
    items: List[PolicyCheckItem] = field(default_factory=list)
    weak_count: int = 0
    error: Optional[str] = None


def get_system_policy() -> SystemPolicyResult:
    """Best-effort read of the local machine's account password policy."""
    system = platform.system().lower()

    if system == "windows":
        return _windows_policy()
    else:
        return SystemPolicyResult(
            platform=system,
            error="System policy reading is currently only implemented for Windows "
                  "(via 'net accounts'). You can still use the password tester above "
                  "on any OS.",
        )


def _windows_policy() -> SystemPolicyResult:
    try:
        output = subprocess.check_output(
            ["net", "accounts"], stderr=subprocess.STDOUT, timeout=5
        ).decode(errors="ignore")
    except Exception as e:
        return SystemPolicyResult(platform="windows", error=f"Could not read policy: {e}")

    def _extract(pattern, text, default="Unknown"):
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    min_len_raw = _extract(r"Minimum password length.*?:\s*(\S+)", output)
    max_age_raw = _extract(r"Maximum password age.*?:\s*(\S+)", output)
    lockout_raw = _extract(r"Lockout threshold.*?:\s*(\S+)", output)
    history_raw = _extract(r"password history.*?:\s*(\S+)", output)

    items = []

    def _to_int(v):
        try:
            return int(v)
        except Exception:
            return None

    min_len = _to_int(min_len_raw)
    items.append(PolicyCheckItem(
        "Minimum password length", min_len_raw, f">= {_min_length()}",
        passed=(min_len is not None and min_len >= _min_length()),
    ))

    lockout = _to_int(lockout_raw)
    items.append(PolicyCheckItem(
        "Account lockout threshold", lockout_raw, "1-10 attempts (0/Never is risky)",
        passed=(lockout is not None and 0 < lockout <= 10),
    ))

    history = _to_int(history_raw)
    items.append(PolicyCheckItem(
        "Password history remembered", history_raw, ">= 5",
        passed=(history is not None and history >= 5),
    ))

    items.append(PolicyCheckItem(
        "Maximum password age", max_age_raw, "<= 90 days (or a managed rotation policy)",
        passed=(max_age_raw not in ("Unknown",)),  # informational; hard to score generically
    ))

    weak_count = sum(1 for i in items if not i.passed)

    return SystemPolicyResult(platform="windows", items=items, weak_count=weak_count)
