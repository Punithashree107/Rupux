"""
Core logic for the Cryptanalysis tool.

Classical, well-established cryptanalysis techniques -- frequency
analysis, index of coincidence, brute force over small keyspaces
(26 Caesar shifts, 256 single-byte XOR keys). These work because
classical ciphers and single-byte XOR are fundamentally weak; none
of this applies to modern ciphers like AES, which is precisely the
point this tool demonstrates (why weak/legacy crypto should be
retired). No general-purpose hash cracking is included -- only a
lookup against a small, well-known common-password list to
illustrate why unsalted hashes of common passwords are unsafe.
"""
import base64
import binascii
import math
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Standard English letter frequency percentages (Wikipedia / standard corpus)
ENGLISH_FREQ = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}
ENGLISH_IC = 0.0667  # typical index of coincidence for English text


def _letters_only(text: str) -> str:
    return re.sub(r"[^a-zA-Z]", "", text).lower()


def _chi_squared(text: str) -> float:
    """Lower score = closer to natural English letter distribution."""
    letters = _letters_only(text)
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = {c: letters.count(c) for c in set(letters)}
    score = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        observed = counts.get(letter, 0)
        expected = expected_pct / 100.0 * n
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score


def _index_of_coincidence(letters: str) -> float:
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {c: letters.count(c) for c in set(letters)}
    numerator = sum(c * (c - 1) for c in counts.values())
    return numerator / (n * (n - 1))


# ---------------- Caesar cipher ----------------

def _caesar_shift(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


@dataclass
class CaesarResult:
    shift: int
    score: float
    plaintext: str


def crack_caesar(ciphertext: str, top_n: int = 3) -> List[CaesarResult]:
    results = []
    for shift in range(26):
        pt = _caesar_shift(ciphertext, shift)
        results.append(CaesarResult(shift=shift, score=_chi_squared(pt), plaintext=pt))
    results.sort(key=lambda r: r.score)
    return results[:top_n]


# ---------------- Vigenere cipher ----------------

@dataclass
class VigenereResult:
    key: str
    key_length: int
    score: float
    plaintext: str


def _estimate_key_lengths(ciphertext: str, max_len: int = 12, top_n: int = 3) -> List[int]:
    letters = _letters_only(ciphertext)
    candidates = []
    for length in range(1, min(max_len, max(2, len(letters) // 2)) + 1):
        cosets = ["".join(letters[i::length]) for i in range(length)]
        ics = [_index_of_coincidence(c) for c in cosets if len(c) > 1]
        avg_ic = sum(ics) / len(ics) if ics else 0.0
        # Score by closeness to natural English IC
        candidates.append((length, abs(avg_ic - ENGLISH_IC)))
    candidates.sort(key=lambda x: x[1])
    return [length for length, _ in candidates[:top_n]]


def _vigenere_decrypt(ciphertext: str, key: str) -> str:
    result = []
    key = key.lower()
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def crack_vigenere(ciphertext: str, max_key_len: int = 12, top_n: int = 3) -> List[VigenereResult]:
    letters_upper_positions = [c for c in ciphertext if c.isalpha()]
    if len(letters_upper_positions) < 20:
        return []  # too short for reliable statistical cryptanalysis

    candidate_lengths = _estimate_key_lengths(ciphertext, max_len=max_key_len, top_n=4)
    results = []

    for length in candidate_lengths:
        letters = _letters_only(ciphertext)
        key_chars = []
        for col in range(length):
            coset = letters[col::length]
            best = min(range(26), key=lambda s: _chi_squared(_caesar_shift(coset, s)))
            key_chars.append(chr(best + ord('a')))
        key = "".join(key_chars)
        pt = _vigenere_decrypt(ciphertext, key)
        results.append(VigenereResult(key=key, key_length=length, score=_chi_squared(pt), plaintext=pt))

    results.sort(key=lambda r: r.score)
    return results[:top_n]


# ---------------- Single-byte XOR ----------------

@dataclass
class XorResult:
    key: int
    score: float
    plaintext: str


def _printable_score(data: bytes) -> float:
    """Lower = more printable/English-like. Penalizes non-printable bytes heavily."""
    if not data:
        return float("inf")
    penalty = 0.0
    text_chars = []
    for b in data:
        if 32 <= b <= 126:
            text_chars.append(chr(b))
        elif b in (9, 10, 13):
            text_chars.append(" ")
        else:
            penalty += 10  # heavy penalty for non-printable bytes
    text = "".join(text_chars)
    return penalty + _chi_squared(text)


def xor_bruteforce(data: bytes, top_n: int = 5) -> List[XorResult]:
    results = []
    for key in range(256):
        xored = bytes(b ^ key for b in data)
        try:
            text = xored.decode("utf-8", errors="replace")
        except Exception:
            text = str(xored)
        results.append(XorResult(key=key, score=_printable_score(xored), plaintext=text))
    results.sort(key=lambda r: r.score)
    return results[:top_n]


def parse_input_bytes(text: str) -> Optional[bytes]:
    """Best-effort: interpret input as hex if it looks like hex, else raw UTF-8 bytes."""
    stripped = text.strip().replace(" ", "").replace("\n", "")
    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0 and len(stripped) > 0:
        try:
            return bytes.fromhex(stripped)
        except ValueError:
            pass
    return text.encode("utf-8", errors="replace")


# ---------------- Encoding detection ----------------

@dataclass
class DecodeStep:
    label: str
    result: str
    success: bool


def detect_and_decode(text: str) -> List[DecodeStep]:
    steps = []
    stripped = text.strip()

    # ROT13 (always "succeeds" -- just show it as an option)
    steps.append(DecodeStep("ROT13", _caesar_shift(stripped, 13), True))

    # Hex
    hex_candidate = stripped.replace(" ", "")
    if re.fullmatch(r"[0-9a-fA-F]+", hex_candidate) and len(hex_candidate) % 2 == 0 and hex_candidate:
        try:
            decoded = bytes.fromhex(hex_candidate).decode("utf-8", errors="replace")
            steps.append(DecodeStep("Hex decode", decoded, True))
        except Exception:
            steps.append(DecodeStep("Hex decode", "Failed to decode", False))

    # Base64
    b64_candidate = stripped
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", b64_candidate) and len(b64_candidate) % 4 == 0:
        try:
            decoded = base64.b64decode(b64_candidate).decode("utf-8", errors="replace")
            steps.append(DecodeStep("Base64 decode", decoded, True))
        except Exception:
            steps.append(DecodeStep("Base64 decode", "Failed to decode", False))

    # Binary (space-separated 8-bit groups)
    binary_candidate = stripped.replace(" ", "")
    if re.fullmatch(r"[01]+", binary_candidate) and len(binary_candidate) % 8 == 0 and binary_candidate:
        try:
            n = int(binary_candidate, 2)
            byte_length = len(binary_candidate) // 8
            decoded = n.to_bytes(byte_length, "big").decode("utf-8", errors="replace")
            steps.append(DecodeStep("Binary decode", decoded, True))
        except Exception:
            steps.append(DecodeStep("Binary decode", "Failed to decode", False))

    return steps


# ---------------- Hash identification ----------------

HASH_PATTERNS = [
    (r"^\$2[aby]\$\d{2}\$.{53}$", "bcrypt"),
    (r"^\$1\$", "MD5 crypt (Unix)"),
    (r"^\$6\$", "SHA-512 crypt (Unix)"),
    (r"^\$5\$", "SHA-256 crypt (Unix)"),
    (r"^[a-fA-F0-9]{32}$", "MD5 or NTLM (32 hex chars — ambiguous by pattern alone)"),
    (r"^[a-fA-F0-9]{40}$", "SHA-1"),
    (r"^[a-fA-F0-9]{56}$", "SHA-224"),
    (r"^[a-fA-F0-9]{64}$", "SHA-256"),
    (r"^[a-fA-F0-9]{96}$", "SHA-384"),
    (r"^[a-fA-F0-9]{128}$", "SHA-512"),
]


def identify_hash(hash_string: str) -> List[str]:
    hash_string = hash_string.strip()
    matches = [name for pattern, name in HASH_PATTERNS if re.match(pattern, hash_string)]
    return matches or ["Unrecognized format — not a common hash pattern"]


def check_common_password_hash(hash_string: str) -> Optional[str]:
    """Checks if the given hash matches md5/sha1/sha256 of a small, well-known
    common-password list. Demonstrates why unsalted hashes of common passwords
    are trivially reversible -- not a general cracking tool."""
    import hashlib
    from modules.aid_box.password_policy_analyzer.analyzer import COMMON_PASSWORDS

    target = hash_string.strip().lower()
    for pwd in COMMON_PASSWORDS:
        for algo_name, algo in (("MD5", hashlib.md5), ("SHA-1", hashlib.sha1), ("SHA-256", hashlib.sha256)):
            if algo(pwd.encode()).hexdigest() == target:
                return f"Matches {algo_name} hash of common password: '{pwd}'"
    return None
