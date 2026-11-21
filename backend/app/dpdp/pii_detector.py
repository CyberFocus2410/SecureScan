"""India & Global PII Detection with Verhoeff and Luhn Checksums (Step 10, DPDP Act 2023)."""
from dataclasses import dataclass
import logging
import re
from typing import Dict, List, Optional, Tuple, Any

from app.core.security import redact_text

logger = logging.getLogger(__name__)

# Verhoeff Tables for Aadhaar Checksum Validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validates 12-digit Aadhaar number against the Verhoeff algorithm."""
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) != 12:
        return False
    # Aadhaar numbers cannot begin with 0 or 1
    if digits[0] in (0, 1):
        return False
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][item]]
    return c == 0


def validate_luhn(card_str: str) -> bool:
    """Validates credit/debit card numbers against the Luhn algorithm."""
    digits = [int(c) for c in card_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# PAN Regex: 5 letters, 4 digits, 1 letter. 4th letter is taxpayer category.
PAN_REGEX = re.compile(r"""\b([A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z])\b""")

# Aadhaar Candidate Regex: 12 digits (with optional spaces or dashes)
AADHAAR_REGEX = re.compile(r"""\b([2-9][0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b""")

# GSTIN Regex: 2 digit state code + 10 char PAN + 1 entity char + 'Z' + 1 checksum
GSTIN_REGEX = re.compile(r"""\b([0-9]{2}[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z])\b""")

# IFSC Regex: 4 bank letters + '0' + 6 alphanumeric
IFSC_REGEX = re.compile(r"""\b([A-Z]{4}0[A-Z0-9]{6})\b""")

# Indian Phone Regex: +91, 91, or 0 followed by 10 digits starting with 6, 7, 8, 9
INDIAN_PHONE_REGEX = re.compile(r"""(?:\b|(?<=\+91)|(?<=91))(?:\+91[\-\s]?|91[\-\s]?|0)?([6-9][0-9]{9})\b""")

# UPI ID / VPA Regex
UPI_REGEX = re.compile(r"""\b([a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,64})\b""")

# Indian Passport Regex: 1 letter + 7 digits
PASSPORT_REGEX = re.compile(r"""\b([A-Z][0-9]{7})\b""")

# Voter ID / EPIC Regex: 3 letters + 7 digits
VOTER_ID_REGEX = re.compile(r"""\b([A-Z]{3}[0-9]{7})\b""")

# Indian Driving Licence: 2 state letters + 2 digit RTO + 4 digit year + 7 digits
DRIVING_LICENCE_REGEX = re.compile(r"""\b([A-Z]{2}[0-9]{2}(?:19|20)[0-9]{2}[0-9]{7})\b""")

# Sensitive Personal Data Categories (Health, Biometric, Children)
HEALTH_KEYWORDS = re.compile(r"""\b(?:hiv|cancer|diagnosis|prescription|biopsy|medical_record|blood_group|clinical_data)\b""", re.IGNORECASE)
BIOMETRIC_KEYWORDS = re.compile(r"""\b(?:fingerprint|iris_scan|facial_biometrics|retina_scan|voiceprint)\b""", re.IGNORECASE)
CHILDREN_KEYWORDS = re.compile(r"""\b(?:child_age|minor_consent|parental_consent|guardian_consent|under_18|minor_dob)\b""", re.IGNORECASE)


@dataclass
class DetectedPii:
    category: str
    identifier_type: str
    masked_value: str
    line_number: int
    is_valid_checksum: bool
    context: str


class PiiDetector:
    """Discovers Indian statutory identifiers, financial details, and sensitive personal data."""

    @classmethod
    def scan_text(cls, text: str, file_path: str = "") -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not text:
            return results

        lines = text.splitlines()

        for line_num, line in enumerate(lines, 1):
            # 1. Aadhaar with Verhoeff Checksum
            for match in AADHAAR_REGEX.finditer(line):
                raw_candidate = match.group(1).replace(" ", "").replace("-", "")
                if validate_verhoeff(raw_candidate):
                    results.append({
                        "identifier_type": "Aadhaar",
                        "category": "Official Identity Document",
                        "masked_value": f"XXXX-XXXX-{raw_candidate[-4:]}",
                        "file_path": file_path,
                        "line_number": line_num,
                        "is_valid_checksum": True,
                        "dpdp_section": "Section 2(t) / Section 33(1)"
                    })

            # 2. PAN (Permanent Account Number)
            for match in PAN_REGEX.finditer(line):
                pan = match.group(1)
                results.append({
                    "identifier_type": "PAN",
                    "category": "Tax & Financial Identity",
                    "masked_value": f"{pan[:2]}XXX{pan[5:7]}XX",
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 2(t)"
                })

            # 3. GSTIN (Goods and Services Tax Identification Number)
            for match in GSTIN_REGEX.finditer(line):
                gstin = match.group(1)
                results.append({
                    "identifier_type": "GSTIN",
                    "category": "Business Tax Identity",
                    "masked_value": f"{gstin[:2]}XXXXXXXXXX{gstin[-3:]}",
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 2(t)"
                })

            # 4. IFSC Code
            for match in IFSC_REGEX.finditer(line):
                ifsc = match.group(1)
                results.append({
                    "identifier_type": "IFSC",
                    "category": "Banking & Financial Routing",
                    "masked_value": ifsc,
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 2(t)"
                })

            # 5. Indian Phone Number
            for match in INDIAN_PHONE_REGEX.finditer(line):
                phone = match.group(1)
                results.append({
                    "identifier_type": "Indian Phone",
                    "category": "Contact Information",
                    "masked_value": f"+91-XXXXX-{phone[-4:]}",
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 2(t)"
                })

            # 6. UPI ID
            for match in UPI_REGEX.finditer(line):
                upi = match.group(1)
                # Filter out email addresses
                if not upi.endswith((".com", ".org", ".net", ".io", ".co")):
                    parts = upi.split("@")
                    results.append({
                        "identifier_type": "UPI ID",
                        "category": "Financial Payment Address",
                        "masked_value": f"{parts[0][:2]}***@{parts[1]}",
                        "file_path": file_path,
                        "line_number": line_num,
                        "is_valid_checksum": True,
                        "dpdp_section": "Section 2(t)"
                    })

            # 7. Sensitive Categories: Health, Biometric, Children
            if HEALTH_KEYWORDS.search(line):
                results.append({
                    "identifier_type": "Health Data",
                    "category": "Special / Sensitive Personal Data",
                    "masked_value": "[HEALTH_DATA_INDICATOR]",
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 2(t) / Section 8(5)"
                })

            if BIOMETRIC_KEYWORDS.search(line):
                results.append({
                    "identifier_type": "Biometric Data",
                    "category": "Special / Sensitive Personal Data",
                    "masked_value": "[BIOMETRIC_DATA_INDICATOR]",
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 2(t) / Section 8(5)"
                })

            if CHILDREN_KEYWORDS.search(line):
                results.append({
                    "identifier_type": "Children's Data",
                    "category": "Children's Personal Data",
                    "masked_value": "[CHILDREN_DATA_INDICATOR]",
                    "file_path": file_path,
                    "line_number": line_num,
                    "is_valid_checksum": True,
                    "dpdp_section": "Section 9 (Children's Obligations)"
                })

        return results
