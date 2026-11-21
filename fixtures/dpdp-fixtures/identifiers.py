"""Test fixture containing valid and invalid Indian statutory identifiers for Step 10 DPDP testing."""

# Valid Indian Identifiers
VALID_AADHAAR = "234567890124"  # Passes Verhoeff D5 algorithm
INVALID_AADHAAR_CHECKSUM = "234567890125"  # Fails Verhoeff D5 algorithm
INVALID_AADHAAR_START_0 = "012345678901"  # Cannot start with 0

VALID_PAN = "ABCPE1234F"  # 4th char 'P' = Individual (Person)
VALID_GSTIN = "27ABCPE1234F1Z5"  # Valid format with embedded PAN
VALID_IFSC = "HDFC0001234"
VALID_PHONE = "+91-9876543210"
VALID_UPI = "customer@oksbi"

# Sensitive Categories
HEALTH_RECORD = "Patient has blood_group O+ with chronic diagnosis prescription"
BIOMETRIC_RECORD = "User authentication enabled via iris_scan and fingerprint enrollment"
CHILDREN_RECORD = "minor_consent granted for student child_age 12 years old"
