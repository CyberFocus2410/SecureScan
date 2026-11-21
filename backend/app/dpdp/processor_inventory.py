"""Third-Party Data Processor & SDK Inventory Scanner (Step 10, DPDP Act 2023 §8(2) & §16)."""
from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DetectedProcessor:
    name: str
    category: str
    data_transferred: List[str]
    country: str
    purpose: str
    cross_border_risk: bool
    source_file: str
    dpdp_citation: str = "Section 8(2) / Section 16"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "data_transferred": self.data_transferred,
            "country": self.country,
            "purpose": self.purpose,
            "cross_border_risk": self.cross_border_risk,
            "source_file": self.source_file,
            "dpdp_citation": self.dpdp_citation,
        }


KNOWN_PROCESSORS: List[Dict[str, Any]] = [
    # Payment Gateways
    {
        "name": "Razorpay",
        "category": "Payment Gateway",
        "keywords": [r"\brazorpay\b", r"razorpay-pod", r"@razorpay/"],
        "data_transferred": ["Customer Name", "Billing Address", "Phone Number", "Email", "Card / UPI Identifiers", "Transaction Amount"],
        "country": "India",
        "purpose": "Payment collection, checkout processing, and refund management",
        "cross_border_risk": False,
    },
    {
        "name": "Cashfree",
        "category": "Payment Gateway",
        "keywords": [r"\bcashfree\b", r"cashfree-sdk"],
        "data_transferred": ["Customer Name", "Phone Number", "Bank Account Details", "Transaction Metadata"],
        "country": "India",
        "purpose": "Payment gateway and payout processing",
        "cross_border_risk": False,
    },
    {
        "name": "PayU",
        "category": "Payment Gateway",
        "keywords": [r"\bpayu\b", r"payumoney", r"payubiz"],
        "data_transferred": ["Customer Name", "Email", "Phone Number", "Payment Credentials"],
        "country": "India",
        "purpose": "Payment gateway processing",
        "cross_border_risk": False,
    },
    {
        "name": "Stripe",
        "category": "Payment Gateway",
        "keywords": [r"\bstripe\b", r"@stripe/"],
        "data_transferred": ["Credit Card Tokens", "Customer Name", "Billing Address", "Email"],
        "country": "United States",
        "purpose": "International payment processing and subscriptions",
        "cross_border_risk": True,
    },
    {
        "name": "PhonePe",
        "category": "Payment Gateway",
        "keywords": [r"\bphonepe\b", r"phonepe-pg"],
        "data_transferred": ["UPI Identifiers", "Phone Number", "Transaction Identifiers"],
        "country": "India",
        "purpose": "Merchant UPI payments and reconciliation",
        "cross_border_risk": False,
    },

    # Analytics & Behavioral Tracking
    {
        "name": "Google Analytics",
        "category": "Product Analytics & Tracking",
        "keywords": [r"\bgoogle-analytics\b", r"\bgtag\b", r"\bga4\b", r"analytics\.js", r"@google-analytics/"],
        "data_transferred": ["Client IP", "Device ID", "User-Agent", "Geolocation", "Pageviews & Behavioral Events"],
        "country": "United States",
        "purpose": "Web traffic analysis and digital engagement telemetry",
        "cross_border_risk": True,
    },
    {
        "name": "Firebase Analytics",
        "category": "Product Analytics & Tracking",
        "keywords": [r"firebase-analytics", r"@firebase/analytics", r"firebase_analytics"],
        "data_transferred": ["Device Identifiers", "App Instance IDs", "In-App Events", "Demographics"],
        "country": "United States",
        "purpose": "Mobile application telemetry and cohort tracking",
        "cross_border_risk": True,
    },
    {
        "name": "Mixpanel",
        "category": "Product Analytics & Tracking",
        "keywords": [r"\bmixpanel\b", r"mixpanel-browser", r"mixpanel-python"],
        "data_transferred": ["Distinct User ID", "Email", "Custom User Properties", "Event Telemetry"],
        "country": "United States",
        "purpose": "Product analytics and user journey funnel analysis",
        "cross_border_risk": True,
    },
    {
        "name": "Amplitude",
        "category": "Product Analytics & Tracking",
        "keywords": [r"\bamplitude\b", r"@amplitude/"],
        "data_transferred": ["User IDs", "Device Identifiers", "Behavioral Session Data"],
        "country": "United States",
        "purpose": "Behavioral analytics and conversion rate tracking",
        "cross_border_risk": True,
    },
    {
        "name": "Segment",
        "category": "Customer Data Platform",
        "keywords": [r"\banalytics\.js\b", r"\bsegment\b", r"@segment/analytics"],
        "data_transferred": ["User Profiles", "Email", "Phone", "Cross-Platform Events"],
        "country": "United States",
        "purpose": "Customer data aggregation and downstream marketing sync",
        "cross_border_risk": True,
    },

    # Communications, SMS & Email
    {
        "name": "Twilio",
        "category": "Communications & Messaging",
        "keywords": [r"\btwilio\b", r"@twilio/"],
        "data_transferred": ["Phone Numbers", "SMS Content", "Call Metadata", "Voice Recordings"],
        "country": "United States",
        "purpose": "SMS delivery, phone verification, and voice communications",
        "cross_border_risk": True,
    },
    {
        "name": "SendGrid",
        "category": "Email Delivery",
        "keywords": [r"\bsendgrid\b", r"@sendgrid/"],
        "data_transferred": ["Email Addresses", "Recipient Names", "Email Body Content"],
        "country": "United States",
        "purpose": "Transactional and marketing email delivery",
        "cross_border_risk": True,
    },
    {
        "name": "Exotel",
        "category": "Communications & Messaging",
        "keywords": [r"\bexotel\b"],
        "data_transferred": ["Phone Numbers", "Call Logs", "SMS Metadata"],
        "country": "India",
        "purpose": "Cloud telephony, customer calls, and OTP delivery",
        "cross_border_risk": False,
    },
    {
        "name": "Gupshup",
        "category": "Communications & Messaging",
        "keywords": [r"\bgupshup\b"],
        "data_transferred": ["Phone Numbers", "WhatsApp Messaging Content", "SMS"],
        "country": "India",
        "purpose": "Conversational messaging and WhatsApp business notifications",
        "cross_border_risk": False,
    },

    # Cloud & Storage
    {
        "name": "Amazon Web Services (AWS)",
        "category": "Cloud Infrastructure",
        "keywords": [r"\bboto3\b", r"@aws-sdk/", r"aws-sdk"],
        "data_transferred": ["Application Data", "Encrypted Backups", "Media Storage"],
        "country": "United States / Global",
        "purpose": "Hosting compute, database storage, and file persistence",
        "cross_border_risk": True,
    },
    {
        "name": "Google Cloud Platform (GCP)",
        "category": "Cloud Infrastructure",
        "keywords": [r"google-cloud-storage", r"@google-cloud/", r"google-cloud-firestore"],
        "data_transferred": ["Application Data", "Blob Objects", "User Records"],
        "country": "United States / Global",
        "purpose": "Cloud compute, database hosting, and object storage",
        "cross_border_risk": True,
    },

    # AI & Model Providers
    {
        "name": "OpenAI",
        "category": "AI / LLM Provider",
        "keywords": [r"\bopenai\b", r"langchain-openai"],
        "data_transferred": ["User Prompts", "Conversational Context", "Document Embeddings"],
        "country": "United States",
        "purpose": "Natural language generation and prompt completion",
        "cross_border_risk": True,
    },
    {
        "name": "Anthropic",
        "category": "AI / LLM Provider",
        "keywords": [r"\banthropic\b", r"@anthropic-ai/"],
        "data_transferred": ["User Prompts", "Contextual Text", "Document Data"],
        "country": "United States",
        "purpose": "LLM text processing and generative intelligence",
        "cross_border_risk": True,
    },
]


class ProcessorInventoryScanner:
    """Scans repository dependencies and source files for third-party data processors."""

    @classmethod
    def scan_worktree(cls, worktree_dir: Path) -> List[DetectedProcessor]:
        processors: Dict[str, DetectedProcessor] = {}
        seen_names: Set[str] = set()

        # 1. Inspect dependency manifests
        manifest_files = [
            "requirements.txt",
            "Pipfile",
            "pyproject.toml",
            "package.json",
            "pom.xml",
            "build.gradle",
        ]

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root or "node_modules" in root or "venv" in root:
                continue

            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")

                if fname in manifest_files or fname.endswith((".py", ".js", ".ts", ".jsx", ".tsx")):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    for proc in KNOWN_PROCESSORS:
                        pname = proc["name"]
                        if pname in seen_names:
                            continue

                        for kw in proc["keywords"]:
                            if re.search(kw, content, re.IGNORECASE):
                                processors[pname] = DetectedProcessor(
                                    name=pname,
                                    category=proc["category"],
                                    data_transferred=proc["data_transferred"],
                                    country=proc["country"],
                                    purpose=proc["purpose"],
                                    cross_border_risk=proc["cross_border_risk"],
                                    source_file=rel_path,
                                )
                                seen_names.add(pname)
                                break

        return list(processors.values())
