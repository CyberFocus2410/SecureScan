"""DAST TLS & Cryptographic Protocol Analyzer (Step 7, ADR-002, ASVS 9.1)."""
import logging
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.schemas.enums import Severity, Confidence
from app.scanners.base import RawFinding

logger = logging.getLogger(__name__)


class TlsScanner:
    """Safe, non-destructive TLS, SSL protocol, certificate, and cipher suite analyzer."""

    @staticmethod
    def audit_target_tls(target_url: str, port: int = 443, timeout: float = 3.0) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url

        if parsed.scheme.lower() == "http" and port == 443:
            # If target explicitly uses cleartext HTTP
            findings.append(RawFinding(
                rule_id="dast-tls-plaintext-http",
                title="Application Transmits Cleartext Traffic over HTTP",
                description="Target website accepts unencrypted HTTP connections, allowing eavesdropping and man-in-the-middle tampering.",
                category="crypto",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                file_path=target_url,
                start_line=1,
                end_line=1,
                raw_snippet=f"URL: {target_url} (HTTP scheme without TLS)",
                cwe_ids=["CWE-319"],
                owasp_refs=["A02:2021-Cryptographic Failures"],
                technical_fix="Enforce HTTPS across all application endpoints and implement automatic HTTP-to-HTTPS 301 redirects.",
                validation_steps=f"Curl '{target_url}' and verify redirect to HTTPS scheme."
            ))
            return findings

        # Connect with standard SSL context
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    # 1. Certificate Expiration Check
                    if cert and "notAfter" in cert:
                        # format: 'May 15 12:00:00 2027 GMT'
                        try:
                            exp_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            if exp_date < datetime.utcnow():
                                findings.append(RawFinding(
                                    rule_id="dast-tls-certificate-expired",
                                    title="Expired SSL/TLS Certificate on Target Host",
                                    description=f"Server certificate expired on {cert['notAfter']}. Browsers will display security warnings to users.",
                                    category="crypto",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=f"{host}:{port}",
                                    start_line=1,
                                    end_line=1,
                                    raw_snippet=f"Certificate expired: {cert['notAfter']}",
                                    cwe_ids=["CWE-295"],
                                    owasp_refs=["A02:2021-Cryptographic Failures"],
                                    technical_fix="Renew TLS certificate with an authorized Certificate Authority (CA) e.g. Let's Encrypt.",
                                    validation_steps=f"Inspect certificate using 'openssl s_client -connect {host}:{port}'."
                                ))
                        except Exception:
                            pass

                    # 2. Check for Deprecated TLS Protocol
                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append(RawFinding(
                            rule_id=f"dast-tls-deprecated-protocol-{tls_version.lower()}",
                            title=f"Deprecated and Broken TLS Protocol Supported ({tls_version})",
                            description=f"Server negotiated connection using legacy protocol {tls_version}. Deprecated protocols are vulnerable to POODLE, BEAST, and Sweet32.",
                            category="crypto",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            file_path=f"{host}:{port}",
                            start_line=1,
                            end_line=1,
                            raw_snippet=f"Negotiated protocol: {tls_version}",
                            cwe_ids=["CWE-326", "CWE-327"],
                            owasp_refs=["A02:2021-Cryptographic Failures"],
                            technical_fix="Disable TLS 1.0 and TLS 1.1 on the server or load balancer; permit only TLS 1.2 and TLS 1.3.",
                            validation_steps="Verify server handshake rejects connections with -tls1 and -tls1_1."
                        ))

                    # 3. Check for Weak Ciphers (RC4, 3DES, CBC mode without AEAD)
                    if cipher:
                        cipher_name = cipher[0]
                        if any(w in cipher_name.upper() for w in ["RC4", "3DES", "DES", "EXPORT", "NULL", "MD5", "ADH"]):
                            findings.append(RawFinding(
                                rule_id="dast-tls-weak-cipher-suite",
                                title=f"Weak or Broken Cipher Suite Negotiated ({cipher_name})",
                                description=f"Connection established with weak cipher suite '{cipher_name}', vulnerable to cryptanalytic attacks.",
                                category="crypto",
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                file_path=f"{host}:{port}",
                                start_line=1,
                                end_line=1,
                                raw_snippet=f"Cipher: {cipher_name}",
                                cwe_ids=["CWE-327"],
                                owasp_refs=["A02:2021-Cryptographic Failures"],
                                technical_fix="Configure cipher suite preference to exclusively require modern AEAD ciphers (AES-GCM, CHACHA20-POLY1305).",
                                validation_steps="Test with testssl.sh or sslyze to confirm absence of legacy ciphers."
                            ))

        except ssl.SSLCertVerificationError as cert_err:
            findings.append(RawFinding(
                rule_id="dast-tls-certificate-verification-failed",
                title=f"Invalid or Untrusted SSL/TLS Certificate ({host})",
                description=f"TLS certificate validation failed: {cert_err.verify_message or str(cert_err)}.",
                category="crypto",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                file_path=f"{host}:{port}",
                start_line=1,
                end_line=1,
                raw_snippet=str(cert_err),
                cwe_ids=["CWE-295"],
                owasp_refs=["A02:2021-Cryptographic Failures"],
                technical_fix="Install a valid certificate issued by a trusted public Certificate Authority.",
                validation_steps="Verify openssl s_client returns Verify return code: 0 (ok)."
            ))
        except (socket.timeout, socket.gaierror, ConnectionRefusedError):
            # Target unreachable or offline during test
            pass
        except Exception as exc:
            logger.debug("TLS probe encountered exception on %s: %s", host, exc)

        return findings
