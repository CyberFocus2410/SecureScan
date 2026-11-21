"""SecureScan 2.0 DAST Engine Package."""
from app.dast.crawler import ScopedCrawler, CrawledPage
from app.dast.tls_scanner import TlsScanner
from app.dast.headers_cors import HeadersAndCorsAnalyzer
from app.dast.frontend_tester import FrontendAnalyzer
from app.dast.backend_tester import BackendExposureTester
from app.dast.static_runtime_correlator import StaticRuntimeCorrelator
from app.dast.pipeline import DastPipeline, DastExecutionResult

__all__ = [
    "ScopedCrawler",
    "CrawledPage",
    "TlsScanner",
    "HeadersAndCorsAnalyzer",
    "FrontendAnalyzer",
    "BackendExposureTester",
    "StaticRuntimeCorrelator",
    "DastPipeline",
    "DastExecutionResult"
]
