"""Scoped Web Crawler & Asset Discovery Engine (Step 7, ADR-002, Section 4)."""
import logging
import re
import time
from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag
import httpx

from app.core.safe_fetch import is_safe_url
from app.models.models import ScanScopeModel

logger = logging.getLogger(__name__)

HREF_REGEX = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
SCRIPT_SRC_REGEX = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
API_ROUTE_REGEX = re.compile(r"""['"](/(?:api|v[0-9]+|rest|graphql)/[^'"]+)['"]""", re.IGNORECASE)


class CrawledPage:
    def __init__(self, url: str, status_code: int, content_type: str, text: str, headers: Dict[str, str], depth: int):
        self.url = url
        self.status_code = status_code
        self.content_type = content_type
        self.text = text
        self.headers = headers
        self.depth = depth
        self.discovered_links: Set[str] = set()
        self.script_urls: Set[str] = set()
        self.api_endpoints: Set[str] = set()


class ScopedCrawler:
    """
    Safe, rate-limited, scope-enforcing web crawler for single-page applications and multi-page sites.
    Guarantees:
    - Never hits hosts outside allowed_hosts
    - Hard-drops excluded dangerous paths (/logout, /delete, /payment)
    - Enforces max crawl depth and max requests budget
    - Enforces inter-request rate limit delays
    """

    def __init__(
        self,
        base_url: str,
        allowed_hosts: Optional[List[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        max_depth: int = 3,
        max_requests: int = 50,
        requests_per_second: float = 5.0,
        timeout: float = 4.0
    ):
        self.base_url = base_url.strip()
        parsed = urlparse(self.base_url)
        self.target_host = (parsed.hostname or "").lower()

        self.allowed_hosts = [h.lower() for h in (allowed_hosts or [self.target_host])]
        self.allowed_paths = allowed_paths or ["/"]
        self.excluded_paths = [p.lower() for p in (excluded_paths or [
            "/logout", "/signout", "/delete", "/destroy", "/payment",
            "/checkout", "/billing", "/stripe", "/razorpay", "/admin/wipe"
        ])]
        self.max_depth = max_depth
        self.max_requests = min(max_requests, 200)
        self.rate_delay = 1.0 / max(1.0, min(requests_per_second, 20.0))
        self.timeout = timeout

        self.visited_urls: Set[str] = set()
        self.crawled_pages: List[CrawledPage] = []
        self.dropped_safety_paths: List[str] = []

    def is_permitted_url(self, url: str) -> Tuple[bool, str]:
        """Check if URL complies with scope and safety rules."""
        if not url or not isinstance(url, str):
            return False, "Empty URL"

        clean_url, _ = urldefrag(url.strip())
        parsed = urlparse(clean_url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported scheme: {parsed.scheme}"

        host = (parsed.hostname or "").lower()
        if host not in self.allowed_hosts:
            return False, f"Host '{host}' not in allowed scope {self.allowed_hosts}"

        path = parsed.path.lower() or "/"

        # Safety: Hard-drop dangerous destructive or authentication paths
        for ex in self.excluded_paths:
            if ex in path or path.startswith(ex):
                self.dropped_safety_paths.append(clean_url)
                return False, f"Path '{path}' matches dangerous excluded safety rule: {ex}"

        # Allowed paths prefix check
        if self.allowed_paths:
            if not any(path.startswith(ap.lower()) for ap in self.allowed_paths):
                return False, f"Path '{path}' not within allowed path prefixes."

        # Anti-SSRF check
        is_safe, reason = is_safe_url(clean_url, allowed_hosts=self.allowed_hosts)
        if not is_safe:
            return False, f"Anti-SSRF check failed: {reason}"

        return True, "Permitted"

    def crawl(self) -> List[CrawledPage]:
        """Executes breadth-first crawl within defined boundaries."""
        queue: deque[Tuple[str, int]] = deque([(self.base_url, 0)])
        req_count = 0

        with httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "SecureScan-DAST-Crawler/2.0"}
        ) as client:
            while queue and req_count < self.max_requests:
                current_url, depth = queue.popleft()
                clean_url, _ = urldefrag(current_url)

                if clean_url in self.visited_urls:
                    continue

                is_ok, reason = self.is_permitted_url(clean_url)
                if not is_ok:
                    continue

                if depth > self.max_depth:
                    continue

                self.visited_urls.add(clean_url)
                req_count += 1

                try:
                    time.sleep(self.rate_delay)
                    resp = client.get(clean_url)

                    content_type = resp.headers.get("content-type", "").lower()
                    text = resp.text if "text" in content_type or "json" in content_type or "javascript" in content_type else ""

                    page = CrawledPage(
                        url=str(resp.url),
                        status_code=resp.status_code,
                        content_type=content_type,
                        text=text,
                        headers=dict(resp.headers),
                        depth=depth
                    )

                    # Extract links, scripts, and endpoints if HTML/JS
                    if "text/html" in content_type:
                        for match in HREF_REGEX.finditer(text):
                            href = match.group(1).strip()
                            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                                abs_link = urljoin(clean_url, href)
                                page.discovered_links.add(abs_link)
                                if abs_link not in self.visited_urls and depth + 1 <= self.max_depth:
                                    queue.append((abs_link, depth + 1))

                        # Script files
                        for s_match in SCRIPT_SRC_REGEX.finditer(text):
                            s_src = s_match.group(1).strip()
                            if s_src:
                                abs_script = urljoin(clean_url, s_src)
                                page.script_urls.add(abs_script)
                                if abs_script not in self.visited_urls and depth + 1 <= self.max_depth:
                                    queue.append((abs_script, depth + 1))

                    # API routes discovered in text
                    for api_match in API_ROUTE_REGEX.finditer(text):
                        api_p = api_match.group(1).strip()
                        page.api_endpoints.add(api_p)

                    self.crawled_pages.append(page)

                except Exception as exc:
                    logger.debug("Crawling error for %s: %s", clean_url, exc)

        return self.crawled_pages
