"""Malicious URL detection scanner."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import OutputScanner

# URL extraction pattern
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+|"
    r"(?:www\.)[^\s<>\"')\]]+",
    re.IGNORECASE,
)

# Known malicious TLDs and suspicious patterns
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs commonly used for phishing
    ".xyz", ".top", ".work", ".click",   # Frequently abused TLDs
    ".zip", ".mov",                       # Confusing TLDs that mimic file extensions
}

SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "ip_address_url",
        re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        "URL uses raw IP address instead of domain",
    ),
    (
        "homograph",
        re.compile(r"https?://[^\s]*[а-яА-Я\u0400-\u04FF]"),  # Cyrillic chars in URL
        "Possible homograph/IDN attack in URL",
    ),
    (
        "data_uri",
        re.compile(r"data:(?:text|application)/[^;]+;base64,"),
        "Data URI detected (possible payload delivery)",
    ),
    (
        "url_shortener",
        re.compile(
            r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|"
            r"v\.gd|buff\.ly|ow\.ly|rebrand\.ly|short\.io)/",
        ),
        "URL shortener detected (destination unknown)",
    ),
    (
        "excessive_subdomains",
        re.compile(r"https?://(?:[^./]+\.){4,}[^./]+"),
        "Suspicious number of subdomains",
    ),
]


class MaliciousURLScanner(OutputScanner):
    """Detects potentially malicious URLs in LLM output.

    Checks for:
    - Suspicious TLDs commonly used for phishing
    - Raw IP address URLs
    - Homograph/IDN attacks
    - URL shorteners (destination unknown)
    - Data URIs
    - Excessive subdomains
    """

    name = "malicious_url"
    tier = Tier.FAST

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings: list[Finding] = []

        # Extract all URLs
        urls = URL_PATTERN.findall(text)

        for url in urls:
            url_findings = self._check_url(url, text)
            findings.extend(url_findings)

        score = 1.0 if not findings else max(0.0, 1.0 - len(findings) * 0.3)
        passed = len(findings) == 0

        return ScanResult(
            scanner=self.name,
            passed=passed,
            score=score,
            findings=findings,
        )

    def _check_url(self, url: str, full_text: str) -> list[Finding]:
        """Check a single URL for suspicious indicators."""
        findings: list[Finding] = []
        start = full_text.find(url)
        end = start + len(url) if start >= 0 else None

        # Check suspicious TLDs
        try:
            parsed = urlparse(url if url.startswith("http") else f"https://{url}")
            hostname = parsed.hostname or ""
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category="malicious_url",
                            severity="medium",
                            description=f"URL uses suspicious TLD: {tld}",
                            matched_text=url,
                            start=start if start >= 0 else None,
                            end=end,
                            metadata={"tld": tld, "url": url},
                        )
                    )
                    break
        except Exception:
            pass

        # Check suspicious patterns
        for pattern_name, pattern, description in SUSPICIOUS_PATTERNS:
            if pattern.search(url):
                findings.append(
                    Finding(
                        scanner=self.name,
                        category="malicious_url",
                        severity="medium",
                        description=description,
                        matched_text=url,
                        start=start if start >= 0 else None,
                        end=end,
                        metadata={"pattern": pattern_name, "url": url},
                    )
                )

        return findings
