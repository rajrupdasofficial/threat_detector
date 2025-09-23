import requests
import logging
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)

def check_xss(url, session):
    """Specific check for XSS vulnerabilities"""
    try:
        response = session.get(url, timeout=10, verify=False)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        content_lower = content.lower()

        # Patterns for XSS
        xss_patterns = [
            r'<script.*?>', r'javascript:', r'onerror=', r'onload=',
            r'alert\(', r'document\.cookie'
        ]

        indicators = []
        for pattern in xss_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f"XSS pattern detected: {pattern}")

        # Check for reflected XSS test (simple payload test - note: this is non-destructive)
        test_payload = "<script>alert('test')</script>"
        test_url = f"{url}?q={test_payload}" if '?' not in url else f"{url}&q={test_payload}"
        test_response = session.get(test_url, timeout=5, verify=False)
        if test_payload in test_response.text:
            indicators.append("Potential reflected XSS detected")

        return ' '.join(indicators) if indicators else "No XSS issues detected"
    except Exception as e:
        logger.warning(f"XSS check failed for {url}: {e}")
        return f"XSS check error: {str(e)}"
