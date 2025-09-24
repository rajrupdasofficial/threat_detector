import requests
import logging
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)

def check_xss(url, session):
    """Robust XSS vulnerability checker"""
    try:
        response = session.get(url, timeout=10, verify=False)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        content_lower = content.lower()
        indicators = []

        # Pattern-based static checks
        xss_patterns = [
            r'<script.*?>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'alert\s*\(',
            r'document\.cookie',
            r'<img[^>]+src\s*=',
            r'<iframe.*?>',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'onfocus\s*=',
            r'oninput\s*=',
            r'onchange\s*='
        ]
        for pattern in xss_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f"Pattern detected: {pattern}")

        # Scan inline event handler attributes
        for tag in soup.find_all(['a', 'img', 'button', 'input']):
            for attr in tag.attrs:
                if attr.lower().startswith('on'):
                    indicators.append(f"Inline JavaScript event handler found: {attr}")

        # Flag forms with suspicious fields
        forms = soup.find_all('form')
        for form in forms:
            for field in form.find_all(['input', 'textarea']):
                input_type = field.get('type', '')
                # Look for dangerous input types or names
                if input_type in ['text', 'search', 'password']:
                    indicators.append("Unprotected user input detected (text/search/password)")

        # Scan for HTTP links with javascript: URIs
        for a in soup.find_all('a', href=True):
            if a['href'].strip().lower().startswith('javascript:'):
                indicators.append('javascript: URI detected in anchor tag')

        # Active reflected XSS testing on all input names
        test_payload = "<svg/onload=alert('XSS_')>"
        fields_tested = 0
        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()

            params = {}
            for inp in form.find_all('input'):
                name = inp.get('name')
                if name:
                    params[name] = test_payload
                    fields_tested += 1

            # Only test if form has input fields
            if params:
                if method == 'post':
                    test_resp = session.post(action, data=params, timeout=5, verify=False)
                else:
                    test_resp = session.get(action, params=params, timeout=5, verify=False)
                if test_payload in test_resp.text:
                    indicators.append('Potential reflected XSS detected in form ({})'.format(action))

        # Simple static reflected XSS test for common URL parameter
        static_test_url = url
        if '?' not in url:
            static_test_url += "?q=" + test_payload
        else:
            static_test_url += "&q=" + test_payload
        test_response = session.get(static_test_url, timeout=5, verify=False)
        if test_payload in test_response.text:
            indicators.append("Potential reflected XSS via ?q= param")

        # Summarize results
        if indicators:
            return 'Possible XSS risk(s) detected: ' + '; '.join(set(indicators))
        else:
            return "No XSS issues detected"
    except Exception as e:
        logger.warning(f"XSS check failed for {url}: {e}")
        return f"XSS check error: {str(e)}"
