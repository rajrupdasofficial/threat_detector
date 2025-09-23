import requests
import logging
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)

def check_script_issues(url, session):
    """Specific check for script-related issues (e.g., insecure scripts, injection points)"""
    try:
        response = session.get(url, timeout=10, verify=False)
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        content_lower = content.lower()

        # Patterns for script issues
        script_patterns = [
            r'<script[^>]*src=["\']http:',  # Insecure HTTP script src
            r'eval\(', r'document\.write\(', r'innerHTML\s*='  # Dangerous JS methods
        ]

        indicators = []
        for pattern in script_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f"Script issue pattern detected: {pattern}")

        # Check for mixed content (HTTP scripts on HTTPS page)
        if url.startswith('https:'):
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                if script['src'].startswith('http:'):
                    indicators.append(f"Mixed content: HTTP script {script['src']}")

        return ' '.join(indicators) if indicators else "No script issues detected"
    except Exception as e:
        logger.warning(f"Script issues check failed for {url}: {e}")
        return f"Script issues check error: {str(e)}"
