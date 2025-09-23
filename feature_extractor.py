import requests
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

logger = logging.getLogger(__name__)

# Common vulnerability indicators (fixed regex patterns)
vuln_patterns = {
    'sql_injection': [
        r'mysql_error', r'ora-\d{5}', r'microsoft ole db provider',
        r'unclosed quotation mark', r'syntax error.*query'
    ],
    'xss': [
        r'<script.*?>', r'javascript:', r'onerror=', r'onload=',
        r'alert\(', r'document\.cookie'
    ],
    'path_traversal': [
        r'\.\.//', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e\\'
    ],
    'server_disclosure': [
        r'server:\s*apache/[\d.]+', r'server:\s*nginx/[\d.]+',
        r'server:\s*microsoft-iis/[\d.]+', r'x-powered-by:'
    ],
    'debug_info': [
        r'stack trace', r'debug mode', r'exception.*?at\s',
        r'warning:', r'notice:', r'fatal error'
    ]
}

def extract_website_features(url, session, progress_callback=None):
    """
    Extract comprehensive features from a website that could indicate vulnerabilities
    """
    features = {
        'url_analysis': '',
        'headers': '',
        'content': '',
        'technologies': '',
        'forms': '',
        'links': '',
        'errors': '',
        'security_headers': ''
    }

    feature_steps = [
        "Parsing URL",
        "Fetching content",
        "Analyzing headers",
        "Extracting content",
        "Detecting technologies",
        "Analyzing forms",
        "Scanning links",
        "Checking error patterns"
    ]

    try:
        if progress_callback:
            progress_callback("Parsing URL")

        parsed_url = urlparse(url)
        features['url_analysis'] = f"domain {parsed_url.netloc} path {parsed_url.path} query {parsed_url.query}"

        if progress_callback:
            progress_callback("Fetching content")

        # Make request with timeout
        response = session.get(url, timeout=10, allow_redirects=True, verify=False)

        if progress_callback:
            progress_callback("Analyzing headers")

        # Header Analysis
        headers_text = []
        for key, value in response.headers.items():
            headers_text.append(f"{key.lower()} {value.lower()}")

            # Check for security headers
            if key.lower() in ['x-frame-options', 'x-xss-protection', 'x-content-type-options',
                               'strict-transport-security', 'content-security-policy']:
                features['security_headers'] += f"{key} {value} "

        features['headers'] = ' '.join(headers_text)

        if progress_callback:
            progress_callback("Extracting content")

        # Content Analysis
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')

        # Extract visible text
        visible_text = soup.get_text(separator=' ', strip=True)
        features['content'] = visible_text[:2000]  # Limit content size

        if progress_callback:
            progress_callback("Detecting technologies")

        # Technology Detection
        tech_indicators = []

        # Check for common frameworks/technologies
        if 'wp-content' in content or 'wordpress' in content.lower():
            tech_indicators.append('wordpress')
        if 'drupal' in content.lower():
            tech_indicators.append('drupal')
        if 'joomla' in content.lower():
            tech_indicators.append('joomla')
        if 'react' in content.lower():
            tech_indicators.append('react')
        if 'angular' in content.lower():
            tech_indicators.append('angular')
        if 'vue' in content.lower():
            tech_indicators.append('vue')

        # Check server header
        server = response.headers.get('server', '').lower()
        if server:
            tech_indicators.append(f"server {server}")

        # Check X-Powered-By
        powered_by = response.headers.get('x-powered-by', '').lower()
        if powered_by:
            tech_indicators.append(f"powered-by {powered_by}")

        features['technologies'] = ' '.join(tech_indicators)

        if progress_callback:
            progress_callback("Analyzing forms")

        # Form Analysis
        forms = soup.find_all('form')
        form_analysis = []
        for form in forms:
            method = form.get('method', 'get').lower()
            action = form.get('action', '')
            form_analysis.append(f"form {method} {action}")

            # Check for input fields that might be vulnerable
            inputs = form.find_all(['input', 'textarea'])
            for inp in inputs:
                inp_type = inp.get('type', 'text').lower()
                inp_name = inp.get('name', '').lower()
                form_analysis.append(f"input {inp_type} {inp_name}")

        features['forms'] = ' '.join(form_analysis)

        if progress_callback:
            progress_callback("Scanning links")

        # Link Analysis
        links = soup.find_all('a', href=True)
        link_analysis = []
        for link in links[:50]:  # Limit number of links
            href = link['href'].lower()
            if any(param in href for param in ['id=', 'user=', 'admin', 'login', 'upload']):
                link_analysis.append(f"link {href}")

        features['links'] = ' '.join(link_analysis)

        if progress_callback:
            progress_callback("Checking error patterns")

        # Error Pattern Detection
        error_indicators = []
        content_lower = content.lower()

        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    error_indicators.append(f"{vuln_type} pattern detected")

        features['errors'] = ' '.join(error_indicators)

    except requests.exceptions.RequestException as e:
        logger.warning(f"Request failed for {url}: {e}")
        features['errors'] = f"connection error {str(e)}"
    except Exception as e:
        logger.warning(f"Feature extraction error for {url}: {e}")
        features['errors'] = f"analysis error {str(e)}"

    return features

def features_to_text(features):
    """Convert extracted features to text format similar to training data"""
    text_parts = []

    # Combine all features into a single text
    for key, value in features.items():
        if value:
            text_parts.append(f"{key} {value}")

    combined_text = ' '.join(text_parts)

    # Add some vulnerability-related keywords based on detected patterns
    vuln_keywords = []
    content_lower = combined_text.lower()

    if any(word in content_lower for word in ['sql', 'database', 'mysql', 'error']):
        vuln_keywords.append('database injection vulnerability')

    if any(word in content_lower for word in ['script', 'javascript', 'xss']):
        vuln_keywords.append('cross site scripting vulnerability')

    if any(word in content_lower for word in ['upload', 'file', 'path']):
        vuln_keywords.append('file inclusion vulnerability')

    if any(word in content_lower for word in ['admin', 'login', 'authentication']):
        vuln_keywords.append('authentication bypass vulnerability')

    if vuln_keywords:
        combined_text += ' ' + ' '.join(vuln_keywords)

    return combined_text
