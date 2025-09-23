import ssl
import socket
import logging
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

def check_ssl(url):
    """Specific check for SSL/TLS issues"""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443

        # Add timeout to prevent hanging (10 seconds)
        conn_timeout = 10
        with socket.create_connection((hostname, port), timeout=conn_timeout) as sock:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert is None:
                    return "SSL certificate data unavailable"

                # Check expiration
                if 'notAfter' not in cert:
                    return "SSL certificate expiration data missing"
                expiry_date_str = cert['notAfter']
                try:
                    expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                except ValueError:
                    return f"Invalid expiration date format: {expiry_date_str}"

                days_to_expiry = (expiry_date - datetime.now()).days

                issues = []
                if days_to_expiry < 30:
                    issues.append(f"SSL certificate expires in {days_to_expiry} days")

                # Check for weak ciphers (simplified)
                cipher_info = ssock.cipher()
                if cipher_info is not None:
                    cipher = cipher_info[0]
                    if 'RC4' in cipher or '3DES' in cipher:
                        issues.append(f"Weak cipher detected: {cipher}")

                # Check protocol version
                version = ssock.version()
                if version is not None and version not in ['TLSv1.2', 'TLSv1.3']:
                    issues.append(f"Insecure TLS version: {version}")

                return ' '.join(issues) if issues else "No SSL issues detected"

    except socket.timeout as e:
        logger.warning(f"SSL check timed out for {url}: {e}")
        return "SSL check timed out (connection took too long)"
    except Exception as e:
        logger.warning(f"SSL check failed for {url}: {e}")
        return f"SSL check error: {str(e)}"
