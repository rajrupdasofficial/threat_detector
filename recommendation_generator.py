def generate_recommendations(features, predicted_vulnerability):
    """Generate security recommendations based on analysis"""
    recommendations = []

    # General recommendations
    if 'security_headers' not in features or not features['security_headers']:
        recommendations.append("Implement security headers (X-Frame-Options, CSP, HSTS)")

    if 'server' in features.get('headers', '').lower():
        recommendations.append("Consider hiding server version information")

    if 'form' in features.get('forms', '').lower():
        recommendations.append("Ensure all forms use HTTPS and proper validation")

    # Vulnerability-specific recommendations
    vuln_lower = predicted_vulnerability.lower()

    if 'injection' in vuln_lower or 'sql' in vuln_lower:
        recommendations.extend([
            "Use parameterized queries to prevent SQL injection",
            "Implement input validation and sanitization",
            "Use ORM frameworks with built-in protection"
        ])

    if 'xss' in vuln_lower or 'scripting' in vuln_lower:
        recommendations.extend([
            "Implement Content Security Policy (CSP)",
            "Sanitize all user inputs before output",
            "Use HTTPOnly and Secure flags for cookies"
        ])

    if 'authentication' in vuln_lower or 'access' in vuln_lower:
        recommendations.extend([
            "Implement multi-factor authentication",
            "Use strong password policies",
            "Implement proper session management"
        ])

    if 'buffer' in vuln_lower or 'overflow' in vuln_lower:
        recommendations.extend([
            "Implement proper input length validation",
            "Use safe string handling functions",
            "Enable compiler-based buffer overflow protections"
        ])

    # Add recommendations from specific checks
    if 'xss_check' in features and 'detected' in features['xss_check'].lower():
        recommendations.append("Escape all user-generated content to prevent XSS")

    if 'ssl_check' in features and 'weak' in features['ssl_check'].lower():
        recommendations.append("Upgrade to stronger SSL ciphers and TLS 1.3")

    if 'script_check' in features and 'mixed content' in features['script_check'].lower():
        recommendations.append("Ensure all scripts are loaded over HTTPS")

    return recommendations[:5]  # Limit to top 5 recommendations
