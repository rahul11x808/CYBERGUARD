"""
CyberGuard Module 6: HTTP Header Viewer & Security Analyzer
Uses Python's `requests`, `socket`, `ipaddress`, and `urllib.parse`.
Blocks hosts with any non-public DNS result and does not follow redirects.
Inspects response headers and evaluates common browser security policies.
"""
import socket
import ipaddress
import urllib.parse
import requests

def is_safe_public_url(url):
    """
    Validates URL scheme and resolves hostname to ensure it does not point
    to localhost, private RFC-1918 networks, link-local, or reserved IPs (SSRF Defense).
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ('http', 'https'):
            return False, "Invalid protocol. Only http:// and https:// URLs are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL does not contain a valid hostname."

        try:
            ip_obj = ipaddress.ip_address(hostname)
            addresses = [ip_obj]
        except ValueError:
            results = socket.getaddrinfo(hostname, parsed.port, type=socket.SOCK_STREAM)
            addresses = [ipaddress.ip_address(result[4][0]) for result in results]
            if not addresses:
                return False, f"DNS resolution failed: Host '{hostname}' returned no addresses."

        for ip_obj in addresses:
            if not ip_obj.is_global:
                return False, f"SSRF PROTECTION: Host resolves to non-public IP ({ip_obj})."

        return True, str(addresses[0])
    except ValueError:
        return False, "URL does not contain a valid hostname or port."
    except socket.gaierror:
        hostname = urllib.parse.urlsplit(url).hostname or '(unknown)'
        return False, f"DNS resolution failed: Host '{hostname}' could not be resolved."


def inspect_http_headers(target_url):
    """
    Fetches headers from an authorized public URL with timeouts and redirect limits.
    Evaluates key security headers: CSP, HSTS, X-Content-Type-Options, Referrer-Policy,
    X-Frame-Options, and Permissions-Policy.
    """
    clean_url = target_url.strip()
    try:
        parsed_url = urllib.parse.urlsplit(clean_url)
    except ValueError as e:
        return {'success': False, 'url': clean_url, 'error': f'Invalid URL: {e}'}
    if not parsed_url.scheme:
        clean_url = 'https://' + clean_url

    # Check SSRF safety
    is_safe, msg = is_safe_public_url(clean_url)
    if not is_safe:
        return {
            'success': False,
            'url': clean_url,
            'error': msg
        }

    try:
        headers_req = {
            'User-Agent': 'CyberGuard-Security-Auditor/1.0 (B.Tech Educational Security Scanner)'
        }
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                clean_url,
                headers=headers_req,
                timeout=5,
                allow_redirects=False,
                stream=True,
            )
            response.close()

        res_headers = dict(response.headers)
        status_code = response.status_code
        status_text = response.reason

        # Security Headers Evaluation
        security_checklist = [
            {
                'header': 'Content-Security-Policy',
                'present': 'Content-Security-Policy' in res_headers,
                'value': res_headers.get('Content-Security-Policy', ''),
                'purpose': 'Restricts sources of executable scripts, stylesheets, and resources to mitigate XSS and data injection.',
                'recommendation': 'Define strict script-src and default-src directives.'
            },
            {
                'header': 'Strict-Transport-Security',
                'present': 'Strict-Transport-Security' in res_headers,
                'value': res_headers.get('Strict-Transport-Security', ''),
                'purpose': 'Enforces HTTPS encryption and protects against SSL-stripping man-in-the-middle attacks.',
                'recommendation': 'Set max-age to at least 31536000 with includeSubDomains.'
            },
            {
                'header': 'X-Content-Type-Options',
                'present': 'X-Content-Type-Options' in res_headers,
                'value': res_headers.get('X-Content-Type-Options', ''),
                'purpose': 'Prevents MIME-sniffing attacks where browsers misinterpret file types as executable.',
                'recommendation': 'Set value to "nosniff".'
            },
            {
                'header': 'X-Frame-Options',
                'present': 'X-Frame-Options' in res_headers or 'Content-Security-Policy' in res_headers and 'frame-ancestors' in res_headers.get('Content-Security-Policy', ''),
                'value': res_headers.get('X-Frame-Options', '(Handled via CSP frame-ancestors)' if 'frame-ancestors' in res_headers.get('Content-Security-Policy', '') else ''),
                'purpose': 'Prevents clickjacking attacks by controlling whether the site can be embedded in an iframe.',
                'recommendation': 'Set to DENY or SAMEORIGIN (or use CSP frame-ancestors).'
            },
            {
                'header': 'Referrer-Policy',
                'present': 'Referrer-Policy' in res_headers,
                'value': res_headers.get('Referrer-Policy', ''),
                'purpose': 'Protects user privacy by controlling how much referrer metadata is sent with outgoing requests.',
                'recommendation': 'Set to "strict-origin-when-cross-origin" or "no-referrer".'
            },
            {
                'header': 'Permissions-Policy',
                'present': 'Permissions-Policy' in res_headers,
                'value': res_headers.get('Permissions-Policy', ''),
                'purpose': 'Restricts access to browser device capabilities like camera, microphone, and geolocation.',
                'recommendation': 'Disable unused browser features explicitly.'
            }
        ]

        present_count = sum(1 for item in security_checklist if item['present'])
        total_count = len(security_checklist)
        score_percent = round((present_count / total_count) * 100)

        return {
            'success': True,
            'url': clean_url,
            'final_url': response.url,
            'status_code': status_code,
            'status_text': status_text,
            'all_headers': sorted(res_headers.items()),
            'security_checklist': security_checklist,
            'present_count': present_count,
            'total_count': total_count,
            'score_percent': score_percent,
        }
    except requests.exceptions.Timeout:
        return {'success': False, 'url': clean_url, 'error': 'Connection timed out after 5 seconds.'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'url': clean_url, 'error': f'Request failed: {str(e)}'}
