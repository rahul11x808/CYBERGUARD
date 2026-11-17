"""
CyberGuard Module 7: QR Code Generator & Scanner
Uses `qrcode`, `Pillow`, and OpenCV (`cv2.QRCodeDetector`).
Generates QR codes for text, URLs, and Wi-Fi networks.
Decodes QR codes from uploaded images with security risk indicator warnings.
"""
import io
import base64
import ipaddress
import urllib.parse
import qrcode

def generate_qr_code(payload, error_correction='M', box_size=10, border=4):
    """
    Generates a QR code image from payload string and returns base64 PNG data URL.
    """
    if not payload:
        return None

    ec_map = {
        'L': qrcode.constants.ERROR_CORRECT_L,
        'M': qrcode.constants.ERROR_CORRECT_M,
        'Q': qrcode.constants.ERROR_CORRECT_Q,
        'H': qrcode.constants.ERROR_CORRECT_H,
    }

    qr = qrcode.QRCode(
        version=None,
        error_correction=ec_map.get(error_correction.upper(), qrcode.constants.ERROR_CORRECT_M),
        box_size=box_size,
        border=border,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{b64_data}"


def build_wifi_qr_payload(ssid, password="", security_type="WPA", hidden=False):
    """
    Formats standard Wi-Fi configuration string:
    WIFI:T:WPA;S:MySSID;P:MyPassword;H:false;;
    """
    def escape(value):
        return (value.replace('\\', '\\\\').replace(';', '\\;')
                .replace(':', '\\:').replace(',', '\\,'))

    clean_ssid = escape(ssid)
    clean_pass = escape(password)
    h_str = 'true' if hidden else 'false'
    return f"WIFI:T:{security_type};S:{clean_ssid};P:{clean_pass};H:{h_str};;"


def scan_qr_image(uploaded_file):
    """
    Reads an uploaded image and decodes any embedded QR code using OpenCV QRCodeDetector.
    Performs security risk assessment on decoded URL or payload.
    """
    try:
        import cv2
        import numpy as np

        uploaded_file.seek(0)
        try:
            file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
        finally:
            uploaded_file.seek(0)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if img is None:
            return {
                'success': False,
                'error': 'Could not decode image file. Please upload a valid PNG, JPG, or WEBP image.'
            }

        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)

        if not data:
            # Try converting to grayscale and thresholding for low-contrast images
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            data, _, _ = detector.detectAndDecode(gray)

        if not data:
            return {
                'success': False,
                'error': 'No QR code detected in the uploaded image. Please ensure the QR code is clear, well-lit, and uncropped.'
            }

        # Security risk checks
        security_analysis = evaluate_qr_payload(data)

        return {
            'success': True,
            'decoded_text': data,
            'content_type': security_analysis['content_type'],
            'analysis': security_analysis,
        }

    except Exception as e:
        return {
            'success': False,
            'error': f'QR scanning failed: {str(e)}'
        }


def evaluate_qr_payload(text):
    """
    Analyzes decoded payload for indicators of malicious intent or phishing patterns.
    Labels are cautions/indicators, not definitive verdicts.
    """
    warnings = []
    is_url = False
    is_wifi = text.startswith("WIFI:")
    content_type = "Plain Text"

    lower_text = text.lower().strip()

    if is_wifi:
        content_type = "Wi-Fi Configuration"
        warnings.append("NOTICE: This QR code contains wireless network credentials.")
    elif lower_text.startswith(('http://', 'https://', 'ftp://', 'javascript:', 'data:', 'file:')):
        is_url = True
        content_type = "URL Destination"
        try:
            parsed = urllib.parse.urlsplit(text.strip())

            if parsed.scheme != 'https':
                warnings.append(f"UNENCRYPTED PROTOCOL: Uses '{parsed.scheme}://' instead of encrypted 'https://'. Traffic may be intercepted.")

            hostname = parsed.hostname or ''
            try:
                ipaddress.ip_address(hostname)
                warnings.append(f"IP-LITERAL HOST: Points directly to IP address ({hostname}) rather than a registered domain name.")
            except ValueError:
                pass

            if '@' in parsed.netloc:
                warnings.append("EMBEDDED CREDENTIALS: Contains '@' in host, which can disguise the actual destination domain.")

            if parsed.scheme in ('javascript', 'data', 'file'):
                warnings.append(f"HIGH RISK SCHEME: Uses executable scheme '{parsed.scheme}:' which can trigger direct script execution or local file access.")

            try:
                port = parsed.port
            except ValueError:
                warnings.append("MALFORMED URL: Contains an invalid port number.")
            else:
                if port and port not in (80, 443, 8080):
                    warnings.append(f"NON-STANDARD PORT: Connects on uncommon port {port}.")
        except ValueError:
            warnings.append("MALFORMED URL: The destination URL could not be parsed safely.")

    return {
        'content_type': content_type,
        'is_url': is_url,
        'is_wifi': is_wifi,
        'warnings': warnings,
        'has_warnings': len(warnings) > 0,
        'safety_rating': 'Caution Needed' if warnings else 'No High-Risk Patterns Detected'
    }
