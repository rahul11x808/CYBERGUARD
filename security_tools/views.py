import json
import urllib.parse
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import ToolActivity, FileRecord, QRScanHistory
from . import password_tools
from . import hash_tools
from . import encryption_tools
from . import qr_tools
from . import metadata_tools
from . import header_tools


# ==============================================================================
# Helper Utilities
# ==============================================================================

def log_activity(user, tool_name, action_summary):
    """Safely log non-sensitive tool usage in the database."""
    try:
        ToolActivity.objects.create(
            user=user if user and user.is_authenticated else None,
            tool_name=tool_name,
            action_summary=action_summary[:255]
        )
    except Exception:
        pass


def parse_request_data(request):
    """Extract parameters from request.POST, request.GET, or JSON body."""
    data = {}
    if request.content_type == 'application/json' and request.body:
        try:
            data = json.loads(request.body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            data = {}
    if not data and request.POST:
        data = request.POST.dict()
    if not data and request.GET:
        data = request.GET.dict()
    return data


# ==============================================================================
# 1. Page Template Views
# ==============================================================================

def password(request):
    return render(request, 'dashboard/password.html')


def file_hash(request):
    return render(request, 'dashboard/file_hash.html')


def text_encryption(request):
    return render(request, 'dashboard/text_encryption.html')


def qr_code(request):
    return render(request, 'dashboard/qr_code.html')


def file_metadata(request):
    return render(request, 'dashboard/file_metadata.html')


def http_header(request):
    return render(request, 'dashboard/http_header.html')


def url_encoder(request):
    return render(request, 'dashboard/url_encoder.html')


# ==============================================================================
# 2. Password Tool APIs
# ==============================================================================

@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_password_generate(request):
    data = parse_request_data(request)
    try:
        length = int(data.get('length', 16))
    except (ValueError, TypeError):
        length = 16

    use_upper = data.get('use_upper', 'true') in (True, 'true', '1', 1)
    use_lower = data.get('use_lower', 'true') in (True, 'true', '1', 1)
    use_digits = data.get('use_digits', 'true') in (True, 'true', '1', 1)
    use_symbols = data.get('use_symbols', 'true') in (True, 'true', '1', 1)
    exclude_ambiguous = data.get('exclude_ambiguous', 'false') in (True, 'true', '1', 1)

    generated = password_tools.generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous
    )
    strength = password_tools.evaluate_password_strength(generated)
    log_activity(request.user, 'Password Tool', f'Generated {len(generated)}-character password')

    return JsonResponse({
        'success': True,
        'password': generated,
        'strength': strength
    })


@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_password_evaluate(request):
    data = parse_request_data(request)
    pwd = data.get('password', '')
    strength = password_tools.evaluate_password_strength(pwd)
    return JsonResponse({
        'success': True,
        'strength': strength
    })


# ==============================================================================
# 3. Text Encryption APIs
# ==============================================================================

@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_encryption_generate_key(request):
    key = encryption_tools.generate_fernet_key()
    log_activity(request.user, 'Encryption Tool', 'Generated Fernet key')
    return JsonResponse({
        'success': True,
        'key': key
    })


@csrf_exempt
@require_http_methods(["POST"])
def api_encryption_encrypt(request):
    data = parse_request_data(request)
    text = data.get('text', '')
    key = data.get('key', '')
    algo = data.get('algorithm', 'fernet').lower()

    if not text:
        return JsonResponse({'success': False, 'error': 'Plaintext cannot be empty.'}, status=400)

    if algo == 'fernet' or algo == 'aes':
        result = encryption_tools.encrypt_text(text, key)
        if result.get('success'):
            log_activity(request.user, 'Encryption Tool', 'Encrypted text with Fernet (AES-128-CBC + HMAC-SHA256)')
        return JsonResponse(result)

    elif algo == 'caesar':
        try:
            shift = int(key) if key else 3
        except ValueError:
            return JsonResponse({'success': False, 'error': 'Caesar cipher key must be an integer (e.g. 3).'}, status=400)
        
        shifted = []
        for ch in text:
            if 'a' <= ch <= 'z':
                shifted.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= ch <= 'Z':
                shifted.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            else:
                shifted.append(ch)
        ciphertext = ''.join(shifted)
        log_activity(request.user, 'Encryption Tool', f'Encrypted text with Caesar cipher (shift={shift})')
        return JsonResponse({
            'success': True,
            'ciphertext': ciphertext,
            'algorithm': f'Caesar Cipher (shift {shift})'
        })

    elif algo == 'sha256':
        hashed = hash_tools.calculate_text_hashes(text)['sha256']
        log_activity(request.user, 'Encryption Tool', 'Generated SHA-256 one-way hash')
        return JsonResponse({
            'success': True,
            'ciphertext': hashed,
            'algorithm': 'SHA-256 One-Way Hash'
        })

    return JsonResponse({'success': False, 'error': f'Unsupported algorithm: {algo}'}, status=400)


@csrf_exempt
@require_http_methods(["POST"])
def api_encryption_decrypt(request):
    data = parse_request_data(request)
    ciphertext = data.get('ciphertext', '')
    key = data.get('key', '')
    algo = data.get('algorithm', 'fernet').lower()

    if not ciphertext:
        return JsonResponse({'success': False, 'error': 'Ciphertext cannot be empty.'}, status=400)

    if algo == 'fernet' or algo == 'aes':
        result = encryption_tools.decrypt_text(ciphertext, key)
        if result.get('success'):
            log_activity(request.user, 'Encryption Tool', 'Decrypted text with Fernet')
        return JsonResponse(result)

    elif algo == 'caesar':
        try:
            shift = int(key) if key else 3
        except ValueError:
            return JsonResponse({'success': False, 'error': 'Caesar cipher key must be an integer (e.g. 3).'}, status=400)
        
        shifted = []
        for ch in ciphertext:
            if 'a' <= ch <= 'z':
                shifted.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
            elif 'A' <= ch <= 'Z':
                shifted.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            else:
                shifted.append(ch)
        plaintext = ''.join(shifted)
        log_activity(request.user, 'Encryption Tool', f'Decrypted Caesar cipher (shift={shift})')
        return JsonResponse({
            'success': True,
            'plaintext': plaintext,
            'authenticated': True
        })

    return JsonResponse({'success': False, 'error': f'Cannot decrypt with {algo}'}, status=400)


# ==============================================================================
# 4. Hash Generator & Integrity Verifier APIs
# ==============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def api_hash_calculate(request):
    expected_hash = request.POST.get('expected_hash', '').strip()

    if 'file' in request.FILES:
        uploaded = request.FILES['file']
        try:
            hashes = hash_tools.calculate_file_hashes(uploaded)
            verification = hash_tools.compare_hashes(hashes['sha256'], expected_hash)
            if not verification['match'] and expected_hash:
                # Also check md5 comparison if sha256 didn't match
                verification_md5 = hash_tools.compare_hashes(hashes['md5'], expected_hash)
                if verification_md5['match']:
                    verification = verification_md5

            # Save FileRecord
            try:
                FileRecord.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    original_name=uploaded.name,
                    sha256_hash=hashes['sha256'],
                    file_size=hashes['size_bytes']
                )
            except Exception:
                pass

            log_activity(request.user, 'File Hash Tool', f'Hashed file: {uploaded.name}')
            return JsonResponse({
                'success': True,
                'filename': uploaded.name,
                'hashes': hashes,
                'verification': verification
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': f'Failed to process file: {str(e)}'}, status=500)

    # Check for text hashing
    data = parse_request_data(request)
    text = data.get('text', '')
    if text:
        hashes = hash_tools.calculate_text_hashes(text)
        verification = hash_tools.compare_hashes(hashes['sha256'], expected_hash)
        log_activity(request.user, 'Text Hash Tool', 'Hashed text input')
        return JsonResponse({
            'success': True,
            'hashes': hashes,
            'verification': verification
        })

    return JsonResponse({'success': False, 'error': 'No file or text was provided for hashing.'}, status=400)


# ==============================================================================
# 5. QR Code Tool APIs
# ==============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def api_qr_generate(request):
    data = parse_request_data(request)
    ctype = data.get('content_type', 'text').lower()

    if ctype == 'wifi':
        ssid = data.get('wifi_name', data.get('ssid', ''))
        pwd = data.get('wifi_password', data.get('password', ''))
        sec = data.get('wifi_security', 'WPA')
        hidden = data.get('wifi_hidden', False) in (True, 'true', '1')
        if not ssid:
            return JsonResponse({'success': False, 'error': 'Wi-Fi SSID is required.'}, status=400)
        payload = qr_tools.build_wifi_qr_payload(ssid=ssid, password=pwd, security_type=sec, hidden=hidden)
    else:
        payload = data.get('content', '').strip()
        if not payload:
            return JsonResponse({'success': False, 'error': 'Content cannot be empty.'}, status=400)

    try:
        data_url = qr_tools.generate_qr_code(payload)
        log_activity(request.user, 'QR Code Tool', f'Generated QR ({ctype})')
        return JsonResponse({
            'success': True,
            'qr_image': data_url,
            'payload': payload,
            'content_type': ctype
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'QR generation failed: {str(e)}'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_qr_scan(request):
    # If image file uploaded
    if 'image' in request.FILES:
        uploaded = request.FILES['image']
        scan_result = qr_tools.scan_qr_image(uploaded)
        if scan_result.get('success'):
            try:
                QRScanHistory.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    content_type=scan_result.get('content_type', 'Unknown'),
                    safe_summary=scan_result.get('decoded_text', '')[:250]
                )
            except Exception:
                pass
            log_activity(request.user, 'QR Code Tool', f"Scanned QR ({scan_result.get('content_type')})")
        return JsonResponse(scan_result)

    # If decoded payload is passed from client-side scanner for security risk evaluation
    data = parse_request_data(request)
    payload = data.get('payload', data.get('decoded_text', '')).strip()
    if payload:
        analysis = qr_tools.evaluate_qr_payload(payload)
        try:
            QRScanHistory.objects.create(
                user=request.user if request.user.is_authenticated else None,
                content_type=analysis.get('content_type', 'Plain Text'),
                safe_summary=payload[:250]
            )
        except Exception:
            pass
        log_activity(request.user, 'QR Code Tool', f"Analyzed QR payload ({analysis.get('content_type')})")
        return JsonResponse({
            'success': True,
            'decoded_text': payload,
            'content_type': analysis.get('content_type'),
            'analysis': analysis
        })

    return JsonResponse({'success': False, 'error': 'No image file or payload text provided.'}, status=400)


# ==============================================================================
# 6. File Metadata Viewer API
# ==============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def api_metadata_extract(request):
    if 'file' not in request.FILES:
        return JsonResponse({'success': False, 'error': 'Please upload a file to analyze its metadata.'}, status=400)

    uploaded = request.FILES['file']
    try:
        metadata = metadata_tools.extract_file_metadata(uploaded)
        log_activity(request.user, 'Metadata Viewer', f'Analyzed metadata: {uploaded.name}')
        return JsonResponse({
            'success': True,
            'metadata': metadata
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Failed to extract metadata: {str(e)}'}, status=500)


# ==============================================================================
# 7. HTTP Header Security Analyzer API
# ==============================================================================

@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_headers_inspect(request):
    data = parse_request_data(request)
    target_url = data.get('url', '').strip()

    if not target_url:
        return JsonResponse({'success': False, 'error': 'Target URL is required.'}, status=400)

    result = header_tools.inspect_http_headers(target_url)
    if result.get('success'):
        log_activity(request.user, 'HTTP Header Tool', f'Analyzed headers: {target_url[:60]} (Score: {result.get("score_percent")}%)')
    return JsonResponse(result)


# ==============================================================================
# 8. URL Encoder / Decoder API
# ==============================================================================

@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_url_process(request):
    data = parse_request_data(request)
    text = data.get('text', '')
    action = data.get('action', 'encode').lower()

    if not text:
        return JsonResponse({'success': False, 'error': 'Input text cannot be empty.'}, status=400)

    try:
        if action == 'decode':
            processed = urllib.parse.unquote(text)
        else:
            processed = urllib.parse.quote(text, safe='/:?=&')
        
        log_activity(request.user, 'URL Tool', f'Processed URL ({action})')
        return JsonResponse({
            'success': True,
            'action': action,
            'result': processed
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Processing failed: {str(e)}'}, status=500)
