"""
CyberGuard Module 3: Text Encryption & Decryption
Uses `cryptography.fernet.Fernet` (authenticated symmetric encryption AES-128-CBC + HMAC-SHA256).
Does NOT store keys or plaintext in database or logs.
"""
from cryptography.fernet import Fernet, InvalidToken

def generate_fernet_key():
    """
    Generates a cryptographically strong 32-byte URL-safe base64-encoded Fernet key.
    """
    return Fernet.generate_key().decode('utf-8')


def encrypt_text(plaintext, key_str):
    """
    Encrypts plaintext using Fernet symmetric encryption.
    Returns ciphertext string or error.
    """
    if not plaintext:
        return {'success': False, 'error': 'Plaintext cannot be empty.'}
    if not key_str:
        return {'success': False, 'error': 'Encryption key is required.'}

    try:
        clean_key = key_str.strip().encode('utf-8')
        f = Fernet(clean_key)
        encrypted_bytes = f.encrypt(plaintext.encode('utf-8'))
        return {
            'success': True,
            'ciphertext': encrypted_bytes.decode('utf-8'),
            'algorithm': 'Fernet (AES-128 in CBC mode + HMAC-SHA256 authenticated)'
        }
    except (TypeError, ValueError) as e:
        return {
            'success': False,
            'error': f'Encryption failed: Ensure key is a valid 32-byte base64 string. Details: {str(e)}'
        }


def decrypt_text(ciphertext, key_str):
    """
    Decrypts ciphertext using Fernet.
    Validates HMAC authentication tag to detect any tampering.
    """
    if not ciphertext:
        return {'success': False, 'error': 'Ciphertext cannot be empty.'}
    if not key_str:
        return {'success': False, 'error': 'Decryption key is required.'}

    try:
        clean_key = key_str.strip().encode('utf-8')
        clean_ciphertext = ciphertext.strip().encode('utf-8')
        f = Fernet(clean_key)
        decrypted_bytes = f.decrypt(clean_ciphertext)
        return {
            'success': True,
            'plaintext': decrypted_bytes.decode('utf-8'),
            'authenticated': True
        }
    except InvalidToken:
        return {
            'success': False,
            'error': 'Decryption failed: Invalid key or corrupted/tampered ciphertext. Authenticated encryption tag rejected the token.'
        }
    except (TypeError, ValueError, UnicodeDecodeError) as e:
        return {
            'success': False,
            'error': f'Decryption failed: {str(e)}'
        }

'''
key = generate_fernet_key()
# print(f"Generated Fernet key (keep this secret!): {key}")

encryption_result = encrypt_text("Hello, World!", key)
if encryption_result['success']:
    ciphertext = encryption_result['ciphertext']
    print(f"Ciphertext: {ciphertext}")
else:
    print(f"Encryption error: {encryption_result['error']}")


decryption_result = decrypt_text(ciphertext, key)
if decryption_result['success']:
        plaintext = decryption_result['plaintext']
        print(f"Decrypted plaintext: {plaintext}")
else:
        print(f"Decryption error: {decryption_result['error']}")

'''