"""
CyberGuard Module 2: File & Text Hash Generator
Uses Python's built-in `hashlib`.
Calculates SHA-256 (standard) and MD5 (educational comparison).
Provides hash comparison and integrity verification.
"""
import hashlib

def calculate_file_hashes(uploaded_file):
    """
    Reads a seekable binary file in memory-efficient 64KB chunks and computes SHA-256 and MD5.
    Returns sha256, md5, and total bytes read.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    total_size = 0

    uploaded_file.seek(0)
    try:
        while chunk := uploaded_file.read(65536):
            sha256.update(chunk)
            md5.update(chunk)
            total_size += len(chunk)
    finally:
        uploaded_file.seek(0)

    return {
        'sha256': sha256.hexdigest(),
        'md5': md5.hexdigest(),
        'size_bytes': total_size,
    }


def calculate_text_hashes(text_input):
    """
    Computes SHA-256 and MD5 hashes of a text string.
    """
    encoded = text_input.encode('utf-8')
    return {
        'sha256': hashlib.sha256(encoded).hexdigest(),
        'md5': hashlib.md5(encoded).hexdigest(),
        'size_bytes': len(encoded)
    }


def compare_hashes(calculated_hash, expected_hash):
    """
    Compares two hashes case-insensitively and returns comparison result.
    """
    if not expected_hash:
        return {
            'checked': False,
            'match': None,
            'message': 'No reference hash was provided for comparison.'
        }

    clean_expected = expected_hash.strip().lower()
    clean_calc = calculated_hash.strip().lower()

    if clean_calc == clean_expected:
        return {
            'checked': True,
            'match': True,
            'message': 'INTEGRITY VERIFIED: Hashes match exactly! The file or text content is intact and unmodified.'
        }
    else:
        return {
            'checked': True,
            'match': False,
            'message': 'MISMATCH WARNING: Hashes do NOT match! The file has been modified, corrupted, or does not originate from the expected source.'
        }
