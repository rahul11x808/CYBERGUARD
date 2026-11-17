"""
CyberGuard Module 4: File Metadata Viewer
Uses Python's `Pillow` (PIL) and `mimetypes`.
Inspects image dimensions, MIME type, file size, format, and safe EXIF metadata.
Includes privacy warnings regarding metadata exposure.
"""
import mimetypes
from PIL import Image, ExifTags

def extract_file_metadata(uploaded_file):
    """
    Analyzes an uploaded file for MIME type, byte size, and (if image) dimensions and safe EXIF fields.
    """
    filename = uploaded_file.name
    size_bytes = uploaded_file.size

    # Guess MIME type
    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type:
        mime_type = getattr(uploaded_file, 'content_type', 'application/octet-stream')

    metadata = {
        'filename': filename,
        'size_bytes': size_bytes,
        'size_human': format_file_size(size_bytes),
        'mime_type': mime_type,
        'is_image': False,
        'dimensions': None,
        'format': None,
        'mode': None,
        'exif_data': {},
        'has_gps': False,
        'warnings': []
    }

    # If mime suggests image or extension is common image
    is_img_mime = mime_type and mime_type.startswith('image/')
    if is_img_mime:
        try:
            uploaded_file.seek(0)
            img = Image.open(uploaded_file)
            metadata['is_image'] = True
            metadata['format'] = img.format
            metadata['dimensions'] = f"{img.width} x {img.height} pixels"
            metadata['mode'] = img.mode
            metadata['aspect_ratio'] = f"{round(img.width / img.height, 2)}:1" if img.height > 0 else 'N/A'

            # Safe EXIF extraction
            exif_raw = getattr(img, '_getexif', None)
            if callable(exif_raw):
                raw_dict = exif_raw()
                if raw_dict:
                    safe_exif = {}
                    for tag_id, val in raw_dict.items():
                        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                        # Only include safe human-readable non-binary strings
                        if tag_name in ['Make', 'Model', 'DateTime', 'DateTimeOriginal',
                                        'Software', 'Orientation', 'XResolution', 'YResolution',
                                        'ExposureTime', 'FNumber', 'ISOSpeedRatings', 'LensModel']:
                            safe_exif[tag_name] = str(val)[:120]
                        elif tag_name == 'GPSInfo':
                            metadata['has_gps'] = True
                            metadata['warnings'].append(
                                "PRIVACY ALERT: Embedded GPS Geolocation coordinates detected in EXIF! Anyone with this image can pinpoint where it was taken."
                            )

                    metadata['exif_data'] = safe_exif

            if not metadata['warnings'] and metadata['exif_data']:
                metadata['warnings'].append(
                    "NOTICE: Camera make/model and timestamp metadata are present. Consider stripping EXIF before publishing."
                )

        except Exception as e:
            metadata['warnings'].append(f"Image parsing notice: {str(e)}")
        finally:
            uploaded_file.seek(0)

    return metadata


def format_file_size(size_in_bytes):
    """
    Formats byte integer into human-readable string (KB, MB, GB).
    """
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{round(size_in_bytes / 1024, 2)} KB"
    else:
        return f"{round(size_in_bytes / (1024 * 1024), 2)} MB"
