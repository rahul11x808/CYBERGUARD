from django.urls import path
from . import views

app_name = 'security_tools'

urlpatterns = [
    # Page Views
    path('password/', views.password, name='password'),
    path('file_hash/', views.file_hash, name='file_hash'),
    path('text_encryption/', views.text_encryption, name='text_encryption'),
    path('qr_code/', views.qr_code, name='qr_code'),
    path('file_metadata/', views.file_metadata, name='file_metadata'),
    path('http_header/', views.http_header, name='http_header'),
    path('url_encoder/', views.url_encoder, name='url_encoder'),

    # API Endpoints
    # 1. Password
    path('api/password/generate/', views.api_password_generate, name='api_password_generate'),
    path('api/password/evaluate/', views.api_password_evaluate, name='api_password_evaluate'),

    # 2. Encryption
    path('api/encryption/generate-key/', views.api_encryption_generate_key, name='api_encryption_generate_key'),
    path('api/encryption/encrypt/', views.api_encryption_encrypt, name='api_encryption_encrypt'),
    path('api/encryption/decrypt/', views.api_encryption_decrypt, name='api_encryption_decrypt'),

    # 3. Hash
    path('api/hash/calculate/', views.api_hash_calculate, name='api_hash_calculate'),

    # 4. QR Code
    path('api/qr/generate/', views.api_qr_generate, name='api_qr_generate'),
    path('api/qr/scan/', views.api_qr_scan, name='api_qr_scan'),

    # 5. Metadata
    path('api/metadata/extract/', views.api_metadata_extract, name='api_metadata_extract'),

    # 6. HTTP Headers
    path('api/headers/inspect/', views.api_headers_inspect, name='api_headers_inspect'),

    # 7. URL Encoder
    path('api/url/process/', views.api_url_process, name='api_url_process'),
]
