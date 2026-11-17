"""
CyberGuard Security Tools Database Models
Implements Section 5 of Project Blueprint:
- ToolActivity (Required): Records safe tool activity without storing sensitive data
- FileRecord (Optional): Saves hash verification records
- QRScanHistory (Optional): Records safe scan events
"""
from django.db import models
from django.contrib.auth.models import User

class ToolActivity(models.Model):
    """
    Stores non-sensitive usage metrics and action timestamps.
    NEVER stores plaintext, encryption keys, passwords, or full document content.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities', null=True, blank=True)
    tool_name = models.CharField(max_length=64)
    action_summary = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'Tool Activities'

    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"[{self.created_at.strftime('%Y-%m-%d %H:%M')}] {username} - {self.tool_name}: {self.action_summary}"

class FileRecord(models.Model):
    """
    Stores calculated file hashes and file sizes for audit verification.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='file_records', null=True, blank=True)
    original_name = models.CharField(max_length=255)
    sha256_hash = models.CharField(max_length=64)
    file_size = models.PositiveIntegerField(help_text='File size in bytes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.original_name} ({self.sha256_hash[:12]}...)"

class QRScanHistory(models.Model):
    """
    Stores metadata regarding scanned QR codes without persisting sensitive payload contents.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='qr_scans', null=True, blank=True)
    content_type = models.CharField(max_length=32, help_text='URL, Wi-Fi, or Plain Text')
    safe_summary = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name_plural = 'QR Scan Histories'

    def __str__(self):
        return f"{self.content_type} scan at {self.created_at.strftime('%Y-%m-%d %H:%M')}"
