from django.contrib import admin
from .models import ToolActivity, FileRecord, QRScanHistory

@admin.register(ToolActivity)
class ToolActivityAdmin(admin.ModelAdmin):
    list_display = ('tool_name', 'action_summary', 'user', 'created_at')
    list_filter = ('tool_name', 'created_at')
    search_fields = ('tool_name', 'action_summary', 'user__username')
    readonly_fields = ('created_at',)

@admin.register(FileRecord)
class FileRecordAdmin(admin.ModelAdmin):
    list_display = ('original_name', 'sha256_hash', 'file_size', 'user', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('original_name', 'sha256_hash', 'user__username')
    readonly_fields = ('created_at',)

@admin.register(QRScanHistory)
class QRScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('content_type', 'safe_summary', 'user', 'created_at')
    list_filter = ('content_type', 'created_at')
    search_fields = ('content_type', 'safe_summary', 'user__username')
    readonly_fields = ('created_at',)
