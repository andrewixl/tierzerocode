from django.contrib import admin
from .models import Log

# Customize the admin interface for the Log model
class LogAdmin(admin.ModelAdmin):
    # Specify the fields to display in the table
    list_display = ('id', 'event_code', 'event_type', 'event_group', 'user_level', 'privileged', 'action', 'outcome', 'additional_data', 'created_at', 'user_id')
    # Add search functionality
    search_fields = ('event_code', 'event_type', 'event_group', 'action', 'user_id')
    # Add filters
    list_filter = ('event_type', 'event_group', 'user_level', 'privileged', 'outcome', 'created_at')
    # Enable ordering
    ordering = ('-created_at',)  # Order by created_at descending

# Register the Log model with the customized admin
admin.site.register(Log, LogAdmin)