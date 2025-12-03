from django.contrib import admin
from .models import (
    Device,
    Integration,
    DeviceComplianceSettings,
    MicrosoftEntraIDDeviceData,
    MicrosoftIntuneDeviceData,
    UserData,
    MicrosoftDefenderforEndpointDeviceData,
    CrowdStrikeFalconDeviceData,
    SophosCentralDeviceData,
    CrowdStrikeFalconPreventionPolicy,
    CrowdStrikeFalconPreventionPolicySetting,
    Notification,
)

class UserDataAdmin(admin.ModelAdmin):
    list_display = ('upn', 'uid', 'network_id', 'persona', 'job_title', 'department', 'isAdmin', 'isMfaCapable', 'created_at', 'updated_at')
    list_filter = ('isAdmin', 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable', 'isSsprEnabled', 'department', 'job_title')
    search_fields = ('upn', 'uid', 'network_id', 'persona', 'given_name', 'surname', 'job_title', 'department')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')

# Integration Models
admin.site.register(Integration)
admin.site.register(DeviceComplianceSettings)

# Device Models
admin.site.register(Device)
admin.site.register(CrowdStrikeFalconDeviceData)
admin.site.register(MicrosoftDefenderforEndpointDeviceData)
admin.site.register(MicrosoftEntraIDDeviceData)
admin.site.register(MicrosoftIntuneDeviceData)
admin.site.register(SophosCentralDeviceData)
admin.site.register(UserData, UserDataAdmin)

# CS Health Check
admin.site.register(CrowdStrikeFalconPreventionPolicy)
admin.site.register(CrowdStrikeFalconPreventionPolicySetting)

class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at', 'updated_at')
    search_fields = ('title', 'status')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Notification Details', {
            'fields': ('title', 'status')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

admin.site.register(Notification, NotificationAdmin)
