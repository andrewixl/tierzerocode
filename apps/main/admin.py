from django.contrib import admin
from .models import Device, IntuneIntegration, IntuneDevice, SophosIntegration, SophosDevice

admin.site.register(Device)

# Microsoft Intune Models
admin.site.register(IntuneIntegration)
admin.site.register(IntuneDevice)

# Sophos Central Models
admin.site.register(SophosIntegration)
admin.site.register(SophosDevice)