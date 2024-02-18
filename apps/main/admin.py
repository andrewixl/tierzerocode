from django.contrib import admin
from .models import IntuneIntegration, IntuneDevice, SophosIntegration, SophosDevice

# Microsoft Intune Models
admin.site.register(IntuneIntegration)
admin.site.register(IntuneDevice)

# Sophos Central Models
admin.site.register(SophosIntegration)
admin.site.register(SophosDevice)