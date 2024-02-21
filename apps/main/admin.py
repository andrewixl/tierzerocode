from django.contrib import admin
from .models import Device, IntuneIntegration, IntuneDevice, SophosIntegration, SophosDevice, DefenderIntegration, DefenderDevice, CrowdStrikeIntegration
# CrowdStrikeDevice

admin.site.register(Device)

# Microsoft Intune Models
admin.site.register(IntuneIntegration)
admin.site.register(IntuneDevice)

# Sophos Central Models
admin.site.register(SophosIntegration)
admin.site.register(SophosDevice)

# Defender for Endpoint Models
admin.site.register(DefenderIntegration)
admin.site.register(DefenderDevice)

# CrowdStrike Falcon Models
admin.site.register(CrowdStrikeIntegration)
# admin.site.register(CrowdStrikeDevice)