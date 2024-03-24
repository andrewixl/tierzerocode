from django.contrib import admin
from .models import Device, Integration, IntuneDevice, SophosDevice, DefenderDevice
# CrowdStrikeDevice

admin.site.register(Device)

# Integration Models
admin.site.register(Integration)

# Microsoft Intune Models
admin.site.register(IntuneDevice)

# Sophos Central Models
admin.site.register(SophosDevice)

# Defender for Endpoint Models
admin.site.register(DefenderDevice)

# CrowdStrike Falcon Models
# admin.site.register(CrowdStrikeDevice)