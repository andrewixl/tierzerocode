from django.contrib import admin
from .models import Device, Integration, MicrosoftEntraIDDevice, IntuneDevice, SophosDevice, DefenderDevice, QualysDevice
# CrowdStrikeDevice

admin.site.register(Device)

# Integration Models
admin.site.register(Integration)

admin.site.register(MicrosoftEntraIDDevice)

# Microsoft Intune Models
admin.site.register(IntuneDevice)

# Sophos Central Models
admin.site.register(SophosDevice)

# Defender for Endpoint Models
admin.site.register(DefenderDevice)

# Defender for Endpoint Models
admin.site.register(QualysDevice)

# CrowdStrike Falcon Models
# admin.site.register(CrowdStrikeDevice)