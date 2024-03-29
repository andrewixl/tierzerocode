from django.contrib import admin
from .models import Device, Integration, DeviceComplianceSettings, CrowdStrikeFalconDevice, MicrosoftEntraIDDevice, IntuneDevice, SophosDevice, DefenderDevice, QualysDevice

# Integration Models
admin.site.register(Integration)
admin.site.register(DeviceComplianceSettings)

# Device Models
admin.site.register(Device)

admin.site.register(CrowdStrikeFalconDevice)
admin.site.register(MicrosoftEntraIDDevice)
admin.site.register(IntuneDevice)
admin.site.register(SophosDevice)
admin.site.register(DefenderDevice)
admin.site.register(QualysDevice)