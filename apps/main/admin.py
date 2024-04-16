from django.contrib import admin
# from .models import Device, Integration, DeviceComplianceSettings, CrowdStrikeFalconDevice, MicrosoftEntraIDDevice, IntuneDevice, SophosDevice, DefenderDevice, QualysDevice
from .models import Device, Integration, DeviceComplianceSettings, MicrosoftEntraIDDeviceData, MicrosoftIntuneDeviceData


# Integration Models
admin.site.register(Integration)
admin.site.register(DeviceComplianceSettings)

# Device Models
admin.site.register(Device)

# admin.site.register(CrowdStrikeFalconDevice)
admin.site.register(MicrosoftEntraIDDeviceData)
admin.site.register(MicrosoftIntuneDeviceData)
# admin.site.register(SophosDevice)
# admin.site.register(DefenderDevice)
# admin.site.register(QualysDevice)