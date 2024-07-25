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
)

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
admin.site.register(UserData)

# CS Health Check
admin.site.register(CrowdStrikeFalconPreventionPolicy)
admin.site.register(CrowdStrikeFalconPreventionPolicySetting)
