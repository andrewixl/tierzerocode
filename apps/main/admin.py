from django.contrib import admin
from .models import IntuneIntegration, IntuneDevice

# Microsoft Intune Models
admin.site.register(IntuneIntegration)
admin.site.register(IntuneDevice)