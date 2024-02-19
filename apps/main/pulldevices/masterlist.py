from ..models import Device

def updateMasterList(devices, tenant_domain):
    for device in devices:
        hostname = str(device).lower()
        hostname_without_suffix = hostname[:-(len(tenant_domain)+1)] if hostname.endswith('.' + tenant_domain) else hostname
        if device.parentDevice is None:
            if len(Device.objects.filter(hostname=hostname_without_suffix)) == 0:
                newDevice = Device.objects.create(hostname=hostname_without_suffix)
                device.parentDevice = newDevice
            else:
                device.parentDevice = Device.objects.get(hostname=hostname_without_suffix)
            device.save()
    return 'Success'