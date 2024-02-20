from ..models import Device

def updateMasterList(devices, tenant_domain):
    for device in devices:
        hostname = str(device).lower()
        hostname_without_suffix = hostname[:-(len(tenant_domain)+1)] if hostname.endswith('.' + tenant_domain) else hostname
        if device.parentDevice is None:
            if len(Device.objects.filter(hostname=hostname_without_suffix)) == 0:
                if 'server' in (device.osPlatform).lower():
                    endpointType = 'SERVER'
                elif 'ubuntu' in (device.osPlatform).lower():
                    endpointType = 'SERVER'
                elif 'windows' in (device.osPlatform).lower():
                    endpointType = 'CLIENT'
                elif 'android' in (device.osPlatform).lower():
                    endpointType = 'MOBILE'
                newDevice = Device.objects.create(hostname=hostname_without_suffix, osPlatform=device.osPlatform, endpointType=endpointType)
                device.parentDevice = newDevice
            else:
                device.parentDevice = Device.objects.get(hostname=hostname_without_suffix)
            device.save()
    return 'Success'