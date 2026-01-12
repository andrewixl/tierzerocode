from ...models import Device

def updateMasterList(devices, tenant_domain):
    # Sets Tenant Domain Suffix for DNS Computer Names
    tenant_domain_suffix = '.' + tenant_domain

    # Iterates through device list for specified function caller (Sophos, Intune, Defender, etc.).
    for device in devices:

        hostname = str(device).lower()
        hostname_without_suffix = hostname[:-len(tenant_domain_suffix)] if hostname.endswith(tenant_domain_suffix) else hostname

        if device.parentDevice is None:
            if len(Device.objects.filter(hostname=hostname_without_suffix)) == 0:
                newDevice = Device.objects.create(hostname=hostname_without_suffix, osPlatform=device.osPlatform, endpointType=device.endpointType)
                device.parentDevice = newDevice
            else:
                device.parentDevice = Device.objects.get(hostname=hostname_without_suffix)
            # Saves changes made to current device.
            device.save()
    return 'Success'