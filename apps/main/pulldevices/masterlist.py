from ..models import Device

def updateMasterList(devices, tenant_domain):
    # Sets Tenant Domain Suffix for DNS Computer Names
    tenant_domain_suffix = '.' + tenant_domain

    # Iterates through device list for specified function caller (Sophos, Intune, Defender, etc.).
    for device in devices:

        hostname = str(device).lower()
        hostname_without_suffix = hostname[:-len(tenant_domain_suffix)] if hostname.endswith(tenant_domain_suffix) else hostname
        os_platform_lower = (device.osPlatform).lower()

        if device.parentDevice is None:
            if len(Device.objects.filter(hostname=hostname_without_suffix)) == 0:
                if 'server' in os_platform_lower and 'windows' in os_platform_lower:
                    endpointType = 'Server'
                    osPlatform = 'Windows Server'
                elif 'ubuntu' in os_platform_lower:
                    endpointType = 'Server'
                    osPlatform = 'Ubuntu'
                elif 'windows' in os_platform_lower:
                    endpointType = 'Client'
                    osPlatform = 'Windows'
                elif 'android' in os_platform_lower:
                    endpointType = 'Mobile'
                    osPlatform = 'Android'
                newDevice = Device.objects.create(hostname=hostname_without_suffix, osPlatform=osPlatform, endpointType=endpointType)
                device.parentDevice = newDevice
            else:
                device.parentDevice = Device.objects.get(hostname=hostname_without_suffix)
            # Saves changes made to current device.
            device.save()
    return 'Success'