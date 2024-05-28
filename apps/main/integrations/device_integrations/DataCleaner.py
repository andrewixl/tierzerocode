def cleanAPIData(os_platform):
    os_platform_lower = (os_platform).lower()
    if 'server' in os_platform_lower and 'windows' in os_platform_lower:
        osPlatform_clean = 'Windows Server'
        endpointType = 'Server'
    elif 'ubuntu' in os_platform_lower:
        osPlatform_clean  = 'Ubuntu'
        endpointType = 'Server'
    elif 'rhel' in os_platform_lower:
        osPlatform_clean  = 'Red Hat Enterprise Linux'
        endpointType = 'Server'
    elif 'centos' in os_platform_lower:
        osPlatform_clean  = 'CentOS'
        endpointType = 'Server'
    elif 'monterey (12)' in os_platform_lower or 'ventura (13)' in os_platform_lower or 'sonoma (14)' in os_platform_lower:
        osPlatform_clean  = 'MacOS'
        endpointType = 'Client'
    elif 'windows' in os_platform_lower:
        osPlatform_clean  = 'Windows'
        endpointType = 'Client'
    elif 'android' in os_platform_lower:
        osPlatform_clean  = 'Android'
        endpointType = 'Mobile'
    elif 'ios' in os_platform_lower or 'ipados' in os_platform_lower or 'iphone' in os_platform_lower or 'ipad' in os_platform_lower:
        osPlatform_clean = 'iOS/iPadOS'
        endpointType = 'Mobile'
    else:
        osPlatform_clean  = 'Other'
        endpointType = 'Other'
    return [osPlatform_clean, endpointType]