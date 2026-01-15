# Import Dependencies
import requests, time
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, MicrosoftDefenderforEndpointDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *
from apps.code_packages.microsoft import getMicrosoftGraphAccessToken

def _fetch_paginated_data(url, headers, max_retries=5, retry_delay=1):
    """Generic function to fetch paginated data with retry logic."""
    results = []
    while url:
        for attempt in range(max_retries):
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                results.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
                break
            elif response.status_code == 429:  # Throttling error
                retry_after = int(response.headers.get('Retry-After', retry_delay))
                time.sleep(retry_after)
            else:
                raise Exception(f"Failed to fetch data: {response.status_code} - {response.text}")
        else:
            raise Exception("Max retries exceeded while fetching data.")
    return results

######################################## Start Get Microsoft Defender for Endpoint Devices ########################################
def getMicrosoftDefenderforEndpointDevices(access_token):
    """Fetch all enabled Microsoft Defender for Endpoint devices."""
    url = 'https://api.securitycenter.microsoft.com/api/machines'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)
######################################## End Get Microsoft Defender for Endpoint Devices ########################################

######################################## Start Update/Create Microsoft Defender for Endpoint Devices ########################################
def complianceSettings(os_platform):
    try:
        settings = DeviceComplianceSettings.objects.get(os_platform=os_platform)
        return {
            'Cloudflare Zero Trust': settings.cloudflare_zero_trust,
            'CrowdStrike Falcon': settings.crowdstrike_falcon,
            'Microsoft Defender for Endpoint': settings.microsoft_defender_for_endpoint,
            'Microsoft Entra ID': settings.microsoft_entra_id,
            'Microsoft Intune': settings.microsoft_intune,
            'Sophos Central': settings.sophos_central,
            'Qualys': settings.qualys,
        }
    except DeviceComplianceSettings.DoesNotExist:
        return {}
    
def updateMicrosoftDefenderforEndpointDeviceDatabase(json_data):
    for device_data in json_data['value']:
        if device_data.get('onboardingStatus') == 'Onboarded' and not device_data.get('healthStatus') == 'Inactive':
            hostname = (device_data['computerDnsName'].split('.', 1)[0]).lower()
            os_platform = device_data['osPlatform']
            clean_data = cleanAPIData(os_platform)
            
            defaults = {
                'hostname': hostname,
                'osPlatform': clean_data[0],
                'endpointType': clean_data[1],
            }

            obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
            obj.integration.add(Integration.objects.get(integration_type = "Microsoft Defender for Endpoint"))

            enabled_integrations = Integration.objects.filter(enabled=True)
            os_platform = clean_data[0]
            compliance_settings = complianceSettings(os_platform)
            endpoint_data = [
                obj.integration.filter(integration_type=integration.integration_type).exists()
                for integration in enabled_integrations
            ]
            endpoint_match = [
                compliance_settings.get(integration.integration_type)
                for integration in enabled_integrations
            ]
            obj.compliant = endpoint_data == endpoint_match
            obj.save()

            defaults_all = {
                "id": device_data['id'],
                "mergedIntoMachineId": device_data['mergedIntoMachineId'],
                "isPotentialDuplication": device_data['isPotentialDuplication'],
                "isExcluded": device_data['isExcluded'],
                "exclusionReason": device_data['exclusionReason'],
                "computerDnsName": hostname,
                "firstSeen": device_data['firstSeen'],
                "lastSeen": device_data['lastSeen'],
                "osPlatform": device_data['osPlatform'],
                "osVersion": device_data['osVersion'],
                "osProcessor": device_data['osProcessor'],
                "version": device_data['version'],
                "lastIpAddress": device_data['lastIpAddress'],
                "lastExternalIpAddress": device_data['lastExternalIpAddress'],
                "agentVersion": device_data['agentVersion'],
                "osBuild": device_data['osBuild'],
                "healthStatus": device_data['healthStatus'],
                "deviceValue": device_data['deviceValue'],
                "rbacGroupId": device_data['rbacGroupId'],
                "rbacGroupName": device_data['rbacGroupName'],
                "riskScore": device_data['riskScore'],
                "exposureLevel": device_data['exposureLevel'],
                "isAadJoined": device_data['isAadJoined'],
                "aadDeviceId": device_data['aadDeviceId'],
                # "defenderAvStatus": device_data['defenderAvStatus'],
                "onboardingStatus": device_data['onboardingStatus'],
                "osArchitecture": device_data['osArchitecture'],
                "managedBy": device_data['managedBy'],
                "managedByStatus": device_data['managedByStatus'],
                "vmMetadata": device_data['vmMetadata'],
                "parentDevice": obj
            }
            MicrosoftDefenderforEndpointDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)

######################################## End Update/Create Microsoft Defender for Endpoint Devices ########################################

######################################## Start Sync Microsoft Defender for Endpoint ########################################
def syncMicrosoftDefenderforEndpointDevice():
    data = Integration.objects.get(integration_type = "Microsoft Defender for Endpoint")
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Microsoft Defender for Endpoint integration is not properly configured. Missing client_id, client_secret, or tenant_id.")
    
    access_token = getMicrosoftGraphAccessToken(data.client_id, data.client_secret, data.tenant_id, ["https://api.securitycenter.microsoft.com/.default"])
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")
    
    updateMicrosoftDefenderforEndpointDeviceDatabase(getMicrosoftDefenderforEndpointDevices(access_token))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Defender for Endpoint ########################################