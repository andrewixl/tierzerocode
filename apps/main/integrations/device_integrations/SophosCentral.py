# Import Dependencies
import requests
from datetime import datetime
# Import Models
from ...models import Integration, Device, SophosCentralDeviceData, DeviceComplianceSettings
# Import Functions Scripts
from .ReusedFunctions import *

######################################## Start Get Sophos Central Access Token ########################################
def getSophosAccessToken(client_id, client_secret):
    auth_url = 'https://id.sophos.com/api/v2/oauth2/token'
    auth_payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'token'
    }
    try:
        response = requests.post(auth_url, data=auth_payload)
        if response.status_code == 200:
            return 'Bearer ' + response.json()['access_token']
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))
######################################## End Get Sophos Central Access Token ########################################

######################################## Start Get Sophos Central Devices ########################################
def getSophosDevices(access_token, tenant_id):
    url = 'https://api-us03.central.sophos.com/endpoint/v1/endpoints'
    headers = {
        'Authorization': access_token,
        'X-Tenant-ID': tenant_id
    }
    response = requests.get(url=url, headers=headers)
    return response.json()
######################################## End Get Sophos Central Devices ########################################

######################################## Start Update/Create Sophos Central Devices ########################################
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

def updateSophosDeviceDatabase(json_data):
    for device_data in json_data['items']:
        hostname = device_data.get('hostname').lower()
        os_platform = device_data.get('os', {}).get('name')
        clean_data = cleanAPIData(os_platform)
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Sophos Central"))

        enabled_integrations = Integration.objects.filter(enabled=True)
        compliance_settings = complianceSettings(clean_data[0])
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
            "id": device_data.get('id'),
            "type": device_data.get('type'),
            "hostname": hostname,
            "os_isServer": device_data.get('os', {}).get('isServer'),
            "os_platform": device_data.get('os', {}).get('platform'),
            "os_name": device_data.get('os', {}).get('name'),
            "os_majorVersion": device_data.get('os', {}).get('majorVersion'),
            "os_minorVersion": device_data.get('os', {}).get('minorVersion'),
            "os_build": device_data.get('os', {}).get('build'),
            "associatedPerson_name": device_data.get('associatedPerson', {}).get('name'),
            "associatedPerson_viaLogin": device_data.get('associatedPerson', {}).get('viaLogin'),
            "associatedPerson_id": device_data.get('associatedPerson', {}).get('id'),
            "tamperProtectionEnabled": device_data.get('tamperProtectionEnabled'),
            "lastSeenAt": device_data.get('lastSeenAt'),
            "parentDevice": obj
        }
        SophosCentralDeviceData.objects.update_or_create(id=device_data.get('id'), defaults=defaults_all)
######################################## End Update/Create Sophos Central Devices ########################################

######################################## Start Sync Sophos Central ######################################## 
def syncSophos():
    data = Integration.objects.get(integration_type="Sophos Central")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateSophosDeviceDatabase(getSophosDevices(getSophosAccessToken(client_id, client_secret), tenant_id))
    data.last_synced_at = datetime.now()
    data.save()
    print("Sophos Central Synced Successfully")
    return True
######################################## End Sync Sophos Central ########################################
