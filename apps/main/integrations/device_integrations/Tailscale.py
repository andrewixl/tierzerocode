# Import Dependencies
import requests
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device, TailscaleDeviceData, DeviceComplianceSettings
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *

######################################## Start Get Tailscale Access Token ########################################
def getTailscaleAccessToken(client_id, client_secret):
    auth_url = 'https://api.tailscale.com/api/v2/oauth/token'
    auth_payload = {'client_id': client_id, 'client_secret': client_secret, 'grant_type': 'client_credentials'}
    response = requests.post(auth_url, data=auth_payload)
    if response.status_code == 200:
        access_token = 'Bearer ' + response.json()['access_token']
        return access_token
    else:
        print("Failed to authenticate. Status code:", response.status_code)
        print("Response:", response.text)
        return {'error': response.text}
######################################## End Get Tailscale Access Token ########################################

######################################## Start Get CrowdStrike Falcon Devices ########################################
def getTailscaleDevices(access_token, tenant_domain):
    url = f'https://api.tailscale.com/api/v2/tailnet/{tenant_domain}/devices'
    headers = {'Authorization': access_token}
    return ((requests.get(url=url, headers=headers)).json())['devices']

######################################## End Get CrowdStrike Falcon Devices ########################################

######################################## Start Update/Create CrowdStrike Falcon Devices ########################################
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

def updateTailscaleDeviceDatabase(total_tailscale_results):
    for device_data in total_tailscale_results:
        hostname = device_data.get('hostname').lower()
        os_platform = device_data.get('os')

        clean_data = cleanAPIData(os_platform)
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }

        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Tailscale"))

        enabled_integrations = Integration.objects.filter(enabled=True)
        compliance_settings = complianceSettings(clean_data[0])
        endpoint_data = [obj.integration.filter(integration_type=integration.integration_type).exists() for integration in enabled_integrations]
        endpoint_match = [compliance_settings.get(integration.integration_type) for integration in enabled_integrations]
        obj.compliant = endpoint_data == endpoint_match
        obj.save()

        defaults_all = {
            'id': device_data['id'],
            'nodeId': device_data['nodeId'],
            'hostname': device_data['hostname'],
            'user': device_data['user'],
            'name': device_data['name'],
            'clientVersion': device_data['clientVersion'],
            'updateAvailable': device_data['updateAvailable'],
            'os': device_data['os'],
            'created': device_data['created'],
            'connectedToControl': device_data['connectedToControl'],
            'lastSeen': device_data['lastSeen'],
            'expires': device_data['expires'],
            'keyExpiryDisabled': device_data['keyExpiryDisabled'],
            'authorized': device_data['authorized'],
            'isExternal': device_data['isExternal'],
            'machineKey': device_data['machineKey'],
            'nodeKey': device_data['nodeKey'],
            'tailnetLockKey': device_data['tailnetLockKey'],
            'blocksIncomingConnections': device_data['blocksIncomingConnections'],
            'tailnetLockError': device_data['tailnetLockError'],
            'parentDevice': obj
        }
        TailscaleDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)
######################################## End Update/Create Tailscale Devices ########################################

######################################## Start Sync Tailscale ########################################
def syncTailscaleDevice():
    data = Integration.objects.get(integration_type="Tailscale")
    if not data.client_id or not data.client_secret:
        raise Exception("Tailscale integration is not properly configured. Missing client_id or client_secret.")

    access_token = getTailscaleAccessToken(data.client_id, data.client_secret)
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")

    updateTailscaleDeviceDatabase(getTailscaleDevices(access_token, data.tenant_domain))
    data.last_synced_at = timezone.now()
    data.save()
    return True
