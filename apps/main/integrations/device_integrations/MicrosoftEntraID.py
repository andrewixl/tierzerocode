# Import Dependencies
import msal, requests, logging
from django.utils import timezone
# Import Models
from ...models import Integration, Device, MicrosoftEntraIDDeviceData, DeviceComplianceSettings
# Import Function Scripts
from .ReusedFunctions import *

# Set the logger
# logger = logging.getLogger('custom_logger')

######################################## Start Get Microsoft Entra ID Access Token ########################################
def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
    authority = 'https://login.microsoftonline.com/' + tenant_id
    scope = ['https://graph.microsoft.com/.default']
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    token_result = client.acquire_token_silent(scope, account=None)
    if token_result:
        access_token = 'Bearer ' + token_result['access_token']
        logger.info('Access token was loaded from cache')
    if not token_result:
        token_result = client.acquire_token_for_client(scopes=scope)
        access_token = 'Bearer ' + token_result['access_token']
        logger.info('New access token was acquired from Azure AD')
    return access_token
######################################## End Get Microsoft Entra ID Access Token ########################################

######################################## Start Get Microsoft Entra ID Devices ########################################
def getMicrosoftEntraIDDevices(access_token):
    url = 'https://graph.microsoft.com/v1.0/devices'
    headers = {'Authorization': access_token}
    graph_result = requests.get(url=url, headers=headers)
    return graph_result.json()
######################################## End Get Microsoft Entra ID Devices ########################################

######################################## Start Update/Create Microsoft Entra ID Devices ########################################
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

def updateMicrosoftEntraIDDeviceDatabase(json_data):
    for device_data in json_data['value']:
        hostname = device_data['displayName'].lower()
        os_platform = device_data['operatingSystem']
        try:
            manufacturer = (device_data['manufacturer'].lower()).title()
        except:
            print(hostname + " does not have a manufacturer")
            manufacturer = None

        clean_data = cleanAPIData(os_platform)

        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
            'manufacturer': manufacturer,
        }
        if not clean_data[1] == 'Mobile' and not device_data['deviceOwnership'] == 'Company':
            continue

        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Microsoft Entra ID"))

        enabled_integrations = Integration.objects.filter(enabled=True)
        compliance_settings = complianceSettings(clean_data[0])
        endpoint_data = [obj.integration.filter(integration_type=integration.integration_type).exists() for integration in enabled_integrations]
        endpoint_match = [compliance_settings.get(integration.integration_type) for integration in enabled_integrations]
        obj.compliant = endpoint_data == endpoint_match
        obj.save()

        defaults_all = {
            "id": device_data['id'],
            "deletedDateTime": device_data.get('deletedDateTime'),
            "accountEnabled": device_data.get('accountEnabled'),
            "approximateLastSignInDateTime": device_data.get('approximateLastSignInDateTime'),
            "complianceExpirationDateTime": device_data.get('complianceExpirationDateTime'),
            "createdDateTime": device_data.get('createdDateTime'),
            "deviceCategory": device_data.get('deviceCategory'),
            "deviceId": device_data.get('deviceId'),
            "deviceMetadata": device_data.get('deviceMetadata'),
            "deviceOwnership": device_data.get('deviceOwnership'),
            "deviceVersion": device_data.get('deviceVersion'),
            "displayName": hostname,
            "domainName": device_data.get('domainName'),
            "enrollmentProfileName": device_data.get('enrollmentProfileName'),
            "enrollmentType": device_data.get('enrollmentType'),
            "externalSourceName": device_data.get('externalSourceName'),
            "isCompliant": device_data.get('isCompliant'),
            "isManaged": device_data.get('isManaged'),
            "isRooted": device_data.get('isRooted'),
            "managementType": device_data.get('managementType'),
            "manufacturer": device_data.get('manufacturer'),
            "mdmAppId": device_data.get('mdmAppId'),
            "model": device_data.get('model'),
            "onPremisesLastSyncDateTime": device_data.get('onPremisesLastSyncDateTime'),
            "onPremisesSyncEnabled": device_data.get('onPremisesSyncEnabled'),
            "operatingSystem": device_data.get('operatingSystem'),
            "operatingSystemVersion": device_data.get('operatingSystemVersion'),
            "profileType": device_data.get('profileType'),
            "registrationDateTime": device_data.get('registrationDateTime'),
            "sourceType": device_data.get('sourceType'),
            "trustType": device_data.get('trustType'),
            "parentDevice": obj
        }
        MicrosoftEntraIDDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)
######################################## End Update/Create Microsoft Entra ID Devices ########################################

######################################## Start Sync Microsoft Entra ID ########################################
def syncMicrosoftEntraID():
    data = Integration.objects.get(integration_type="Microsoft Entra ID")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateMicrosoftEntraIDDeviceDatabase(getMicrosoftEntraIDDevices(getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()
    print("Microsoft Entra ID Synced Successfully")
    return True
######################################## End Sync Microsoft Entra ID ########################################
