# Import Dependencies
import msal, requests, threading, time
from django.utils import timezone
from datetime import datetime
from django.contrib import messages
from django.utils.timezone import make_aware
# Import Models
from ...models import Integration, Device, MicrosoftEntraIDDeviceData, DeviceComplianceSettings, Notification
# Import Function Scripts
from .ReusedFunctions import *
from ....logger.views import createLog

######################################## Start Get Microsoft Entra ID Access Token ########################################
def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
    """Acquire an access token for Microsoft Entra ID using MSAL."""
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://graph.microsoft.com/.default']
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    
    token_result = client.acquire_token_silent(scope, account=None)
    if not token_result:
        token_result = client.acquire_token_for_client(scopes=scope)
    if not token_result or 'access_token' not in token_result:
        raise Exception("Failed to acquire access token")

    access_token = 'Bearer ' + token_result['access_token']
    return access_token
######################################## End Get Microsoft Entra ID Access Token ########################################

######################################## Start Get Microsoft Entra ID Devices ########################################
def getMicrosoftEntraIDDevices(access_token):
    url = 'https://graph.microsoft.com/v1.0/devices'
    headers = {'Authorization': access_token}
    graph_results_clean = []

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch devices: {response.status_code} - {response.text}")
        data = response.json()
        graph_results_clean.extend(data.get('value', []))
        url = data.get('@odata.nextLink')

    return graph_results_clean
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
    for device_data in json_data:
        hostname = device_data['displayName'].lower()
        os_platform = device_data['operatingSystem']
        try:
            manufacturer = (device_data['manufacturer'].lower()).title()
        except:
            manufacturer = None

        clean_data = cleanAPIData(os_platform)

        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
            'manufacturer': manufacturer,
        }
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="Device"))

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
    data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="Device")
    updateMicrosoftEntraIDDeviceDatabase(getMicrosoftEntraIDDevices(getMicrosoftEntraIDAccessToken(data.client_id, data.client_secret, data.tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Entra ID ########################################

######################################## Start Background Sync Microsoft Intune ########################################
def syncMicrosoftEntraIDBackground(request):
    """Run Microsoft Intune device sync in a background thread."""
    def run():
        obj = Notification.objects.create(
                title="Microsoft Entra ID Device Integration Sync",
                status="In Progress",
                created_at=timezone.now(),
                updated_at=timezone.now(),
            )  # type: ignore[attr-defined]
        try:
            messages.info(request, 'Microsoft Entra ID Device Integration Sync in Progress')
            syncMicrosoftEntraID()
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Success","Microsoft Entra ID",request.session.get('user_email', 'unknown'))
            obj.update(status="Success",updated_at=timezone.now())
            messages.info(request, 'Microsoft Entra ID Device Integration Sync Success')
        except Exception as e:
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Failure",f"Microsoft Entra ID - {e}",request.session['user_email'])
            obj.update(status="Failure",updated_at=timezone.now())
            messages.error(request, f'Microsoft Entra ID Device Integration Sync Failed: {e}')
    thread = threading.Thread(target=run)
    thread.start()
######################################## End Background Sync Microsoft Intune ########################################