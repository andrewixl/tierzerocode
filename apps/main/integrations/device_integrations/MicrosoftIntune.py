# Import Dependencies
import msal, requests, threading, time
from django.utils import timezone
from datetime import datetime
from django.contrib import messages
from django.utils.timezone import make_aware
# Import Models
from ...models import Integration, Device, MicrosoftIntuneDeviceData, DeviceComplianceSettings, Notification
# Import Function Scripts
from .ReusedFunctions import *
from ....logger.views import createLog

######################################## Start Get Microsoft Intune Access Token ########################################
def getMicrosoftIntuneAccessToken(client_id, client_secret, tenant_id):
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
######################################## End Get Microsoft Intune Access Token ########################################

######################################## Start Get Microsoft Intune Devices ########################################
def getMicrosoftIntuneDevices(access_token):
    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
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
######################################## End Get Microsoft Intune Devices ########################################

######################################## Start Update/Create Microsoft Intune Devices ########################################
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

def updateMicrosoftIntuneDeviceDatabase(json_data):
    for device_data in json_data:
        hostname = device_data['deviceName'].lower()
        os_platform = device_data['operatingSystem']
        manufacturer = device_data['manufacturer'].lower()  
        clean_data = cleanAPIData(os_platform)

        if clean_data[0] == "Android":
            hostname = device_data['id'].lower()

        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
            'manufacturer': (manufacturer.lower()).title()
        }
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type="Microsoft Intune"))

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
            "id": device_data['id'],
            "userId": device_data['userId'],
            "deviceName": hostname,
            "managedDeviceOwnerType": device_data['managedDeviceOwnerType'],
            "enrolledDateTime": device_data['enrolledDateTime'],
            "lastSyncDateTime": device_data['lastSyncDateTime'],
            "operatingSystem": device_data['operatingSystem'],
            "complianceState": device_data['complianceState'],
            "jailBroken": device_data['jailBroken'],
            "managementAgent": device_data['managementAgent'],
            "osVersion": device_data['osVersion'],
            "easActivated": device_data['easActivated'],
            "easDeviceId": device_data['easDeviceId'],
            "easActivationDateTime": device_data['easActivationDateTime'],
            "azureADRegistered": device_data['azureADRegistered'],
            "deviceEnrollmentType": device_data['deviceEnrollmentType'],
            "activationLockBypassCode": device_data['activationLockBypassCode'],
            "emailAddress": device_data['emailAddress'],
            "azureADDeviceId": device_data['azureADDeviceId'],
            "deviceRegistrationState": device_data['deviceRegistrationState'],
            "deviceCategoryDisplayName": device_data['deviceCategoryDisplayName'],
            "isSupervised": device_data['isSupervised'],
            "exchangeLastSuccessfulSyncDateTime": device_data['exchangeLastSuccessfulSyncDateTime'],
            "exchangeAccessState": device_data['exchangeAccessState'],
            "exchangeAccessStateReason": device_data['exchangeAccessStateReason'],
            "remoteAssistanceSessionUrl": device_data['remoteAssistanceSessionUrl'],
            "remoteAssistanceSessionErrorDetails": device_data['remoteAssistanceSessionErrorDetails'],
            "isEncrypted": device_data['isEncrypted'],
            "userPrincipalName": device_data['userPrincipalName'],
            "model": device_data['model'],
            "manufacturer": device_data['manufacturer'],
            "imei": device_data['imei'],
            "complianceGracePeriodExpirationDateTime": device_data['complianceGracePeriodExpirationDateTime'],
            "serialNumber": device_data['serialNumber'],
            "phoneNumber": device_data['phoneNumber'],
            "androidSecurityPatchLevel": device_data['androidSecurityPatchLevel'],
            "userDisplayName": device_data['userDisplayName'],
            "configurationManagerClientEnabledFeatures": device_data['configurationManagerClientEnabledFeatures'],
            "wiFiMacAddress": device_data['wiFiMacAddress'],
            "deviceHealthAttestationState": device_data['deviceHealthAttestationState'],
            "subscriberCarrier": device_data['subscriberCarrier'],
            "meid": device_data['meid'],
            "totalStorageSpaceInBytes": device_data['totalStorageSpaceInBytes'],
            "freeStorageSpaceInBytes": device_data['freeStorageSpaceInBytes'],
            "managedDeviceName": device_data['managedDeviceName'],
            "partnerReportedThreatState": device_data['partnerReportedThreatState'],
            "requireUserEnrollmentApproval": device_data['requireUserEnrollmentApproval'],
            "managementCertificateExpirationDate": device_data['managementCertificateExpirationDate'],
            "iccid": device_data['iccid'],
            "udid": device_data['udid'],
            "notes": device_data['notes'],
            "ethernetMacAddress": device_data['ethernetMacAddress'],
            "physicalMemoryInBytes": device_data['physicalMemoryInBytes'],
            "enrollmentProfileName": device_data['enrollmentProfileName'],
            "parentDevice": obj
        }
        MicrosoftIntuneDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)
######################################## End Update/Create Microsoft Intune Devices ########################################

######################################## Start Sync Microsoft Intune ########################################
def syncMicrosoftIntune():
    """Synchronize Microsoft Intune Devices and update the local database."""
    data = Integration.objects.get(integration_type="Microsoft Intune")
    updateMicrosoftIntuneDeviceDatabase(getMicrosoftIntuneDevices(getMicrosoftIntuneAccessToken(data.client_id, data.client_secret, data.tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Intune ########################################

######################################## Start Background Sync Microsoft Intune ########################################
def syncMicrosoftIntuneBackground(request):
    """Run Microsoft Intune device sync in a background thread."""
    def run():
        try:
            Notification.objects.create(
                title="Microsoft Intune Device Integration Sync",
                status="In Progress",
                created_at=timezone.now(),
                updated_at=timezone.now(),
            )  # type: ignore[attr-defined]
            messages.info(request, 'Microsoft Intune Device Integration Sync in Progress')
            syncMicrosoftIntune()
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Success","Microsoft Intune - Device",request.session.get('user_email', 'unknown'))
            Notification.objects.filter(title="Microsoft Intune Device Integration Sync").update(
                status="Success",
                updated_at=timezone.now(),
            )  # type: ignore[attr-defined]
            messages.info(request, 'Microsoft Intune Device Integration Sync Success')
        except Exception as e:
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Failure",f"Microsoft Intune - Device - {e}",request.session.get('user_email', 'unknown'))
            Notification.objects.filter(title="Microsoft Intune Device Integration Sync").update(
                status="Failure",
                updated_at=timezone.now(),
            )  # type: ignore[attr-defined]
            messages.error(request, f'Microsoft Intune Device Integration Sync Failed: {e}')
    thread = threading.Thread(target=run)
    thread.start()
######################################## End Background Sync Microsoft Intune ########################################