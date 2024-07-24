# Import Dependencies
import msal, requests, logging
from django.utils import timezone
# Import Models
from ...models import Integration, Device, MicrosoftIntuneDeviceData, DeviceComplianceSettings
# Import Function Scripts
from .ReusedFunctions import *

# Set the logger
# logger = logging.getLogger('custom_logger')

######################################## Start Get Microsoft Intune Access Token ########################################
def getIntuneAccessToken(client_id, client_secret, tenant_id):
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
######################################## End Get Microsoft Intune Access Token ########################################

######################################## Start Get Microsoft Intune Devices ########################################
def getIntuneDevices(access_token):
    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    headers = {'Authorization': access_token}
    graph_results_original = []
    graph_results_clean = []
    graph_results_original.append(requests.get(url=url, headers=headers).json())

    if '@odata.nextLink' in graph_results_original[0]:
        while '@odata.nextLink' in graph_results_original[-1]:
            next_link = graph_results_original[-1]['@odata.nextLink']
            graph_results_original.append(requests.get(url=next_link, headers=headers).json())
    
    for graph_result in graph_results_original:
        graph_results_clean.append(graph_result['value'])
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

def updateIntuneDeviceDatabase(json_data):
    for device_datas in json_data:
        for device_data in device_datas:
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
            if not clean_data[1] == 'Mobile' or not device_data['managedDeviceOwnerType'] == 'company':
                continue
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
    logger.info('Microsoft Intune Devices Updated')
######################################## End Update/Create Microsoft Intune Devices ########################################

######################################## Start Sync Microsoft Intune ########################################
def syncIntune():
    data = Integration.objects.get(integration_type="Microsoft Intune")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateIntuneDeviceDatabase(getIntuneDevices(getIntuneAccessToken(client_id, client_secret, tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()

    print('Microsoft Intune Synced Successfully')
    return True
######################################## End Sync Microsoft Intune ########################################

import threading

def syncMicrosoftIntuneBackground():
    thread = threading.Thread(target=syncIntune)
    thread.start()
