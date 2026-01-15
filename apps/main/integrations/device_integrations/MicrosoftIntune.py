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

######################################## Start Get Microsoft Intune Devices ########################################
def getMicrosoftIntuneDevices(access_token):
    """Fetch all enabled Microsoft Intune devices."""
    # Check if access_token is an error dictionary
    if isinstance(access_token, dict) and 'error' in access_token:
        raise Exception(f"Failed to get access token: {access_token['error']}")

    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

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
def syncMicrosoftIntuneDevice():
    data = Integration.objects.get(integration_type="Microsoft Intune")
    if not data.client_id or not data.client_secret or not data.tenant_id:
        raise Exception("Microsoft Intune integration is not properly configured. Missing client_id, client_secret, or tenant_id.")
    access_token = getMicrosoftGraphAccessToken(data.client_id, data.client_secret, data.tenant_id, ["https://graph.microsoft.com/.default"])
    
    if isinstance(access_token, dict) and 'error' in access_token:
        error_msg = str(access_token['error'])
        raise Exception(f"Failed to get access token: {error_msg}")

    updateMicrosoftIntuneDeviceDatabase(getMicrosoftIntuneDevices(access_token))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Intune ########################################