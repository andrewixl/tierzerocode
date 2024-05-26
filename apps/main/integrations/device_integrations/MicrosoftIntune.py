# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ...models import Integration, Device, MicrosoftIntuneDeviceData
# Import Function Scripts
from .DataCleaner import *

######################################## Start Get Microsoft Intune Access Token ########################################
def getIntuneAccessToken(client_id, client_secret, tenant_id):
    # Set the authority and scope for the request
    authority = 'https://login.microsoftonline.com/' + tenant_id
    scope = ['https://graph.microsoft.com/.default']
    # Create an MSAL instance providing the client_id, authority and client_credential parameters
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    # Try to lookup an access token in cache
    token_result = client.acquire_token_silent(scope, account=None)
    # If the token is available in cache, save it to a variable
    if token_result:
        access_token = 'Bearer ' + token_result['access_token']
        print('Access token was loaded from cache')
    # If the token is not available in cache, acquire a new one from Azure AD and save it to a variable
    if not token_result:
        token_result = client.acquire_token_for_client(scopes=scope)
        access_token = 'Bearer ' + token_result['access_token']
        print('New access token was acquired from Azure AD')
    # Return the access token
    return access_token
######################################## End Get Microsoft Intune Access Token ########################################

######################################## Start Get Microsoft Intune Devices ########################################
def getIntuneDevices(access_token):
    # Set the URL for the request
    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    # Set the headers for the request
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Return the results in a JSON format
    return graph_result.json()
######################################## End Get Microsoft Intune Devices ########################################

######################################## Start Update/Create Microsoft Intune Devices ########################################
def updateIntuneDeviceDatabase(json_data):
    # Loop through the data provided
    for device_data in json_data['value']:
        # Set the hostname and osPlatform variables
        hostname = device_data['deviceName'].lower()
        os_platform = device_data['operatingSystem']
        # [osPlatform_clean, endpointType]
        clean_data = cleanAPIData(os_platform)
        # Prepare data for updating/creating device
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        # Update or Create the Device object
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        # Add the Microsoft Intune Integration to the Device object
        obj.integration.add(Integration.objects.get(integration_type = "Microsoft Intune"))

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
        # Update or Create the Device object
        # obj2, created = MicrosoftIntuneDeviceData.objects.update_or_create(deviceName=device_data['deviceName'], defaults=defaults_all)
        obj2, created = MicrosoftIntuneDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)
        
######################################## End Update/Create Microsoft Intune Devices ########################################

######################################## Start Sync Microsoft Intune ########################################
def syncIntune():
    # Get the Microsoft Intune Integration data
    data = Integration.objects.get(integration_type = "Microsoft Intune")
    # Set the variables for the Microsoft Intune Integration
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    # Sync the Microsoft Intune Integration
    updateIntuneDeviceDatabase(getIntuneDevices(getIntuneAccessToken(client_id, client_secret, tenant_id)))
    # Update the last synced time
    data.last_synced_at = datetime.now()
    # Save the changes
    data.save()
    # Return True to indicate the sync was successful
    return True
    # try:
    #     # Get the Microsoft Intune Integration data
    #     data = Integration.objects.get(integration_type = "Microsoft Intune")
    #     # Set the variables for the Microsoft Intune Integration
    #     client_id = data.client_id
    #     client_secret = data.client_secret
    #     tenant_id = data.tenant_id
    #     tenant_domain = data.tenant_domain
    #     # Sync the Microsoft Intune Integration
    #     updateIntuneDeviceDatabase(getIntuneDevices(getIntuneAccessToken(client_id, client_secret, tenant_id)))
    #     # Update the last synced time
    #     data.last_synced_at = datetime.now()
    #     # Save the changes
    #     data.save()
    #     # Return True to indicate the sync was successful
    #     return True
    # except Exception as e:
    #     # Print the error
    #     print(e)
    #     # Return False to indicate the sync was unsuccessful
    #     return False, e
######################################## End Sync Microsoft Intune ########################################