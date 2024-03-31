# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ..models import IntuneDevice, Integration
# Import Function Scripts
from .masterlist import *
from .DataCleaner import *

def getIntuneAccessToken(client_id, client_secret, tenant_id):
    authority = 'https://login.microsoftonline.com/' + tenant_id
    scope = ['https://graph.microsoft.com/.default']

    # Create an MSAL instance providing the client_id, authority and client_credential parameters
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)

    # First, try to lookup an access token in cache
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

    return access_token

def getIntuneDevices(access_token):
    url = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()    

def updateIntuneDeviceDatabase(graph_result):
    data = graph_result

    for device_data in data['value']:
        # device_id = device_data['id']
        hostname = device_data['deviceName']
        os_platform = device_data['operatingSystem']

        # Check if the device exists in the database
        try:
            device = Device.objects.get(hostname=hostname.lower())
        except Device.DoesNotExist:
            device = None

        # [osPlatform_clean, endpointType]
        clean_data = cleanAPIData(os_platform)

        # Prepare data for updating/creating device
        device_fields = {
            # 'userId': device_data['userId'],
            'hostname': hostname.lower(),
            # 'managedDeviceOwnerType': device_data['managedDeviceOwnerType'],
            # 'enrolledDateTime': datetime.fromisoformat(device_data['enrolledDateTime']),
            # 'lastSyncDateTime': datetime.fromisoformat(device_data['lastSyncDateTime']),
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
            # 'complianceState': device_data['complianceState'],
            # 'jailBroken': device_data['jailBroken'],
            # 'managementAgent': device_data['managementAgent'],
            # 'osVersion': device_data['osVersion'],
            # 'easActivated': device_data['easActivated'],
            # 'easDeviceId': device_data['easDeviceId'],
            # 'easActivationDateTime': datetime.fromisoformat(device_data['easActivationDateTime']),
            # 'azureADRegistered': device_data['azureADRegistered'],
            # 'deviceEnrollmentType': device_data['deviceEnrollmentType'],
            # 'activationLockBypassCode': device_data['activationLockBypassCode'],
            # 'emailAddress': device_data['emailAddress'],
            # 'azureADDeviceId': device_data['azureADDeviceId'],
            # 'deviceRegistrationState': device_data['deviceRegistrationState'],
            # 'deviceCategoryDisplayName': device_data['deviceCategoryDisplayName'],
            # 'isSupervised': device_data['isSupervised'],
            # 'exchangeLastSuccessfulSyncDateTime': datetime.fromisoformat(device_data['exchangeLastSuccessfulSyncDateTime']),
            # 'exchangeAccessState': device_data['exchangeAccessState'],
            # 'exchangeAccessStateReason': device_data['exchangeAccessStateReason'],
            # 'remoteAssistanceSessionUrl': device_data['remoteAssistanceSessionUrl'],
            # 'remoteAssistanceSessionErrorDetails': device_data['remoteAssistanceSessionErrorDetails'],
            # 'isEncrypted': device_data['isEncrypted'],
            # 'userPrincipalName': device_data['userPrincipalName'],
            # 'model': device_data['model'],
            # 'manufacturer': device_data['manufacturer'],
            # 'imei': device_data['imei'],
            # 'complianceGracePeriodExpirationDateTime': datetime.fromisoformat(device_data['complianceGracePeriodExpirationDateTime']),
            # 'serialNumber': device_data['serialNumber'],
            # 'phoneNumber': device_data['phoneNumber'],
            # 'androidSecurityPatchLevel': device_data['androidSecurityPatchLevel'],
            # 'userDisplayName': device_data['userDisplayName'],
            # 'configurationManagerClientEnabledFeatures': device_data['configurationManagerClientEnabledFeatures'],
            # 'wiFiMacAddress': device_data['wiFiMacAddress'],
            # 'deviceHealthAttestationState': device_data['deviceHealthAttestationState'],
            # 'subscriberCarrier': device_data['subscriberCarrier'],
            # 'meid': device_data['meid'],
            # 'totalStorageSpaceInBytes': device_data['totalStorageSpaceInBytes'],
            # 'freeStorageSpaceInBytes': device_data['freeStorageSpaceInBytes'],
            # 'managedDeviceName': device_data['managedDeviceName'],
            # 'partnerReportedThreatState': device_data['partnerReportedThreatState'],
            # 'requireUserEnrollmentApproval': device_data['requireUserEnrollmentApproval'],
            # 'managementCertificateExpirationDate': datetime.fromisoformat(device_data['managementCertificateExpirationDate']),
            # 'iccid': device_data['iccid'],
            # 'udid': device_data['udid'],
            # 'notes': device_data['notes'],
            # 'ethernetMacAddress': device_data['ethernetMacAddress'],
            # 'physicalMemoryInBytes': device_data['physicalMemoryInBytes']
        }

        # If device exists, update; otherwise, create new
        if device:
            for field, value in device_fields.items():
                setattr(device, field, value)
            device.updated_at = datetime.now()
            device.save()
            device.integration.add(Integration.objects.get(integration_type = "Microsoft Intune"))
        else:
            device = Device.objects.create(id=device_id, **device_fields)
            device.integration.add(Integration.objects.get(integration_type = "Microsoft Intune"))

def syncIntune():
    data = Integration.objects.get(integration_type = "Microsoft Intune")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateIntuneDeviceDatabase(getIntuneDevices(getIntuneAccessToken(client_id, client_secret, tenant_id)))
    # devices = IntuneDevice.objects.all()
    # updateMasterList(devices, tenant_domain)
    return True