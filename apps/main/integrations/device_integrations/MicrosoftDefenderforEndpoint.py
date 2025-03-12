# Import Dependencies
import msal, requests, threading
from datetime import datetime
# Import Models
from ...models import Integration, Device, MicrosoftDefenderforEndpointDeviceData
# Import Function Scripts
from .ReusedFunctions import *

######################################## Start Get Microsoft Defender for Endpoint Access Token ########################################
def getDefenderAccessToken(client_id, client_secret, tenant_id):
    # Set the authority and scope for the request
    authority = 'https://login.microsoftonline.com/' + tenant_id
    scope = ['https://api.securitycenter.microsoft.com/.default']
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
######################################## End Get Microsoft Defender for Endpoint Access Token ########################################

######################################## Start Get Microsoft Defender for Endpoint Devices ########################################
def getDefenderDevices(access_token):
    # Set the URL for the request
    url = 'https://api.securitycenter.microsoft.com/api/machines'
    # Set the headers for the request
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()
######################################## End Get Microsoft Defender for Endpoint Devices ########################################

######################################## Start Update/Create Microsoft Defender for Endpoint Devices ########################################
def updateDefenderDeviceDatabase(json_data):
    # Loop through the data provided
    for device_data in json_data['value']:
        # Check if the device is onboarded and active
        if device_data.get('onboardingStatus') == 'Onboarded' and not device_data.get('healthStatus') == 'Inactive':
            # Set the hostname and osPlatform variables
            hostname = (device_data['computerDnsName'].split('.', 1)[0]).lower()
            os_platform = device_data['osPlatform']
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
            # Add the Microsoft Defender for Endpoint Integration to the Device object
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
            if endpoint_data == endpoint_match:
                obj.compliant = True
            else:
                obj.compliant = False
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
            # Update or Create the Device object
            # obj2, created = MicrosoftDefenderforEndpointDeviceData.objects.update_or_create(computerDnsName=device_data['computerDnsName'], defaults=defaults_all)
            obj2, created = MicrosoftDefenderforEndpointDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)

######################################## End Update/Create Microsoft Defender for Endpoint Devices ########################################

######################################## Start Sync Microsoft Defender for Endpoint ########################################
def syncMicrosoftDefender():
    # Get the Microsoft Defender for Endpoint Integration data
    data = Integration.objects.get(integration_type = "Microsoft Defender for Endpoint")
    # Sync the Microsoft Defender for Endpoint Integration
    updateDefenderDeviceDatabase(getDefenderDevices(getDefenderAccessToken(data.client_id, data.client_secret, data.tenant_id)))
    # Update the last synced time
    data.last_synced_at = datetime.now()
    # Save the changes
    data.save()
    # Return True to indicate the sync was successful
    return True
######################################## End Sync Microsoft Defender for Endpoint ########################################

def syncMicrosoftDefenderBackground():
    def run():
        try:
            syncMicrosoftDefender()
        except Exception as e:
            print(f"Defender sync failed: {e}")
    thread = threading.Thread(target=run)
    thread.start()