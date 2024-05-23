# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ...models import Integration, Device
# Import Function Scripts
from .DataCleaner import *

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
######################################## End Update/Create Microsoft Defender for Endpoint Devices ########################################

######################################## Start Sync Microsoft Defender for Endpoint ########################################
def syncDefender():
    try:
        # Get the Microsoft Defender for Endpoint Integration data
        data = Integration.objects.get(integration_type = "Microsoft Defender for Endpoint")
        # Set the variables for the Microsoft Defender for Endpoint Integration
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        # Sync the Microsoft Defender for Endpoint Integration
        updateDefenderDeviceDatabase(getDefenderDevices(getDefenderAccessToken(client_id, client_secret, tenant_id)))
        # Update the last synced time
        data.last_synced_at = datetime.now()
        # Save the changes
        data.save()
        # Return True to indicate the sync was successful
        return True
    except Exception as e:
        # Print the error
        print(e)
        # Return False to indicate the sync was unsuccessful
        return False, e
######################################## End Sync Microsoft Defender for Endpoint ########################################