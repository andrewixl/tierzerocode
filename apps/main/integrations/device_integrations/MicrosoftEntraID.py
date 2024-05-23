# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ...models import Integration, Device
# Import Function Scripts
from .DataCleaner import *

######################################## Start Get Microsoft Entra ID Access Token ########################################
def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
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
######################################## End Get Microsoft Entra ID Access Token ########################################

######################################## Start Get Microsoft Entra ID Devices ########################################
def getMicrosoftEntraIDDevices(access_token):
    # Set the URL for the request
    url = 'https://graph.microsoft.com/v1.0/devices'
    # Set the headers for the request
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()    
######################################## End Get Microsoft Entra ID Devices ########################################

######################################## Start Update/Create Microsoft Entra ID Devices ########################################
def updateMicrosoftEntraIDDeviceDatabase(json_data):
    # Loop through the data provided
    for device_data in json_data['value']:
        # Set the hostname and osPlatform variables
        hostname = device_data['displayName'].lower()
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
        obj.integration.add(Integration.objects.get(integration_type = "Microsoft Entra ID"))
######################################## End Update/Create Microsoft Entra ID Devices ########################################

######################################## Start Sync Microsoft Entra ID ########################################
def syncMicrosoftEntraID():
    try:
        # Get the Microsoft Entra ID Integration data
        data = Integration.objects.get(integration_type = "Microsoft Entra ID")
        # Set the variables for the Microsoft Entra ID Integration
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        # Sync the Microsoft Entra ID Integration
        updateMicrosoftEntraIDDeviceDatabase(getMicrosoftEntraIDDevices(getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id)))
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
######################################## End Sync Microsoft Entra ID ########################################