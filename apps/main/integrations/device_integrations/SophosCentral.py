# Import Dependencies
import requests
from datetime import datetime
# Import Models
from ...models import Integration, Device
# Import Functions Scripts
from .DataCleaner import *

######################################## Start Get Sophos Central Access Token ########################################
def getSophosAccessToken(client_id, client_secret):
    # Set the Url for the request
    auth_url = 'https://id.sophos.com/api/v2/oauth2/token'
    # Set the authentication payload
    auth_payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'token'
    }
    try:
        # Make a POST request to the authentication endpoint
        response = requests.post(auth_url, data=auth_payload)
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Return the access token
            return 'Bearer ' + response.json()['access_token']
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))
######################################## End Get Sophos Central Access Token ########################################

######################################## Start Get Sophos Central Devices ########################################
def getSophosDevices(access_token, tenant_id):
    # Set the URL for the request
    url = 'https://api-us03.central.sophos.com/endpoint/v1/endpoints'
    # Set the headers for the request
    headers = {
        'Authorization': access_token,
        'X-Tenant-ID': tenant_id
    }
    # Make a GET request to the provided url, passing the access token and tenant_id in a header
    response = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return response.json()
######################################## End Get Sophos Central Devices ########################################

######################################## Start Update/Create Sophos Central Devices ########################################
def updateSophosDeviceDatabase(json_data):
    # Loop through the data provided
    for device_data in json_data['items']:
        # Set the hostname and osPlatform variables
        hostname = device_data.get('hostname').lower()
        os_platform = device_data.get('os', {}).get('name')
        # [osPlatform_clean, endpointType]
        clean_data = cleanAPIData(os_platform)
        # Prepare data for updating/creating device
        defaults={
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        # Update or Create the Device object
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        # Add the Microsoft Intune Integration to the Device object
        obj.integration.add(Integration.objects.get(integration_type = "Sophos Central"))
######################################## End Update/Create Sophos Central Devices ########################################

######################################## Start Sync Sophos Central ######################################## 
def syncSophos():
    try:
        # Get the Microsoft Intune Integration data
        data = Integration.objects.get(integration_type = "Sophos Central")
        # Set the variables for the Microsoft Intune Integration
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        # Sync the Microsoft Intune Integration
        updateSophosDeviceDatabase(getSophosDevices(getSophosAccessToken(client_id, client_secret), tenant_id))
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
######################################## End Sync Sophos Central ########################################

