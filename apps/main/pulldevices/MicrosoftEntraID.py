from ..models import MicrosoftEntraIDDevice, Integration
import msal
import requests
from datetime import datetime
from .masterlist import *

def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
    # Enter the details of your AAD app registration
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

def getMicrosoftEntraIDDevices(access_token):
    url = 'https://graph.microsoft.com/v1.0/devices'
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()    

def updateMicrosoftEntraIDDeviceDatabase(graph_result):
    data = graph_result

    for device_data in data['value']:
        device_id = device_data['id']
        device_name = device_data['displayName']

        # Check if the device exists in the database
        try:
            device = MicrosoftEntraIDDevice.objects.get(id=device_id)
        except MicrosoftEntraIDDevice.DoesNotExist:
            device = None
        
        os_platform_lower = (device_data['operatingSystem']).lower()
        if 'server' in os_platform_lower and 'windows' in os_platform_lower:
            endpointType = 'Server'
            osPlatform_clean = 'Windows Server'
        elif 'ubuntu' in os_platform_lower:
            endpointType = 'Server'
            osPlatform_clean  = 'Ubuntu'
        elif 'windows' in os_platform_lower:
            endpointType = 'Client'
            osPlatform_clean  = 'Windows'
        elif 'android' in os_platform_lower:
            endpointType = 'Mobile'
            osPlatform_clean  = 'Android'
        elif 'ios' in os_platform_lower or 'ipados' in os_platform_lower:
            endpointType = 'Mobile'
            osPlatform_clean = 'iOS/iPadOS'
        else:
            endpointType = 'Other'
            osPlatform_clean  = 'Other'

        # Prepare data for updating/creating device
        device_fields = {
            'hostname': device_name.lower(),
            'deviceId': device_data['deviceId'],
            'osPlatform': osPlatform_clean,
            'endpointType': endpointType,
        }

        # If device exists, update; otherwise, create new
        if device:
            for field, value in device_fields.items():
                setattr(device, field, value)
            device.updated_at = datetime.now()
            device.save()
        else:
            MicrosoftEntraIDDevice.objects.create(id=device_id, **device_fields)

def syncMicrosoftEntraID():
    data = Integration.objects.get(integration_type = "Microsoft Entra ID")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateMicrosoftEntraIDDeviceDatabase(getMicrosoftEntraIDDevices(getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id)))
    devices = MicrosoftEntraIDDevice.objects.all()
    updateMasterList(devices, tenant_domain)
    return True