import requests
from datetime import datetime
from ..models import SophosDevice, SophosIntegration
from .masterlist import *

def getSophosAccessToken(client_id, client_secret, tenant_id):
    # Define the authentication endpoint URL
    auth_url = 'https://id.sophos.com/api/v2/oauth2/token'

    # Define the authentication payload
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
            # Extract the access token from the response
            # print(response.json())
            access_token = response.json()['access_token']
            
            # Print the access token (or use it for further API requests)
            return 'Bearer ' + access_token
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))


def getSophosDevices(access_token):
    url = 'https://api-us03.central.sophos.com/endpoint/v1/endpoints'
    headers = {
        'Authorization': access_token,
        'X-Tenant-ID': 'e52b63d3-2659-499a-a8aa-91b75e35a5dc'
    }

    try:
        # Make a GET request to fetch devices
        response = requests.get(url=url, headers=headers)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Extract the devices from the response
            # devices = response.json()['items']
            return response.json()['items']

        else:
            print("Failed to fetch devices. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))

def updateSophosDeviceDatabase(json_data):
    for device_data in json_data:
        # Extract relevant data from the JSON
        device_id = device_data.get('id')
        device_type = device_data.get('type')
        hostname = device_data.get('hostname')
        tenant_id = device_data.get('tenant', {}).get('id')
        os_data = device_data.get('os', {})
        ipv4_addresses = ', '.join(device_data.get('ipv4Addresses', []))
        mac_addresses = ', '.join(device_data.get('macAddresses', []))
        associated_person = device_data.get('associatedPerson', {}).get('viaLogin')
        tamper_protection_enabled = device_data.get('tamperProtectionEnabled')
        last_seen_at = device_data.get('lastSeenAt')
        lockdown_data = device_data.get('lockdown', {})
        isolation_data = device_data.get('isolation', {})

        # Create or update the SophosDevice instance
        sophos_device, created = SophosDevice.objects.update_or_create(
            id=device_id,
            defaults={
                'type': device_type,
                'hostname': hostname.lower(),
                'tenant_id': tenant_id,
                'os_isServer': os_data.get('isServer'),
                'osPlatform': os_data.get('name'),
                'os_name': os_data.get('platform'),
                'os_majorVersion': os_data.get('majorVersion'),
                'os_minorVersion': os_data.get('minorVersion'),
                'os_build': os_data.get('build'),
                'ipv4Addresses': ipv4_addresses,
                'macAddresses': mac_addresses,
                'associatedPerson_viaLogin': associated_person,
                'tamperProtectionEnabled': tamper_protection_enabled,
                'lastSeenAt': datetime.strptime(last_seen_at, '%Y-%m-%dT%H:%M:%S.%fZ') if last_seen_at else None,
                'lockdown_status': lockdown_data.get('status'),
                'lockdown_updateStatus': lockdown_data.get('updateStatus'),
                'isolation_status': isolation_data.get('status'),
                'isolation_adminIsolated': isolation_data.get('adminIsolated'),
                'isolation_selfIsolated': isolation_data.get('selfIsolated')
            }
        )
    
def syncSophos():
    for integration in SophosIntegration.objects.all():
        data = SophosIntegration.objects.get(id = integration.id)
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        updateSophosDeviceDatabase(getSophosDevices(getSophosAccessToken(client_id, client_secret, tenant_id)))
        devices = SophosDevice.objects.all()
        updateMasterList(devices, tenant_domain)
    return True

