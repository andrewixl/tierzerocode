# Import Dependencies
import requests
from datetime import datetime
# Import Models
from ..models import Integration, CrowdStrikeFalconDevice
# Import Functions Scripts
from .masterlist import *
from .DataCleaner import *

def getCrowdStrikeAccessToken(client_id, client_secret, tenant_id):
    # Define the authentication endpoint URL
    auth_url = 'https://api.crowdstrike.com/oauth2/token'

    # Define the authentication payload
    auth_payload = {
        'client_id': client_id,
        'client_secret': client_secret,
    }

    try:
        # Make a POST request to the authentication endpoint
        response = requests.post(auth_url, data=auth_payload)
        
        # Check if the request was successful (status code 200)
        if response.status_code == 200 or response.status_code == 201:
            # Extract the access token from the response
            access_token = response.json()['access_token']
            
            # Print the access token (or use it for further API requests)
            return 'Bearer ' + access_token
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))

def getCrowdStrikeDevices(access_token):
    # url = 'https://api.crowdstrike.com/devices/queries/devices/v1?limit=20'
    url = 'https://api.crowdstrike.com/devices/queries/devices-scroll/v1'
    headers = {
    'Authorization': access_token
    }

    # Make a GET request to the provided url, passing the access token in a header
    crowdstrike_aids = ((requests.get(url=url, headers=headers)).json())['resources']

    total_devices = len(crowdstrike_aids)
    total_devices_count = total_devices
    # [5000, 10000, 14666]
    device_pagination_arr = [0]
    while total_devices_count > 0:
        if total_devices_count > 5000 and len(device_pagination_arr) == 0:
            device_pagination_arr.append(5000)
            total_devices_count -= 5000
        elif total_devices_count < 5000 and len(device_pagination_arr) == 0:
            device_pagination_arr.append(total_devices_count)
            total_devices_count = 0
        elif total_devices_count > 5000:
            device_pagination_arr.append(5000 + device_pagination_arr[-1])
            total_devices_count -= 5000
        elif total_devices_count < 5000:
            device_pagination_arr.append(total_devices_count + device_pagination_arr[-1])
            total_devices_count = 0
            
    total_crowdstrike_results = []
    for pagination_arr in range(len(device_pagination_arr)):
        print(device_pagination_arr[pagination_arr])
        if pagination_arr == 0:
            pass
        else:
            url = 'https://api.crowdstrike.com/devices/entities/devices/v2'
            headers = {
            'accept': 'application/json',
            'Authorization': access_token,
            'Content-Type': 'application/json',
            }

            body = {
                'ids': crowdstrike_aids[device_pagination_arr[pagination_arr-1]:device_pagination_arr[pagination_arr]],
            }

            # Make a GET request to the provided url, passing the access token in a header
            crowdstrike_result = requests.post(url=url, headers=headers, json=body)

            # Print the results in a JSON format
            total_crowdstrike_results.append(crowdstrike_result.json())
    return (total_crowdstrike_results)

def updateCrowdStrikeDeviceDatabase(total_crowdstrike_results):
    for crowdstrike_results in total_crowdstrike_results:
        for device_data in crowdstrike_results['resources']:
            try:
                # Extract relevant data from the JSON
                device_id = device_data.get('device_id')
                hostname = device_data.get('hostname')
                os_platform = device_data.get('os_version')

                # [osPlatform_clean, endpointType]
                clean_data = cleanAPIData(os_platform)
                
                crowdstrikefalcon_device, created = CrowdStrikeFalconDevice.objects.update_or_create(
                    id=device_id,
                    defaults={
                        'hostname': hostname.lower(),
                        'osPlatform': clean_data[0],
                        'endpointType': clean_data[1],
                    }
                )
            except Exception as NoneType:
                print("An error occurred:", str(NoneType) + ' ' + str(device_id))

def syncCrowdStrikeFalcon():
    data = Integration.objects.get(integration_type = "CrowdStrike Falcon")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    print("Syncing CrowdStrike Falcon")
    updateCrowdStrikeDeviceDatabase(getCrowdStrikeDevices(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id)))
    devices = CrowdStrikeFalconDevice.objects.all()
    updateMasterList(devices, tenant_domain)
    return True