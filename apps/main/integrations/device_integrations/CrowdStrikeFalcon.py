# Import Dependencies
import requests
from datetime import datetime
# Import Models
from ...models import Integration, Device
# Import Functions Scripts
from .DataCleaner import *

######################################## Start Get CrowdStrike Falcon Access Token ########################################
def getCrowdStrikeAccessToken(client_id, client_secret, tenant_id):
    # Define the URL for the request
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
            # Return the access token
            return 'Bearer ' + response.json()['access_token']
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))
######################################## End Get CrowdStrike Falcon Access Token ########################################

######################################## Start Get CrowdStrike Falcon Devices ########################################
def getCrowdStrikeDevices(access_token):
    # Set the URL for the request
    url = 'https://api.crowdstrike.com/devices/queries/devices-scroll/v1'
    # Set the headers for the request
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    crowdstrike_aids = ((requests.get(url=url, headers=headers)).json())['resources']

    total_devices = len(crowdstrike_aids)
    total_devices_count = total_devices
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
            total_crowdstrike_results.append(crowdstrike_result.json())

    # Return the results in a JSON format
    return (total_crowdstrike_results)
######################################## End Get CrowdStrike Falcon Devices ########################################

######################################## Start Update/Create CrowdStrike Falcon Devices ########################################
def updateCrowdStrikeDeviceDatabase(total_crowdstrike_results):
    for crowdstrike_results in total_crowdstrike_results:
        for device_data in crowdstrike_results['resources']:
            # Set the hostname and osPlatform variables
            # try:
            if device_data.get('hostname') == None or device_data.get('os_version') == None:
                print("Device Data is None")
                continue
            else:
                hostname = device_data.get('hostname').lower()
                os_platform = device_data.get('os_version')
            # except:
            #     # print(device_data)
            #     continue
            # os_platform = device_data.get('os_version')
            # print(os_platform)

            # [osPlatform_clean, endpointType]
            clean_data = cleanAPIData(os_platform)
            # Prepare data for updating/creating device
            defaults={
                'hostname': hostname,
                'osPlatform': clean_data[0],
                'endpointType': clean_data[1],
            }
            # Test If Statement to Only Import Mobile Devices
            if not clean_data[1] == 'Mobile':
                if clean_data[1] == 'Other':
                    print(device_data.get('hostname'))
                continue
            # Update or Create the Device object
            obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
            # Add the Microsoft Intune Integration to the Device object
            obj.integration.add(Integration.objects.get(integration_type = "CrowdStrike Falcon"))

######################################## End Update/Create CrowdStrike Falcon Devices ########################################

######################################## Start Sync CrowdStrike Falcon ########################################
def syncCrowdStrikeFalcon():
    # Get the CrowdStrike Falcon Integration data
    data = Integration.objects.get(integration_type = "CrowdStrike Falcon")
    # Set the variables for the CrowdStrike Falcon Integration
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    # Sync the CrowdStrike Falcon Integration
    updateCrowdStrikeDeviceDatabase(getCrowdStrikeDevices(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id)))
    # Update the last synced time
    data.last_synced_at = datetime.now()
    # Save the changes
    data.save()
    # Return True to indicate the sync was successful
    return True
    # try:
    #     # Get the CrowdStrike Falcon Integration data
    #     data = Integration.objects.get(integration_type = "CrowdStrike Falcon")
    #     # Set the variables for the CrowdStrike Falcon Integration
    #     client_id = data.client_id
    #     client_secret = data.client_secret
    #     tenant_id = data.tenant_id
    #     tenant_domain = data.tenant_domain
    #     # Sync the CrowdStrike Falcon Integration
    #     updateCrowdStrikeDeviceDatabase(getCrowdStrikeDevices(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id)))
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
######################################## End Sync CrowdStrike Falcon ########################################