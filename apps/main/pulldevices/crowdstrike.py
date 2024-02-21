# from ..models import CrowdStrikeDevice, CrowdStrikeIntegration
from ..models import CrowdStrikeIntegration
import msal
import requests
from datetime import datetime
from .masterlist import *

def getCrowdStrikeAccessToken(client_id, client_secret, tenant_id):
    # Define the authentication endpoint URL
    auth_url = 'https://api.crowdstrike.com/oauth2/token'

    # Define the authentication payload
    auth_payload = {
        # 'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        # 'scope': 'token'
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
    url = 'https://api.crowdstrike.com/devices/queries/devices/v1'
    # url = 'https://api.crowdstrike.com/devices/queries/devices-scroll/v1'
    headers = {
    'Authorization': access_token
    }

    # Make a GET request to the provided url, passing the access token in a header
    crowdstrike_aids = ((requests.get(url=url, headers=headers)).json())['resources']

    print(crowdstrike_aids)

    url = 'https://api.crowdstrike.com/devices/entities/devices/v2'
    headers = {
    'Authorization': access_token
    }

    body = {
        'ids': crowdstrike_aids,
    }

    # Make a GET request to the provided url, passing the access token in a header
    crowdstrike_result = requests.post(url=url, headers=headers, data=body)

    print(crowdstrike_result.json())

    # Print the results in a JSON format
    return crowdstrike_result.json()

def syncCrowdStrike():
    for integration in CrowdStrikeIntegration.objects.all():
        data = CrowdStrikeIntegration.objects.get(id = integration.id)
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        getCrowdStrikeDevices(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id))
    #     updateIntuneDeviceDatabase(getIntuneDevices(getIntuneAccessToken(client_id, client_secret, tenant_id)))
    #     devices = IntuneDevice.objects.all()
    #     updateMasterList(devices, tenant_domain)
    return True