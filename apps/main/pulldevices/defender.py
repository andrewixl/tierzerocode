from ..models import DefenderDevice, DefenderIntegration
# from ..models import IntuneDevice, IntuneIntegration
import msal
import requests
from datetime import datetime
from .masterlist import *

def getDefenderAccessToken(client_id, client_secret, tenant_id):
    # Enter the details of your AAD app registration
    authority = 'https://login.microsoftonline.com/' + tenant_id
    scope = ['https://api.securitycenter.microsoft.com/.default']

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

def getDefenderDevices(access_token):
    url = 'https://api.securitycenter.microsoft.com/api/machines'
    headers = {
    'Authorization': access_token
    }

    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)

    # Print the results in a JSON format
    return graph_result.json()

# from datetime import timezone

def updateDefenderDeviceDatabase(json_data):
    for device_data in json_data['value']:
        if device_data.get('onboardingStatus') == 'Onboarded':
            device_id = device_data['id']
            defaults = {
                'mergedIntoMachineId': device_data['mergedIntoMachineId'],
                'isPotentialDuplication': device_data['isPotentialDuplication'],
                'isExcluded': device_data['isExcluded'],
                'exclusionReason': device_data['exclusionReason'],
                'hostname': (device_data['computerDnsName'].split('.', 1)[0]).lower(),
                'firstSeen': device_data['firstSeen'],
                'lastSeen': device_data['lastSeen'],
                'osPlatform': device_data['osPlatform'],
                'osVersion': device_data['osVersion'],
                'osProcessor': device_data['osProcessor'],
                'version': device_data['version'],
                'lastIpAddress': device_data['lastIpAddress'],
                'lastExternalIpAddress': device_data['lastExternalIpAddress'],
                'agentVersion': device_data['agentVersion'],
                'osBuild': device_data['osBuild'],
                'healthStatus': device_data['healthStatus'],
                'deviceValue': device_data['deviceValue'],
                'rbacGroupId': device_data['rbacGroupId'],
                'rbacGroupName': device_data['rbacGroupName'],
                'riskScore': device_data['riskScore'],
                'exposureLevel': device_data['exposureLevel'],
                'isAadJoined': device_data['isAadJoined'],
                'aadDeviceId': device_data['aadDeviceId'],
                'defenderAvStatus': device_data['defenderAvStatus'],
                'onboardingStatus': device_data['onboardingStatus'],
                'osArchitecture': device_data['osArchitecture'],
                'managedBy': device_data['managedBy'],
                'managedByStatus': device_data['managedByStatus'],
                'vmMetadata': device_data['vmMetadata'],
            }
            obj, created = DefenderDevice.objects.update_or_create(id=device_id, defaults=defaults)

def syncDefender():
    for integration in DefenderIntegration.objects.all():
        data = DefenderIntegration.objects.get(id = integration.id)
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        updateDefenderDeviceDatabase(getDefenderDevices(getDefenderAccessToken(client_id, client_secret, tenant_id)))
        devices = DefenderDevice.objects.all()
        updateMasterList(devices, tenant_domain)
    return True