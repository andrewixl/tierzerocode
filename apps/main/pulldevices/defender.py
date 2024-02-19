from ..models import DefenderIntegration
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

def syncDefender():
    for integration in DefenderIntegration.objects.all():
        data = DefenderIntegration.objects.get(id = integration.id)
        client_id = data.client_id
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        print(getDefenderDevices(getDefenderAccessToken(client_id, client_secret, tenant_id)))