# Import Dependencies
import msal, requests

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
    url = 'https://graph.microsoft.com/v1.0/me'
    # Set the headers for the request
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()    
######################################## End Get Microsoft Entra ID Devices ########################################