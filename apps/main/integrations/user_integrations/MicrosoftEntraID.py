# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ...models import Integration, UserData
# Import Function Scripts
# from .masterlist import *
# from .DataCleaner import *

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

def getMicrosoftEntraIDUsers(access_token):
    url = 'https://graph.microsoft.com/v1.0/users'
    headers = {
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()

def getMicrosoftEntraIDUserAuthenticationMethods(access_token, user_id):
    url = 'https://graph.microsoft.com/v1.0/users/' + user_id + '/authentication/methods'
    headers = { 
    'Authorization': access_token
    }
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()

def updateMicrosoftEntraIDUserDatabase(graph_result, access_token):
    data = graph_result

    for user_data in data['value']:
        upn = user_data['userPrincipalName'].lower()
        uid = user_data['id']
        given_name = user_data['givenName']
        surname = user_data['surname']
        email_authentication_method = False
        fido2_authentication_method = False
        microsoft_authenticator_authentication_method = False
        password_authentication_method = False
        phone_authentication_method = False
        software_oath_authentication_method = False
        temporary_access_pass_authentication_method = False
        windows_hello_for_business_authentication_method = False

        # Check if the user has any authentication methods
        try:
            authentication_methods = getMicrosoftEntraIDUserAuthenticationMethods(access_token, uid)
        except:
            authentication_methods = None  
        
        if authentication_methods: 
            for method in authentication_methods['value']:
                if method['@odata.type'] == '#microsoft.graph.emailAuthenticationMethod':
                    email_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.fido2AuthenticationMethod':
                    fido2_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod':
                    microsoft_authenticator_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.passwordAuthenticationMethod':
                    password_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.phoneAuthenticationMethod':
                    phone_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.softwareOathAuthenticationMethod':
                    software_oath_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.temporaryAccessPassAuthenticationMethod':
                    temporary_access_pass_authentication_method = True
                if method['@odata.type'] == '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod':
                    windows_hello_for_business_authentication_method = True
            


        # Check if the device exists in the database
        try:
            userdata = UserData.objects.get(upn=user_data['userPrincipalName'].lower())
            print("DATA FOUND")
        except UserData.DoesNotExist:
            userdata = None
            print("DATA NOT FOUND")
        
        print(userdata)

        # Prepare data for updating/creating userdata
        user_data_fields = {
            'upn': upn,
            'uid': uid,
            'given_name': given_name,
            'surname': surname,
            'email_authentication_method': email_authentication_method,
            'fido2_authentication_method': fido2_authentication_method,
            'microsoft_authenticator_authentication_method': microsoft_authenticator_authentication_method, 
            'password_authentication_method': password_authentication_method,
            'phone_authentication_method': phone_authentication_method,
            'software_oath_authentication_method': software_oath_authentication_method,
            'temporary_access_pass_authentication_method': temporary_access_pass_authentication_method,
            'windows_hello_for_business_authentication_method': windows_hello_for_business_authentication_method,
        }

        print (user_data_fields)

        # If device exists, update; otherwise, create new
        if userdata:
            for field, value in user_data_fields.items():
                setattr(userdata, field, value)
            userdata.updated_at = datetime.now()
            userdata.save()
            userdata.integration.add(Integration.objects.get(integration_type = "Microsoft Entra ID"))
        else:
            userdata = UserData.objects.create(**user_data_fields)
            userdata.integration.add(Integration.objects.get(integration_type = "Microsoft Entra ID"))


# https://graph.microsoft.com/v1.0/users/283c0eb2-2a8c-4ee8-93bd-e66212b9655e/authentication/methods

def syncMicrosoftEntraIDUser():
    data = Integration.objects.get(integration_type = "Microsoft Entra ID")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateMicrosoftEntraIDUserDatabase(getMicrosoftEntraIDUsers(getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id)), getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id))
#    data.last_synced_at = datetime.now()
    # data.save()
    return True