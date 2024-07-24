# Import Dependencies
import msal, requests, logging
from django.utils import timezone
# Import Models
from ...models import Integration, UserData

# Set the logger
logger = logging.getLogger('custom_logger')

######################################## Start Get Microsoft Entra ID Access Token ########################################
def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://graph.microsoft.com/.default']
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    token_result = client.acquire_token_silent(scope, account=None)
    if token_result:
        access_token = 'Bearer ' + token_result['access_token']
        logger.info('Access token was loaded from cache')
    else:
        token_result = client.acquire_token_for_client(scopes=scope)
        access_token = 'Bearer ' + token_result['access_token']
        logger.info('New access token was acquired from Azure AD')
    return access_token
######################################## End Get Microsoft Entra ID Access Token ########################################

######################################## Start Get Microsoft Entra ID Users ########################################
def getMicrosoftEntraIDUsers(access_token):
    url = 'https://graph.microsoft.com/v1.0/groups/7da83a50-e9ae-4504-a608-c59ec241d993/members?$select=userPrincipalName,givenName,surname,id,accountEnabled'
    headers = {'Authorization': access_token}
    users = []
    while url:
        response = requests.get(url, headers=headers).json()
        users.extend(response.get('value', []))
        url = response.get('@odata.nextLink')
    return users

def getMicrosoftEntraIDUserAuthenticationMethods(access_token, user_id):
    url = f'https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods'
    headers = {'Authorization': access_token}
    response = requests.get(url, headers=headers)
    return response.json().get('value', [])
######################################## End Get Microsoft Entra ID Users ########################################

######################################## Start Update Microsoft Entra ID User Database ########################################
def updateMicrosoftEntraIDUserDatabase(users, access_token):
    for user_data in users:
        if not user_data.get('accountEnabled'):
            continue
        user_fields = {
            'upn': user_data['userPrincipalName'].lower(),
            'uid': user_data['id'],
            'given_name': user_data.get('givenName', ''),
            'surname': user_data.get('surname', ''),
        }

        auth_methods = getMicrosoftEntraIDUserAuthenticationMethods(access_token, user_data['id'])
        auth_method_types = {method['@odata.type'] for method in auth_methods}

        user_fields.update({
            'email_authentication_method': '#microsoft.graph.emailAuthenticationMethod' in auth_method_types,
            'fido2_authentication_method': '#microsoft.graph.fido2AuthenticationMethod' in auth_method_types,
            'microsoft_authenticator_authentication_method': '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' in auth_method_types,
            'password_authentication_method': '#microsoft.graph.passwordAuthenticationMethod' in auth_method_types,
            'phone_authentication_method': '#microsoft.graph.phoneAuthenticationMethod' in auth_method_types,
            'software_oath_authentication_method': '#microsoft.graph.softwareOathAuthenticationMethod' in auth_method_types,
            'temporary_access_pass_authentication_method': '#microsoft.graph.temporaryAccessPassAuthenticationMethod' in auth_method_types,
            'windows_hello_for_business_authentication_method': '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' in auth_method_types,
        })

        # Determine authentication strengths
        if user_fields['fido2_authentication_method'] or user_fields['windows_hello_for_business_authentication_method']:
            user_fields['highest_authentication_strength'] = "Phishing Resistant"
        elif user_fields['microsoft_authenticator_authentication_method']:
            user_fields['highest_authentication_strength'] = "Passwordless"
        elif user_fields['temporary_access_pass_authentication_method'] or user_fields['software_oath_authentication_method']:
            user_fields['highest_authentication_strength'] = "MFA"
        elif user_fields['phone_authentication_method']:
            user_fields['highest_authentication_strength'] = "Deprecated"
        else:
            user_fields['highest_authentication_strength'] = "None"

        if user_fields['phone_authentication_method']:
            user_fields['lowest_authentication_strength'] = "Deprecated"
        elif user_fields['temporary_access_pass_authentication_method'] or user_fields['software_oath_authentication_method']:
            user_fields['lowest_authentication_strength'] = "MFA"
        elif user_fields['microsoft_authenticator_authentication_method']:
            user_fields['lowest_authentication_strength'] = "Passwordless"
        elif user_fields['fido2_authentication_method'] or user_fields['windows_hello_for_business_authentication_method']:
            user_fields['lowest_authentication_strength'] = "Phishing Resistant"
        else:
            user_fields['lowest_authentication_strength'] = "None"

        try:
            userdata = UserData.objects.get(upn=user_fields['upn'])
            for field, value in user_fields.items():
                setattr(userdata, field, value)
            userdata.updated_at = timezone.now()
            userdata.save()
        except UserData.DoesNotExist:
            userdata = UserData.objects.create(**user_fields)
        
        userdata.integration.add(Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User"))
######################################## End Update Microsoft Entra ID User Database ########################################

######################################## Start Sync Microsoft Entra ID User ########################################
def syncMicrosoftEntraIDUser():
    integration_data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    access_token = getMicrosoftEntraIDAccessToken(integration_data.client_id, integration_data.client_secret, integration_data.tenant_id)
    users = getMicrosoftEntraIDUsers(access_token)
    updateMicrosoftEntraIDUserDatabase(users, access_token)
    integration_data.last_synced_at = timezone.now()
    integration_data.save()
    logger.info('Microsoft Entra ID User sync completed successfully')
    return True
######################################## End Sync Microsoft Entra ID User ########################################

import threading

def syncMicrosoftEntraIDUserBackground():
    thread = threading.Thread(target=syncMicrosoftEntraIDUser)
    thread.start()
