# Import Dependencies
import msal, requests, threading, time
from django.utils import timezone
from datetime import datetime
from django.utils.timezone import make_aware
# Import Models
from ...models import Integration, UserData
# Import Function Scripts
from ..device_integrations.ReusedFunctions import *
from ....logger.views import createLog

######################################## Start Get Microsoft Entra ID Access Token ########################################
def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
    authority = 'https://login.microsoftonline.com/' + tenant_id
    scope = ['https://graph.microsoft.com/.default']
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    
    token_result = client.acquire_token_silent(scope, account=None)
    if not token_result:
        token_result = client.acquire_token_for_client(scopes=scope)
    if not token_result or 'access_token' not in token_result:
        raise Exception("Failed to acquire access token")

    access_token = 'Bearer ' + token_result['access_token']
    return access_token
######################################## End Get Microsoft Entra ID Access Token ########################################

######################################## Start Get Microsoft Entra ID Users ########################################
def getMicrosoftEntraIDUsers(access_token):
    # Hourly SMS Exempt Group: < 6 mins
    # url = 'https://graph.microsoft.com/v1.0/groups/6da370d4-32d9-4b70-9da7-6fae6d8f467a/members?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp,createdDateTime'
    # Internal Worker Group: < 5 mins
    url = 'https://graph.microsoft.com/v1.0/groups/148047f5-46e4-4d15-a817-961f9ad1c69e/members?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp,createdDateTime'
    headers = {'Authorization': access_token}
    graph_results_clean = []
    
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch users: {response.status_code} - {response.text}")
        data = response.json()
        graph_results_clean.extend(data.get('value', []))
        url = data.get('@odata.nextLink')
        
    return graph_results_clean

def getMicrosoftEntraIDUserAuthenticationMethods(access_token):
    url = f'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isAdmin,isSsprRegistered,isSsprEnabled,isSsprCapable,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered'
    headers = {'Authorization': access_token}
    graph_results_clean = []
    max_retries = 5  # Maximum number of retries
    retry_delay = 1  # Initial delay in seconds

    while url:
        for attempt in range(max_retries):
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                graph_results_clean.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
                break
            elif response.status_code == 429:  # Throttling error
                retry_after = int(response.headers.get('Retry-After', retry_delay))
                time.sleep(retry_after)
            else:
                raise Exception(f"Failed to fetch users: {response.status_code} - {response.text}")
        else:
            raise Exception("Max retries exceeded while fetching user authentication methods.")
        
    return graph_results_clean
######################################## End Get Microsoft Entra ID Users ########################################

######################################## Start Update Microsoft Entra ID User Database ########################################
# Constants for authentication strengths
AUTHENTICATION_STRENGTHS = {
    "Phishing Resistant": {'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'windowsHelloforBusiness'},
    "Passwordless": {'microsoftAuthenticatorPasswordless'},
    "MFA": {'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'temporaryAccessPass'},
    "Deprecated": {'mobilePhone', 'email', 'securityQuestion'},
    "None": set()
}

def determine_authentication_strength(auth_method_types):
    """Determine the highest and lowest authentication strengths."""
    highest_strength = "None"
    lowest_strength = "None"

    for strength, methods in AUTHENTICATION_STRENGTHS.items():
        if auth_method_types & methods:
            highest_strength = strength
            break

    for strength, methods in reversed(AUTHENTICATION_STRENGTHS.items()):
        if auth_method_types & methods:
            lowest_strength = strength
            break

    return highest_strength, lowest_strength

def updateMicrosoftEntraIDUserDatabase(users, authentication_data, access_token):
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")

    for user_data in users:
        if not user_data.get('accountEnabled'):
            continue

        # Convert last logon timestamp
        last_logon_timestamp = user_data.get('extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp')
        last_logon = make_aware(datetime.utcfromtimestamp(int(last_logon_timestamp) / 10**7 - 11644473600)) if last_logon_timestamp else None
        
        user_authentication_data = next((item for item in authentication_data if item['userPrincipalName'].lower() == user_data['userPrincipalName'].lower()), None)

        # Determine authentication strengths
        auth_method_types = set(user_authentication_data.get('methodsRegistered', []))
        highest_strength, lowest_strength = determine_authentication_strength(auth_method_types)

        user_fields = {
            'upn': user_data['userPrincipalName'].lower(),
            'uid': user_data['id'],
            'network_id': user_data['employeeId'].lower(),
            'given_name': user_data.get('givenName', ''),
            'surname': user_data.get('surname', ''),
            'job_title': user_data.get('jobTitle', ''),
            'department': user_data.get('department', ''),
            'last_logon_timestamp': last_logon,
            'created_at_timestamp': user_data.get('createdDateTime'),
            
            # Authentication capabilities
            'isAdmin': user_authentication_data.get('isAdmin', False),
            'isMfaCapable': user_authentication_data.get('isMfaCapable', False),
            'isMfaRegistered': user_authentication_data.get('isMfaRegistered', False),
            'isPasswordlessCapable': user_authentication_data.get('isPasswordlessCapable', False),
            'isSsprEnabled': user_authentication_data.get('isSsprEnabled', False),
            'isSsprRegistered': user_authentication_data.get('isSsprRegistered', False),
            
            # Authentication methods
            'microsoftAuthenticatorPush_authentication_method': 'microsoftAuthenticatorPush' in auth_method_types,
            'microsoftAuthenticatorPasswordless_authentication_method': 'microsoftAuthenticatorPasswordless' in auth_method_types,
            'softwareOneTimePasscode_authentication_method': 'softwareOneTimePasscode' in auth_method_types,
            'temporaryAccessPass_authentication_method': 'temporaryAccessPass' in auth_method_types,
            'windowsHelloforBusiness_authentication_method': 'windowsHelloForBusiness' in auth_method_types,
            'email_authentication_method': 'email' in auth_method_types,
            'mobilePhone_authentication_method': 'mobilePhone' in auth_method_types,
            'securityQuestion_authentication_method': 'securityQuestion' in auth_method_types,
            'passKeyDeviceBound_authentication_method': 'passKeyDeviceBound' in auth_method_types,
            'passKeyDeviceBoundAuthenticator_authentication_method': 'passKeyDeviceBoundAuthenticator' in auth_method_types,

            # Authentication strengths
            'highest_authentication_strength': highest_strength,
            'lowest_authentication_strength': lowest_strength,
        }

        try:
            userdata = UserData.objects.get(upn=user_fields['upn'])
            for field, value in user_fields.items():
                setattr(userdata, field, value)
            userdata.updated_at = timezone.now()
            userdata.save()
        except UserData.DoesNotExist:
            userdata = UserData(**user_fields)
            userdata.save()

        userdata.integration.add(integration)
######################################## End Update Microsoft Entra ID User Database ########################################

######################################## Start Sync Microsoft Entra ID User ########################################
def syncMicrosoftEntraIDUser():
    data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    access_token = getMicrosoftEntraIDAccessToken(data.client_id, data.client_secret, data.tenant_id)
    users = getMicrosoftEntraIDUsers(access_token)
    authentication_data = getMicrosoftEntraIDUserAuthenticationMethods(access_token)
    updateMicrosoftEntraIDUserDatabase(users, authentication_data , access_token)
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Entra ID User ########################################

######################################## Start Background Sync Microsoft Intune ########################################
def syncMicrosoftEntraIDUserBackground(request):
    # syncMicrosoftEntraIDUser()
    def run():
        try:
            syncMicrosoftEntraIDUser()
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Success","Microsoft Entra ID User",request.session['user_email'])
        except Exception as e:
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Failure",f"Microsoft Entra ID User - {e}",request.session['user_email'])
    thread = threading.Thread(target=run)
    thread.start()
######################################## End Background Sync Microsoft Intune ########################################