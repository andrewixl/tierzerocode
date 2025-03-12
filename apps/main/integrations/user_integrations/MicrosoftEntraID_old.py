# Import Dependencies
import msal, requests
from django.utils import timezone
from datetime import datetime, timedelta
from django.utils.timezone import make_aware, now
from django.db import transaction
# Import Models
from ...models import Integration, UserData

######################################## Start Get Microsoft Entra ID Access Token ########################################
def get_microsoft_entra_id_access_token(client_id, client_secret, tenant_id):
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://graph.microsoft.com/.default']
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    
    token_result = client.acquire_token_silent(scope, account=None)
    if not token_result:
        token_result = client.acquire_token_for_client(scopes=scope)

    if not token_result or 'access_token' not in token_result:
        print("Failed to acquire access token")
        raise Exception("Failed to acquire access token")

    print("Access token acquired successfully")
    return f"Bearer {token_result['access_token']}"
######################################## End Get Microsoft Entra ID Access Token ########################################

######################################## Start Get Microsoft Entra ID Users ########################################
def get_microsoft_entra_id_users(access_token):
    url = ('https://graph.microsoft.com/v1.0/groups/142edc02-1d76-4df9-920a-56df82a4b203/members'
           '?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,'
           'department,extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp')
    headers = {'Authorization': access_token}
    users = []

    while url:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to fetch users: {response.status_code} - {response.text}")
            raise Exception(f"Failed to fetch users: {response.text}")

        data = response.json()
        users.extend(data.get('value', []))
        url = data.get('@odata.nextLink')

    print(f"Retrieved {len(users)} users from Microsoft Entra ID")
    return users

def get_user_authentication_methods(access_token, user_id):
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods"
    headers = {'Authorization': access_token}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Failed to fetch authentication methods for {user_id}: {response.text}")
        return []

    return response.json().get('value', [])
######################################## End Get Microsoft Entra ID Users ########################################

######################################## Start Update Microsoft Entra ID User Database ########################################
def update_microsoft_entra_id_user_database(users, access_token):
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    bulk_updates = []
    new_users = []

    for user_data in users:
        if not user_data.get('accountEnabled'):
            continue  # Skip disabled accounts

        upn = user_data['userPrincipalName'].lower()
        user_id = user_data['id']
        employee_id = user_data.get('employeeId', '').lower()
        
        # Convert last logon timestamp correctly
        last_logon_timestamp = user_data.get('extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp')
        if last_logon_timestamp:
            last_logon = make_aware(datetime.utcfromtimestamp(int(last_logon_timestamp) / 10**7 - 11644473600))
        else:
            last_logon = None

        user_fields = {
            'upn': upn,
            'uid': user_id,
            'network_id': employee_id,
            'given_name': user_data.get('givenName', ''),
            'surname': user_data.get('surname', ''),
            'job_title': user_data.get('jobTitle', ''),
            'department': user_data.get('department', ''),
            'last_logon_timestamp': last_logon,
        }

        # Get authentication methods
        auth_methods = get_user_authentication_methods(access_token, user_id)
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
            userdata = UserData.objects.get(upn=upn)
            for field, value in user_fields.items():
                setattr(userdata, field, value)
            userdata.updated_at = now()
            bulk_updates.append(userdata)
        except UserData.DoesNotExist:
            new_users.append(UserData(**user_fields))

    with transaction.atomic():
        if bulk_updates:
            UserData.objects.bulk_update(bulk_updates, user_fields.keys())
        if new_users:
            UserData.objects.bulk_create(new_users)

    print("User database updated successfully")
######################################## End Update Microsoft Entra ID User Database ########################################

######################################## Start Sync Microsoft Entra ID User ########################################
# def syncMicrosoftEntraIDUser():
#     print("starting sync")
#     integration_data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
#     print("Integration data acquired")
#     access_token = getMicrosoftEntraIDAccessToken(integration_data.client_id, integration_data.client_secret, integration_data.tenant_id)
#     print("Access token acquired")
#     users = getMicrosoftEntraIDUsers(access_token)
#     print("Users acquired")
#     updateMicrosoftEntraIDUserDatabase(users, access_token)
#     print("Users updated")
#     integration_data.last_synced_at = timezone.now()
#     integration_data.save()
#     print('Microsoft Entra ID User sync completed successfully')
#     return True
######################################## End Sync Microsoft Entra ID User ########################################

# import threading

# def syncMicrosoftEntraIDUserBackground():
#     thread = threading.Thread(target=syncMicrosoftEntraIDUser)
#     thread.start()

# def sync_microsoft_entra_id_user():
def syncMicrosoftEntraIDUserBackground():
    integration_data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    access_token = get_microsoft_entra_id_access_token(integration_data.client_id, integration_data.client_secret, integration_data.tenant_id)
    users = get_microsoft_entra_id_users(access_token)
    update_microsoft_entra_id_user_database(users, access_token)
    integration_data.last_synced_at = now()
    integration_data.save()
    print("Microsoft Entra ID User sync completed successfully")
    return True