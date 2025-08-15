# Import Dependencies
import msal, requests, threading, time
from django.utils import timezone
from datetime import datetime
from django.contrib import messages
from django.utils.timezone import make_aware
# Import Models
from apps.main.models import Integration, UserData, Notification
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *
from apps.logger.views import createLog

######################################## Start Get Microsoft Entra ID Access Token ########################################
def getMicrosoftEntraIDAccessToken(client_id, client_secret, tenant_id):
    """Acquire an access token for Microsoft Entra ID using MSAL."""
    authority = f'https://login.microsoftonline.com/{tenant_id}'
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
    # url = 'https://graph.microsoft.com/v1.0/groups/148047f5-46e4-4d15-a817-961f9ad1c69e/members?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp,createdDateTime'
    # All Users Minus Guest Accounts:
    url = "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp,createdDateTime&$filter=accountEnabled eq true and userType eq 'Member'"
    # WHfB Test Group
    # url = "https://graph.microsoft.com/v1.0/groups/91ee09a4-d562-4b25-875d-8a6568886b0a/members?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp,createdDateTime"
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
    """Fetch authentication methods for all users."""
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

def getPersonaGroupMembership(access_token, group_id):
    """Fetch members of a specific persona group."""
    url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=userPrincipalName'
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

def getPersonaGroupMemberships(access_token):
    """Fetch all persona group memberships for mapping personas."""
    persona_groups = [
        {"display_name": "myID_Persona_cld_ShdAdm", "id": "b8cc6523-ba76-411b-8535-47ae8281c8eb"},
        {"display_name": "myID_Persona_cld_Contractor", "id": "656ac754-5b1b-42a4-b280-d253edaf7722"},
        {"display_name": "myID_Persona_cld_Emp", "id": "f5370b41-d93d-48cd-9fa7-23e6cce36753"},
        {"display_name": "myID_Persona_cld_IntAdm", "id": "20e88424-9cf6-476b-a27c-96c10ff5cda7"},
        {"display_name": "myID_Persona_cld_SVC_NI", "id": "8fa7006e-8bbc-4251-8685-eee93a976f95"},
        {"display_name": "myID_Persona_cld_Tst", "id": "d4106d05-4f6a-478f-870d-0cdae06bdb25"},
        {"display_name": "myID_Persona_cld_Hourly", "id": "9321dabb-f680-455c-b3cc-a82a3cb906d0"},
        {"display_name": "myID_Persona_cld_Robots", "id": "16dedf78-8029-4005-9d0f-8b423557b17a"},
        {"display_name": "myID_Persona_cld_ExtAdm", "id": "a7f0ed2b-8cb0-465a-9183-f8d48d392076"},
        {"display_name": "myID_Persona_cld_SVC_I", "id": "cf0c33f6-a23a-47fd-801c-667da87f6cfb"},
        {"display_name": "myid_SharedMailbox", "id": "78250c74-8ede-43d1-b3ac-56db4cc5bbce"},
        {"display_name": "myid_ConferenceRooms", "id": "bdd9653e-88b1-477b-931f-32ce6e1c3344"},
        {"display_name": "myid_MonitoringMailboxes", "id": "c90a0e8c-ed3b-41f7-b3a3-32c695351e73"},
    ]

    all_members = []

    for group in persona_groups:
        group_id = group["id"]
        group_members = getPersonaGroupMembership(access_token, group_id)
        for member in group_members:
            member["group_display_name"] = group["display_name"]  # Add group display name to each member
        all_members.extend(group_members)

    return all_members
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
    """Update the local UserData database with Microsoft Entra ID user and authentication data."""
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")  # type: ignore[attr-defined]

    # Fetch all persona group memberships
    persona_memberships = getPersonaGroupMemberships(access_token)

    # Define a mapping of persona groups to persona names
    persona_mapping = {
        "myID_Persona_cld_ShdAdm": "Shared Admin",
        "myID_Persona_cld_Contractor": "External Worker",
        "myID_Persona_cld_Emp": "Internal Worker",
        "myID_Persona_cld_IntAdm": "Internal Admin",
        "myID_Persona_cld_SVC_NI": "Service Account Non-Interactive",
        "myID_Persona_cld_Tst": "Test Account",
        "myID_Persona_cld_Hourly": "Hourly Worker",
        "myID_Persona_cld_Robots": "Robot Account",
        "myID_Persona_cld_ExtAdm": "External Admin",
        "myID_Persona_cld_SVC_I": "Service Account Interactive",
        "myid_SharedMailbox": "Service Account Interactive",
        "myid_ConferenceRooms": "Service Account Interactive",
        "myid_MonitoringMailboxes": "Service Account Interactive",
    }

    for user_data in users:
        if not user_data.get('userPrincipalName'):
            continue
            
        # Handle disabled accounts - delete them from database if they exist
        if user_data.get('accountEnabled') == "false":
            try:
                userdata = UserData.objects.get(upn=user_data['userPrincipalName'].lower())  # type: ignore[attr-defined]
                userdata.delete()
                print(f"Deleted disabled account: {user_data['userPrincipalName']}")
            except UserData.DoesNotExist:  # type: ignore[attr-defined]
                # Account doesn't exist in database, nothing to delete
                pass
            continue
            
        if not user_data.get('employeeId'):
            user_data['employeeId'] = 'none'

        # Convert last logon timestamp
        last_logon = None
        last_logon_timestamp = user_data.get('extension_09474e7580ed457a8d48b4d8698a8f68_lastLogonTimestamp')
        if last_logon_timestamp:
            try:
                last_logon = make_aware(datetime.utcfromtimestamp(int(last_logon_timestamp) / 10**7 - 11644473600))
            except Exception:
                last_logon = None

        # Find user authentication data
        user_authentication_data = next((item for item in authentication_data if item['userPrincipalName'].lower() == user_data['userPrincipalName'].lower()), None) or {}

        # Determine persona groups for the user
        matching_groups = [
            membership["group_display_name"]
            for membership in persona_memberships
            if membership.get("userPrincipalName", '').lower() == user_data['userPrincipalName'].lower()
        ]

        # Check for duplicates
        if len(matching_groups) > 1:
            persona = "DUPLICATE"
        else:
            persona = persona_mapping.get(matching_groups[0], "Unknown") if matching_groups else "Unknown"

        # Determine authentication strengths
        auth_method_types = set(user_authentication_data.get('methodsRegistered', []))
        highest_strength, lowest_strength = determine_authentication_strength(auth_method_types)

        user_fields = {
            'upn': user_data['userPrincipalName'].lower(),
            'uid': user_data['id'],
            'network_id': user_data['employeeId'].lower(),
            'persona': persona,  # Set the persona group
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
            userdata = UserData.objects.get(upn=user_fields['upn'])  # type: ignore[attr-defined]
            for field, value in user_fields.items():
                setattr(userdata, field, value)
            userdata.updated_at = timezone.now()
            userdata.save()
        except UserData.DoesNotExist:  # type: ignore[attr-defined]
            userdata = UserData(**user_fields)
            userdata.save()

        userdata.integration.add(integration)  # type: ignore[attr-defined]
######################################## End Update Microsoft Entra ID User Database ########################################

######################################## Start Sync Microsoft Entra ID User ########################################
def syncMicrosoftEntraIDUser():
    """Synchronize Microsoft Entra ID users and update the local database."""
    data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")  # type: ignore[attr-defined]
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
    """Run Microsoft Entra ID user sync in a background thread."""
    def run():
        obj = Notification.objects.create(
                title="Microsoft Entra ID User Integration Sync",
                status="In Progress",
                created_at=timezone.now(),
                updated_at=timezone.now(),
            )  # type: ignore[attr-defined]
        try:
            messages.info(request, 'Microsoft Entra ID User Integration Sync in Progress')
            syncMicrosoftEntraIDUser()
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Success","Microsoft Entra ID User",request.session.get('user_email', 'unknown'))
            obj.status = "Success"
            obj.updated_at = timezone.now()
            obj.save()
            messages.info(request, 'Microsoft Entra ID User Integration Sync Success')
        except Exception as e:
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Failure",f"Microsoft Entra ID User - {e}",request.session.get('user_email', 'unknown'))
            obj.status = "Failure"
            obj.updated_at = timezone.now()
            obj.save()
            messages.error(request, f'Microsoft Entra ID User Integration Sync Failed: {e}')
    thread = threading.Thread(target=run)
    thread.start()
######################################## End Background Sync Microsoft Intune ########################################