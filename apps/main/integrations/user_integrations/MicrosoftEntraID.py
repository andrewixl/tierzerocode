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

# Constants
PERSONA_GROUPS = [
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
    {"display_name": "Bookings_Scheduling_Mailboxes", "id": "de36d640-878d-47e5-872f-a0da3c5be023"}
]

PERSONA_MAPPING = {
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
    "Bookings_Scheduling_Mailboxes": "Booking Account",
}

AUTHENTICATION_STRENGTHS = {
    "Phishing Resistant": {'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'windowsHelloForBusiness'},
    "Passwordless": {'microsoftAuthenticatorPasswordless'},
    "MFA": {'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'temporaryAccessPass'},
    "Deprecated": {'mobilePhone', 'email', 'securityQuestion'},
    "None": set()
}



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

    return 'Bearer ' + token_result['access_token']

def _fetch_paginated_data(url, headers, max_retries=5, retry_delay=1):
    """Generic function to fetch paginated data with retry logic."""
    results = []
    
    while url:
        for attempt in range(max_retries):
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                results.extend(data.get('value', []))
                url = data.get('@odata.nextLink')
                break
            elif response.status_code == 429:  # Throttling error
                retry_after = int(response.headers.get('Retry-After', retry_delay))
                time.sleep(retry_after)
            else:
                raise Exception(f"Failed to fetch data: {response.status_code} - {response.text}")
        else:
            raise Exception("Max retries exceeded while fetching data.")
        
    return results

def getMicrosoftEntraIDUsers(access_token):
    """Fetch all enabled Microsoft Entra ID users."""
    url = "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,id,employeeId,givenName,surname,accountEnabled,jobTitle,department,createdDateTime,signInActivity&$filter=accountEnabled eq true and userType eq 'Member'"
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

def getMicrosoftEntraIDUserAuthenticationMethods(access_token):
    """Fetch authentication methods for all users."""
    url = f'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?$select=userPrincipalName,isAdmin,isSsprRegistered,isSsprEnabled,isSsprCapable,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

def getPersonaGroupMembership(access_token, group_id):
    """Fetch members of a specific persona group."""
    url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=userPrincipalName'
    headers = {'Authorization': access_token}
    return _fetch_paginated_data(url, headers)

def getPersonaGroupMemberships(access_token):
    """Fetch all persona group memberships for mapping personas."""
    all_members = []
    
    for group in PERSONA_GROUPS:
        group_members = getPersonaGroupMembership(access_token, group["id"])
        for member in group_members:
            member["group_display_name"] = group["display_name"]
        all_members.extend(group_members)

    return all_members

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

def _parse_timestamp(timestamp_str):
    """Parse ISO 8601 timestamp string to timezone-aware datetime."""
    if not timestamp_str:
        return None
    
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return make_aware(dt) if dt.tzinfo is None else dt
    except Exception:
        return None

def _get_user_persona(matching_groups):
    """Determine user persona from matching groups."""
    if len(matching_groups) > 1:
        return "DUPLICATE"
    return PERSONA_MAPPING.get(matching_groups[0], "Unknown") if matching_groups else "Unknown"

def _build_authentication_fields(auth_method_types):
    """Build authentication method fields dynamically."""
    # Map API field names to database field names
    field_mapping = {
        'windowsHelloForBusiness': 'windowsHelloforBusiness',  # API returns this, DB expects this
        'microsoftAuthenticatorPush': 'microsoftAuthenticatorPush',
        'microsoftAuthenticatorPasswordless': 'microsoftAuthenticatorPasswordless',
        'softwareOneTimePasscode': 'softwareOneTimePasscode',
        'temporaryAccessPass': 'temporaryAccessPass',
        'email': 'email',
        'mobilePhone': 'mobilePhone',
        'securityQuestion': 'securityQuestion',
        'passKeyDeviceBound': 'passKeyDeviceBound',
        'passKeyDeviceBoundAuthenticator': 'passKeyDeviceBoundAuthenticator'
    }
    
    auth_fields = {}
    for api_method, db_field in field_mapping.items():
        field_name = f"{db_field}_authentication_method"
        auth_fields[field_name] = api_method in auth_method_types
    return auth_fields

def _update_or_create_user(user_fields, integration):
    """Update existing user or create new one."""
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
    return userdata

def _process_user_data(user_data, authentication_data, persona_memberships):
    """Process individual user data and return user fields."""
    if not user_data.get('userPrincipalName'):
        return None
        
    # Handle disabled accounts
    if user_data.get('accountEnabled') == "false":
        return None
        
    if not user_data.get('employeeId'):
        user_data['employeeId'] = 'none'

    # Parse timestamps
    last_logon = _parse_timestamp(user_data.get('signInActivity', {}).get('lastSuccessfulSignInDateTime'))
    created_at = _parse_timestamp(user_data.get('createdDateTime'))

    # Find user authentication data
    user_authentication_data = next(
        (item for item in authentication_data if item['userPrincipalName'].lower() == user_data['userPrincipalName'].lower()), 
        {}
    )

    # Determine persona
    matching_groups = [
        membership["group_display_name"]
        for membership in persona_memberships
        if membership.get("userPrincipalName", '').lower() == user_data['userPrincipalName'].lower()
    ]
    persona = _get_user_persona(matching_groups)

    # Determine authentication strengths
    auth_method_types = set(user_authentication_data.get('methodsRegistered', []))
    highest_strength, lowest_strength = determine_authentication_strength(auth_method_types)

    # Build user fields
    user_fields = {
        'upn': user_data['userPrincipalName'].lower(),
        'uid': user_data['id'],
        'network_id': user_data['employeeId'].lower(),
        'persona': persona,
        'given_name': user_data.get('givenName', ''),
        'surname': user_data.get('surname', ''),
        'job_title': user_data.get('jobTitle', ''),
        'department': user_data.get('department', ''),
        'last_logon_timestamp': last_logon,
        'created_at_timestamp': created_at,
        'highest_authentication_strength': highest_strength,
        'lowest_authentication_strength': lowest_strength,
    }

    # Add authentication capabilities
    capability_fields = ['isAdmin', 'isMfaCapable', 'isMfaRegistered', 'isPasswordlessCapable', 'isSsprEnabled', 'isSsprRegistered']
    for field in capability_fields:
        user_fields[field] = user_authentication_data.get(field, False)

    # Add authentication methods
    user_fields.update(_build_authentication_fields(auth_method_types))

    return user_fields

def updateMicrosoftEntraIDUserDatabase(users, authentication_data, access_token):
    """Update the local UserData database with Microsoft Entra ID user and authentication data."""
    integration = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    persona_memberships = getPersonaGroupMemberships(access_token)
    processed_upns = set()

    # Process each user
    for user_data in users:
        user_fields = _process_user_data(user_data, authentication_data, persona_memberships)
        if user_fields:
            _update_or_create_user(user_fields, integration)
            processed_upns.add(user_fields['upn'])

    # Clean up users not updated during this sync
    existing_users = UserData.objects.filter(integration=integration)
    for existing_user in existing_users:
        if existing_user.upn not in processed_upns:
            print(f"Deleting user not updated during sync: {existing_user.upn}")
            existing_user.delete()

def syncMicrosoftEntraIDUser():
    """Synchronize Microsoft Entra ID users and update the local database."""
    data = Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User")
    access_token = getMicrosoftEntraIDAccessToken(data.client_id, data.client_secret, data.tenant_id)
    
    users = getMicrosoftEntraIDUsers(access_token)
    authentication_data = getMicrosoftEntraIDUserAuthenticationMethods(access_token)
    updateMicrosoftEntraIDUserDatabase(users, authentication_data, access_token)
    
    data.last_synced_at = timezone.now()
    data.save()
    return True

def syncMicrosoftEntraIDUserBackground(request):
    """Run Microsoft Entra ID user sync in a background thread."""
    def run():
        obj = Notification.objects.create(
            title="Microsoft Entra ID User Integration Sync",
            status="In Progress",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )
        
        try:
            messages.info(request, 'Microsoft Entra ID User Integration Sync in Progress')
            syncMicrosoftEntraIDUser()
            createLog(1505, "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Entra ID User", request.session.get('user_email', 'unknown'))
            obj.status = "Success"
            obj.updated_at = timezone.now()
            obj.save()
            messages.info(request, 'Microsoft Entra ID User Integration Sync Success')
        except Exception as e:
            createLog(1505, "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Entra ID User - {e}", request.session.get('user_email', 'unknown'))
            obj.status = "Failure"
            obj.updated_at = timezone.now()
            obj.save()
            messages.error(request, f'Microsoft Entra ID User Integration Sync Failed: {e}')
    
    thread = threading.Thread(target=run)
    thread.start()