# Standard library imports
import re
import json

# Third-party imports
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.management import call_command
from django.core.paginator import Paginator
from django.db.models import Count, Prefetch, Q
from django.forms.models import model_to_dict
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import render, redirect

# Local imports
from .integrations.cs_health_check import *
from .integrations.device_integrations.CloudflareZeroTrust import *
from .integrations.device_integrations.CrowdStrikeFalcon import *
from .integrations.device_integrations.MicrosoftDefenderforEndpoint import *
from .integrations.device_integrations.MicrosoftEntraID import *
from .integrations.device_integrations.MicrosoftIntune import *
from .integrations.device_integrations.Qualys import *
from .integrations.device_integrations.SophosCentral import *
from .integrations.user_integrations.MicrosoftEntraID import *
from .models import Device, DeviceComplianceSettings, Integration, Notification, UserData

############################################################################################

# Reused Data Sets
#X6969
integration_names = ['Cloudflare Zero Trust', 'CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'Microsoft Entra ID', 'Microsoft Intune', 'Sophos Central', 'Qualys']
user_integration_names = ['Microsoft Entra ID']
#X6969
integration_names_short = ['Cloudflare', 'CrowdStrike', 'Defender', 'Entra ID', 'Intune', 'Sophos', 'Qualys']
user_integration_names_short = ['Entra ID']
os_platforms = ['Android', 'iOS/iPadOS', 'MacOS', 'Ubuntu', 'Windows', 'Windows Server', 'Other']
endpoint_types = ['Client', 'Mobile', 'Server', 'Other']

############################################################################################

def genErrors(request, Emessages):
	for message in Emessages:
		messages.warning(request, message)

def checkDeviceIntegrations(request):
	for integration in integration_names:
		if Integration.objects.filter(integration_type = integration, integration_context = "Device").exists():
			return True
	return False

def checkUserIntegrations(request):
	for integration in user_integration_names:
		if Integration.objects.filter(integration_type = integration, integration_context = "User").exists():
			return True
	return False
		
def checkDeviceComplianceSettings(request):
	for os_platform in os_platforms:
		if DeviceComplianceSettings.objects.filter(os_platform = os_platform).exists():
			return True
	return False
		
def initialChecks(request):
	results = [checkDeviceIntegrations(request), checkUserIntegrations(request), checkDeviceComplianceSettings(request)]
	for result in results:
		if not result:
			genErrors(request, ["Initial Setup Required"])
			return '/initial-setup'
	return None
	
def getEnabledIntegrations():
	return Integration.objects.filter(enabled=True, integration_context="Device")

def getEnabledUserIntegrations():
	return Integration.objects.filter(enabled=True, integration_context="User")

def complianceSettings(os_platform):
	try:
		settings = DeviceComplianceSettings.objects.get(os_platform=os_platform)
		return {
            'Cloudflare Zero Trust': settings.cloudflare_zero_trust,
            'CrowdStrike Falcon': settings.crowdstrike_falcon,
            'Microsoft Defender for Endpoint': settings.microsoft_defender_for_endpoint,
            'Microsoft Entra ID': settings.microsoft_entra_id,
            'Microsoft Intune': settings.microsoft_intune,
            'Sophos Central': settings.sophos_central,
            'Qualys': settings.qualys,
        }
	except DeviceComplianceSettings.DoesNotExist:
		return {}

@login_required
def test(request):
	# Device.objects.all().delete()
	# Integration.objects.all().delete()
	UserData.objects.all().delete()
	return redirect('/')

############################################################################################	

# Mapping for short integration names
integration_short_map = dict(zip(integration_names, integration_names_short))
user_integration_short_map = dict(zip(user_integration_names, user_integration_names_short))

# Creates blank integration templates if they do not exist
def initialSetup(request):
	for integration in integration_names:
		if not Integration.objects.filter(integration_type=integration, integration_context="Device").exists():
			image_navbar_path = 'main/img/navbar_icons/webp/' + (integration.replace(" ", "_")).lower() + '_logo_nav.webp'
			image_integration_path = 'main/img/integration_images/webp/' + (integration.replace(" ", "_")).lower() + '_logo.webp'
			integration_short = integration_short_map[integration]
			Integration.objects.create(enabled=False, integration_type=integration, integration_type_short=integration_short, integration_context="Device", image_navbar_path=image_navbar_path, image_integration_path=image_integration_path)
	
	for integration in user_integration_names:
		if not Integration.objects.filter(integration_type=integration, integration_context="User").exists():
			image_navbar_path = 'main/img/navbar_icons/webp/' + (integration.replace(" ", "_")).lower() + '_logo_nav.webp'
			image_integration_path = 'main/img/integration_images/webp/' + (integration.replace(" ", "_")).lower() + '_logo.webp'
			integration_short = user_integration_short_map[integration]
			Integration.objects.create(enabled=False, integration_type=integration, integration_type_short=integration_short, integration_context="User", image_navbar_path=image_navbar_path, image_integration_path=image_integration_path)

	for os_platform in os_platforms:
		if not DeviceComplianceSettings.objects.filter(os_platform=os_platform).exists():
			DeviceComplianceSettings.objects.create(os_platform=os_platform, cloudflare_zero_trust=True, crowdstrike_falcon=True, microsoft_defender_for_endpoint=True, microsoft_entra_id=True, microsoft_intune=True, sophos_central=True, qualys=True)

	return redirect(request.META.get('HTTP_REFERER', '/'))

############################################################################################

@login_required
def migration(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("Unauthorized".encode())
    call_command('migrate')
    return HttpResponse("Migrations applied.".encode())

############################################################################################

@login_required
def index(request):
	access_token = getMicrosoftEntraIDAccessToken(Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User").client_id, Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User").client_secret, Integration.objects.get(integration_type="Microsoft Entra ID", integration_context="User").tenant_id)
	guests = getMicrosoftEntraIDGuests(access_token)
	groups = getMicrosoftEntraIDGroups(access_token)
	apps = getMicrosoftEntraIDApps(access_token)
	devices = Device.objects.count()
	managed = Device.objects.filter(integrationMicrosoftEntraID__isManaged=True).count()

	auth_strength_counts = UserData.objects.aggregate(
        count_phishing_resistant=Count('id', filter=Q(highest_authentication_strength='Phishing Resistant')),
        count_passwordless=Count('id', filter=Q(highest_authentication_strength='Passwordless')),
        count_mfa=Count('id', filter=Q(highest_authentication_strength='MFA')),
        count_deprecated=Count('id', filter=Q(highest_authentication_strength='Deprecated')),
        count_none=Count('id', filter=Q(highest_authentication_strength='None')),
        count_low_phishing_resistant=Count('id', filter=Q(lowest_authentication_strength='Phishing Resistant')),
        count_low_passwordless=Count('id', filter=Q(lowest_authentication_strength='Passwordless')),
        count_low_mfa=Count('id', filter=Q(lowest_authentication_strength='MFA')),
        count_low_deprecated=Count('id', filter=Q(lowest_authentication_strength='Deprecated')),
        count_low_none=Count('id', filter=Q(lowest_authentication_strength='None')),
    )
	
	# Calculate auth method flow counts for Sankey diagram
	# Count users with each authentication method
	passkey_users = UserData.objects.filter(Q(passKeyDeviceBound_authentication_method=True) | Q(passKeyDeviceBoundAuthenticator_authentication_method=True))
	whfb_users = UserData.objects.filter(windowsHelloforBusiness_authentication_method=True)
	authenticator_users = UserData.objects.filter(microsoftAuthenticatorPush_authentication_method=True)
	phone_users = UserData.objects.filter(mobilePhone_authentication_method=True)
	single_factor_users = UserData.objects.filter(Q(highest_authentication_strength='None') | Q(highest_authentication_strength='Deprecated'))
	
	# Count users in phish-resistant category (have passkey or WHfB)
	phish_resistant_users = UserData.objects.filter(
		Q(passKeyDeviceBound_authentication_method=True) | 
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True) | 
		Q(windowsHelloforBusiness_authentication_method=True)
	)
	
	# Count users in phishable category (have authenticator or phone, but exclude single factor)
	phishable_users = UserData.objects.filter(
		Q(microsoftAuthenticatorPush_authentication_method=True) | 
		Q(mobilePhone_authentication_method=True)
	).exclude(
		Q(highest_authentication_strength='None') | 
		Q(highest_authentication_strength='Deprecated')
	)
	
	auth_flow_counts = {
		'users_to_phish_resistant': phish_resistant_users.count(),
		'users_to_phishable': phishable_users.count(),
		'users_to_single_factor': single_factor_users.count(),
		'phish_resistant_to_passkey': passkey_users.count(),
		'phish_resistant_to_whfb': whfb_users.count(),
		'phishable_to_authenticator': authenticator_users.count(),
		'phishable_to_phone': phone_users.count(),
	}

	sk1_privileged_users = UserData.objects.filter(isAdmin=True)
	sk1_count_privileged_users = sk1_privileged_users.count()
	
	# Phishing Resistant users (have passkey OR WHfB, regardless of other methods)
	# Priority: Passkey > WHfB (if user has both, count as Passkey)
	sk1_count_privileged_passkey_users = sk1_privileged_users.filter(
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True)
	).count()
	sk1_count_privileged_whfb_users = sk1_privileged_users.filter(
		Q(windowsHelloforBusiness_authentication_method=True)
	).exclude(
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True)
	).count()
	sk1_count_privileged_phishing_resistant_users = sk1_count_privileged_passkey_users + sk1_count_privileged_whfb_users
	
	# Phishable users (have phone OR authenticator, but NOT phishing resistant)
	# Priority: Phone > Authenticator (if user has both, count as Phone)
	sk1_count_privileged_phone_users = sk1_privileged_users.filter(
		Q(mobilePhone_authentication_method=True)
	).exclude(
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
		Q(windowsHelloforBusiness_authentication_method=True)
	).count()
	sk1_count_privileged_authenticator_users = sk1_privileged_users.filter(
		Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
		Q(microsoftAuthenticatorPush_authentication_method=True)
	).exclude(
		Q(mobilePhone_authentication_method=True) |
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
		Q(windowsHelloforBusiness_authentication_method=True)
	).count()
	sk1_count_privileged_phishable_users = sk1_count_privileged_phone_users + sk1_count_privileged_authenticator_users
	
	# Single Factor users (none of the above methods)
	# Calculate as: total - phishing_resistant - phishable to ensure all users are accounted for
	sk1_count_privileged_single_factor_users = sk1_count_privileged_users - sk1_count_privileged_phishing_resistant_users - sk1_count_privileged_phishable_users
	# Ensure it's not negative (shouldn't happen, but safety check)
	if sk1_count_privileged_single_factor_users < 0:
		sk1_count_privileged_single_factor_users = 0



	sk2_users = UserData.objects.all()
	sk2_count_users = sk2_users.count()
	
	# Phishing Resistant users (have passkey OR WHfB, regardless of other methods)
	# Priority: Passkey > WHfB (if user has both, count as Passkey)
	sk2_count_passkey_users = sk2_users.filter(
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True)
	).count()
	sk2_count_whfb_users = sk2_users.filter(
		Q(windowsHelloforBusiness_authentication_method=True)
	).exclude(
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True)
	).count()
	sk2_count_phishing_resistant_users = sk2_count_passkey_users + sk2_count_whfb_users
	
	# Phishable users (have phone OR authenticator, but NOT phishing resistant)
	# Priority: Phone > Authenticator (if user has both, count as Phone)
	sk2_count_phone_users = sk2_users.filter(
		Q(mobilePhone_authentication_method=True)
	).exclude(
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
		Q(windowsHelloforBusiness_authentication_method=True)
	).count()
	sk2_count_authenticator_users = sk2_users.filter(
		Q(microsoftAuthenticatorPasswordless_authentication_method=True) |
		Q(microsoftAuthenticatorPush_authentication_method=True)
	).exclude(
		Q(mobilePhone_authentication_method=True) |
		Q(passKeyDeviceBound_authentication_method=True) |
		Q(passKeyDeviceBoundAuthenticator_authentication_method=True) |
		Q(windowsHelloforBusiness_authentication_method=True)
	).count()
	sk2_count_phishable_users = sk2_count_phone_users + sk2_count_authenticator_users
	
	# Single Factor users (none of the above methods)
	# Calculate as: total - phishing_resistant - phishable to ensure all users are accounted for
	sk2_count_single_factor_users = sk2_count_users - sk2_count_phishing_resistant_users - sk2_count_phishable_users
	# Ensure it's not negative (shouldn't happen, but safety check)
	if sk2_count_single_factor_users < 0:
		sk2_count_single_factor_users = 0
	


	



	context = {
        'page': 'dashboard',
		'count_users': UserData.objects.count(),
        'count_guests': guests,
        'count_groups': groups,
        'count_apps': apps,
        'count_devices': devices,
        'count_managed': managed,
		'auth_method_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
		'auth_method_data': [
            auth_strength_counts['count_phishing_resistant'],
            auth_strength_counts['count_passwordless'],
            auth_strength_counts['count_mfa'],
            auth_strength_counts['count_deprecated'],
            auth_strength_counts['count_none'],
        ],
		'auth_flow_counts': json.dumps(auth_flow_counts),
        'enabled_integrations': getEnabledIntegrations(),
        'enabled_user_integrations': getEnabledUserIntegrations(),
        'notifications': Notification.objects.all(),

		'sk1_count_privileged_users': sk1_count_privileged_users,
		'sk1_count_privileged_single_factor_users': sk1_count_privileged_single_factor_users,
		'sk1_count_privileged_phone_users': sk1_count_privileged_phone_users,
		'sk1_count_privileged_authenticator_users': sk1_count_privileged_authenticator_users,
		'sk1_count_privileged_phishable_users': sk1_count_privileged_phishable_users,
		'sk1_count_privileged_passkey_users': sk1_count_privileged_passkey_users,
		'sk1_count_privileged_whfb_users': sk1_count_privileged_whfb_users,
		'sk1_count_privileged_phishing_resistant_users': sk1_count_privileged_phishing_resistant_users,

		'sk2_count_users': sk2_count_users,
		'sk2_count_single_factor_users': sk2_count_single_factor_users,
		'sk2_count_phone_users': sk2_count_phone_users,
		'sk2_count_authenticator_users': sk2_count_authenticator_users,
		'sk2_count_phishable_users': sk2_count_phishable_users,
		'sk2_count_passkey_users': sk2_count_passkey_users,
		'sk2_count_whfb_users': sk2_count_whfb_users,
		'sk2_count_phishing_resistant_users': sk2_count_phishing_resistant_users,
    }
	return render(request, 'main/index.html', context)

############################################################################################

@login_required
def indexDevice(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	# Fetch all enabled integrations in a single query
	enabled_integrations = getEnabledIntegrations()

	# Count of devices for each integration
	integration_device_counts = [["Master List Endpoints", Device.objects.count()]]
	integrations_with_data = Integration.objects.filter(integration_type__in=integration_names, enabled=True, integration_context="Device")
	for integration in integrations_with_data:
		integration_device_counts.append([integration.integration_type, Device.objects.filter(integration__integration_type=integration).count(), integration.image_navbar_path])

	# Count each os platform and endpoint type
	os_platform_counts = Device.objects.values('osPlatform').annotate(count=Count('osPlatform'))
	endpoint_type_counts = Device.objects.values('endpointType').annotate(count=Count('endpointType'))

	osPlatformData = [next((item['count'] for item in os_platform_counts if item['osPlatform'] == os_platform), 0) for os_platform in os_platforms]
	endpointTypeData = [next((item['count'] for item in endpoint_type_counts if item['endpointType'] == endpoint_type), 0) for endpoint_type in endpoint_types]

	count_all_true = Device.objects.filter(compliant=True).count()
	count_any_false = Device.objects.filter(compliant=False).count()
 
	context = {
		'page': 'device-dashboard',
		'enabled_integrations': enabled_integrations,
		'enabled_user_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.all(),
		'endpoint_device_counts': integration_device_counts,
		'osPlatformLabels': os_platforms,
		'osPlatformData': osPlatformData,
		'endpointTypeLabels': endpoint_types,
		'endpointTypeData': endpointTypeData,
		'compliantLabels': ['Compliant', 'Non-Compliant'],
		'compliantData': [count_all_true, count_any_false],
    }
	return render(request, 'main/index-device.html', context)

@login_required
def indexUser(request):
	# test()
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	# of Users that have adopted each authentication method
	users = UserData.objects.all()
 
   # Aggregate counts for highest and lowest authentication strengths
	auth_strength_counts = UserData.objects.aggregate(
        count_phishing_resistant=Count('id', filter=Q(highest_authentication_strength='Phishing Resistant')),
        count_passwordless=Count('id', filter=Q(highest_authentication_strength='Passwordless')),
        count_mfa=Count('id', filter=Q(highest_authentication_strength='MFA')),
        count_deprecated=Count('id', filter=Q(highest_authentication_strength='Deprecated')),
        count_none=Count('id', filter=Q(highest_authentication_strength='None')),
        count_low_phishing_resistant=Count('id', filter=Q(lowest_authentication_strength='Phishing Resistant')),
        count_low_passwordless=Count('id', filter=Q(lowest_authentication_strength='Passwordless')),
        count_low_mfa=Count('id', filter=Q(lowest_authentication_strength='MFA')),
        count_low_deprecated=Count('id', filter=Q(lowest_authentication_strength='Deprecated')),
        count_low_none=Count('id', filter=Q(lowest_authentication_strength='None')),
    )
   
   # Count passwordless and non-passwordless users
	passwordless_capable_count = UserData.objects.filter(
        Q(highest_authentication_strength__in=['Passwordless', 'Phishing Resistant'])
    ).count()
	non_passwordless_capable_count = UserData.objects.exclude(
        highest_authentication_strength__in=['Passwordless', 'Phishing Resistant']
    ).count()
 
	persona_counts = UserData.objects.values('persona').annotate(count=Count('id'))
	persona_map = {item['persona']: item['count'] for item in persona_counts}
 
	context = {
		'page': 'user-dashboard',
		'enabled_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.all(),
        'auth_method_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_data': [
            auth_strength_counts['count_phishing_resistant'],
            auth_strength_counts['count_passwordless'],
            auth_strength_counts['count_mfa'],
            auth_strength_counts['count_deprecated'],
            auth_strength_counts['count_none'],
        ],
        'auth_method_low_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_low_data': [
            auth_strength_counts['count_low_phishing_resistant'],
            auth_strength_counts['count_low_passwordless'],
            auth_strength_counts['count_low_mfa'],
            auth_strength_counts['count_low_deprecated'],
            auth_strength_counts['count_low_none'],
        ],
        'count_passwordless_capable_labels': ['Passwordless', 'Non-Passwordless'],
        'count_passwordless_capable_data': [passwordless_capable_count, non_passwordless_capable_count],
        'count_internal_worker': persona_map.get('Internal Worker', 0),
        'count_internal_admin': persona_map.get('Internal Admin', 0),
        'count_external_worker': persona_map.get('External Worker', 0),
        'count_external_admin': persona_map.get('External Admin', 0),
        'count_hourly_worker': persona_map.get('Hourly Worker', 0),
        'count_test_account': persona_map.get('Test Account', 0),
        'count_robot_account': persona_map.get('Robot Account', 0),
        'count_shared_admin': persona_map.get('Shared Admin', 0),
        'count_service_account': (
            persona_map.get('Service Account Non-Interactive', 0)
            + persona_map.get('Service Account Interactive', 0)
        ),
		'auth_method_adoption_labels': ['Windows Hello for Business', 'Passkey Device', 'Passkey Authenticator', 'MS Authenticator Passwordless', 'MS Authenticator Push', 'Software OTP', 'Mobile Phone'],
		'auth_method_adoption_data': [
			users.filter(windowsHelloforBusiness_authentication_method=True).count(),
			users.filter(passKeyDeviceBound_authentication_method=True).count(),
			users.filter(passKeyDeviceBoundAuthenticator_authentication_method=True).count(),
			users.filter(microsoftAuthenticatorPasswordless_authentication_method=True).count(),
			users.filter(microsoftAuthenticatorPush_authentication_method=True).count(),
			users.filter(softwareOneTimePasscode_authentication_method=True).count(),
			users.filter(mobilePhone_authentication_method=True).count(),
		],
        'count_unknown_account': persona_map.get('Unknown', 0),
        'count_duplicate_account': persona_map.get('DUPLICATE', 0),
    }
	return render(request, 'main/index-user.html', context)

############################################################################################

@login_required
def personaMetrics(request, persona):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	# of Users that have adopted each authentication method
	persona = persona.replace("-", " ").title()
	users = UserData.objects.filter(persona=persona)
 
   # Aggregate counts for highest and lowest authentication strengths
	auth_strength_counts = users.aggregate(
        count_phishing_resistant=Count('id', filter=Q(highest_authentication_strength='Phishing Resistant')),
        count_passwordless=Count('id', filter=Q(highest_authentication_strength='Passwordless')),
        count_mfa=Count('id', filter=Q(highest_authentication_strength='MFA')),
        count_deprecated=Count('id', filter=Q(highest_authentication_strength='Deprecated')),
        count_none=Count('id', filter=Q(highest_authentication_strength='None')),
        count_low_phishing_resistant=Count('id', filter=Q(lowest_authentication_strength='Phishing Resistant')),
        count_low_passwordless=Count('id', filter=Q(lowest_authentication_strength='Passwordless')),
        count_low_mfa=Count('id', filter=Q(lowest_authentication_strength='MFA')),
        count_low_deprecated=Count('id', filter=Q(lowest_authentication_strength='Deprecated')),
        count_low_none=Count('id', filter=Q(lowest_authentication_strength='None')),
    )

	passwordless_capable_count = users.filter(
        Q(highest_authentication_strength__in=['Passwordless', 'Phishing Resistant'])
    ).count()
	non_passwordless_capable_count = users.exclude(
        highest_authentication_strength__in=['Passwordless', 'Phishing Resistant']
    ).count()

	user_list = []
	for user_data in users:		
		user_list.append([user_data, user_data.passKeyDeviceBound_authentication_method, user_data.passKeyDeviceBoundAuthenticator_authentication_method, user_data.windowsHelloforBusiness_authentication_method, user_data.microsoftAuthenticatorPasswordless_authentication_method, user_data.microsoftAuthenticatorPush_authentication_method, user_data.softwareOneTimePasscode_authentication_method, user_data.temporaryAccessPass_authentication_method, user_data.mobilePhone_authentication_method, user_data.email_authentication_method, user_data.securityQuestion_authentication_method])
 
	context = {
		'page': 'user-dashboard',
		'enabled_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.all(),
		'persona': persona,
		'persona_count': users.count(),
		'percent_mfa': "{:.2f}".format(((auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless'] + auth_strength_counts['count_mfa'] + auth_strength_counts['count_deprecated']) / users.count()) * 100 if users.count() > 0 else 0),
		'count_mfa': auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless'] + auth_strength_counts['count_mfa'] + auth_strength_counts['count_deprecated'],
		'percent_phishing_resistant': "{:.2f}".format(((auth_strength_counts['count_phishing_resistant']) / users.count()) * 100 if users.count() > 0 else 0),
		'count_phishing_resistant': auth_strength_counts['count_phishing_resistant'],
		'percent_passwordless': "{:.2f}".format(((auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless']) / users.count()) * 100 if users.count() > 0 else 0),
		'count_passwordless': (auth_strength_counts['count_phishing_resistant'] + auth_strength_counts['count_passwordless']),
		'auth_method_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_data': [
            auth_strength_counts['count_phishing_resistant'],
            auth_strength_counts['count_passwordless'],
            auth_strength_counts['count_mfa'],
            auth_strength_counts['count_deprecated'],
            auth_strength_counts['count_none'],
        ],
        'auth_method_low_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
        'auth_method_low_data': [
            auth_strength_counts['count_low_phishing_resistant'],
            auth_strength_counts['count_low_passwordless'],
            auth_strength_counts['count_low_mfa'],
            auth_strength_counts['count_low_deprecated'],
            auth_strength_counts['count_low_none'],
        ],
		'auth_method_adoption_labels': ['Windows Hello for Business', 'Passkey Device', 'Passkey Authenticator', 'MS Authenticator Passwordless', 'MS Authenticator Push', 'Software OTP', 'Mobile Phone'],
		'auth_method_adoption_data': [
			users.filter(windowsHelloforBusiness_authentication_method=True).count(),
			users.filter(passKeyDeviceBound_authentication_method=True).count(),
			users.filter(passKeyDeviceBoundAuthenticator_authentication_method=True).count(),
			users.filter(microsoftAuthenticatorPasswordless_authentication_method=True).count(),
			users.filter(microsoftAuthenticatorPush_authentication_method=True).count(),
			users.filter(softwareOneTimePasscode_authentication_method=True).count(),
			users.filter(mobilePhone_authentication_method=True).count(),
		],
        'count_passwordless_capable_labels': ['Passwordless', 'Non-Passwordless'],
        'count_passwordless_capable_data': [passwordless_capable_count, non_passwordless_capable_count],

		'auth_strengths': ['None', 'MFA', 'Passwordless', 'Phishing Resistant', 'Deprecated'],
        'personas': ['Internal Worker', 'Internal Admin', 'External Worker', 'External Admin', 'Hourly Worker', 'Test Account', 'Robot Account', 'Shared Admin', 'OnPrem Internal Admin', 'OnPrem External Admin', 'Service Account Non-Interactive', 'Service Account Interactive', 'OnPrem Service Account Non-Interactive', 'OnPrem Service Account Interactive', 'Unknown', 'DUPLICATE'],
		'user_list':user_list,
    }
	return render(request, 'main/persona-metrics.html', context)

############################################################################################

@login_required
def profileSettings(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	# Import the new utilities
	from .utils import ComplianceSettingsManager, DeviceComplianceChecker
	
	# Get compliance settings using the new manager
	compliance_settings = ComplianceSettingsManager.get_all_compliance_settings()
	
	# Get compliance summary for dashboard
	compliance_summary = ComplianceSettingsManager.get_compliance_summary()
	
	# Get compliance report for insights
	compliance_report = DeviceComplianceChecker.get_compliance_report()

	context = {
		'page': "profile-settings",
		'enabled_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.all(),
		'devicecomps': compliance_settings,  # Use the new structured data
		'compliance_summary': compliance_summary,
		'compliance_report': compliance_report,
	}
	
	# Use the new structured format
	context['devicecomps'] = compliance_settings
	
	return render(request, 'main/profile-settings.html', context)

@login_required
def update_compliance(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	if request.method == 'POST':
		from .utils import ComplianceSettingsManager
		
		# Parse the form data to extract integration settings
		integration_settings = {}
		integration_mapping = {
			'Cloudflare Zero Trust': 'Cloudflare Zero Trust',
			'Crowdstrike Falcon': 'Crowdstrike Falcon', 
			'Microsoft Defender For Endpoint': 'Microsoft Defender For Endpoint',
			'Microsoft Entra Id': 'Microsoft Entra Id',
			'Microsoft Intune': 'Microsoft Intune',
			'Sophos Central': 'Sophos Central',
			'Qualys': 'Qualys'
		}
		
		for integration_name, field_name in integration_mapping.items():
			# Check if the integration is enabled (checkbox was checked)
			is_enabled = request.POST.get(field_name) == 'on'
			integration_settings[integration_name] = is_enabled
		
		# Update the compliance settings using the manager
		success = ComplianceSettingsManager.update_compliance_settings(id, integration_settings)
		
		if success:
			messages.success(request, 'Compliance settings updated successfully!')
		else:
			messages.error(request, 'Failed to update compliance settings.')
	
	return redirect('/profile-settings')

############################################################################################

@login_required
def deviceData(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	# X6969
	# Creates the device object with related data preloaded from each integration
	devices =  Device.objects.filter(id=id).prefetch_related('integrationCloudflareZeroTrust', 'integrationCrowdStrikeFalcon', 'integrationMicrosoftDefenderForEndpoint', 'integrationMicrosoftEntraID', 'integrationIntune', 'integrationSophos', 'integrationQualys')
	# Selects the 1st and only device since prefetch_related required a filter
	device =  devices[0]
	# Gets current integrations for the device
	integrations = device.integration.all()
	# Creates a list of the integration types for the device
	integration_list = []
	for integration in integrations:
		integration_list.append(integration.integration_type)
	
	cloudflare_device = None
	crowdstrike_device = None
	defender_device = None
	entra_device = None
	intune_device = None
	sophos_device = None
	qualys_device = None
	for integration in integration_list:
		# X6969
		# if integration == 'Cloudflare Zero Trust':
		# 	device.integrationCloudflareZeroTrust.get(deviceName=device.hostname.upper())
		if integration == 'CrowdStrike Falcon':
			crowdstrike_device_list = model_to_dict((device.integrationCrowdStrikeFalcon.filter(hostname=device.hostname))[0])
			crowdstrike_device = {}
			for key in crowdstrike_device_list:
				crowdstrike_device[re.sub(r'([a-z])([A-Z])', r'\1 \2', key).title()] = crowdstrike_device_list[key]
		elif integration == 'Microsoft Defender for Endpoint':
			defender_device_list = model_to_dict((device.integrationMicrosoftDefenderForEndpoint.filter(computerDnsName=device.hostname))[0])
			defender_device = {}
			for key in defender_device_list:
				defender_device[re.sub(r'([a-z])([A-Z])', r'\1 \2', key).title()] = defender_device_list[key]
		elif integration == 'Microsoft Entra ID':
			entra_device_list = model_to_dict((device.integrationMicrosoftEntraID.filter(displayName=device.hostname))[0])
			entra_device = {}
			for key in entra_device_list:
				entra_device[re.sub(r'([a-z])([A-Z])', r'\1 \2', key).title()] = entra_device_list[key]
		elif integration == 'Microsoft Intune':
			intune_device_list = model_to_dict((device.integrationIntune.filter(deviceName=device.hostname))[0])
			intune_device = {}
			for key in intune_device_list:
				intune_device[re.sub(r'([a-z])([A-Z])', r'\1 \2', key).title()] = intune_device_list[key]
		elif integration == 'Sophos Central':
			sophos_device_list = model_to_dict((device.integrationSophos.filter(hostname=device.hostname))[0])
			sophos_device = {}
			for key in sophos_device_list:
				sophos_device[re.sub(r'([a-z])([A-Z])', r'\1 \2', key).title()] = sophos_device_list[key]
		# elif integration == 'Qualys':
		# 	device.integrationQualys.get(deviceName=device.hostname.upper())

	integrations = device.integration.all()
	
	context = {
		'page':"device-data",
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.all(),
		'device':device,
		'ints' : integrations,
		# X6969
		"crowdstrike_device":crowdstrike_device,
		"defender_device":defender_device,
		'entra_device':entra_device,
		'intune_device':intune_device,
		'sophos_device':sophos_device,
	}
	return render( request, 'main/device-data.html', context)

############################################################################################

@login_required
def masterList(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	enabled_integrations = getEnabledIntegrations()
	endpoint_list = []

	endpoints = Device.objects.prefetch_related(Prefetch('integration', queryset=Integration.objects.filter(enabled=True))).all()
	for endpoint in endpoints:
		endpoint_data = [endpoint]
		os_platform = endpoint.osPlatform
		compliance_settings = complianceSettings(os_platform)
	
		for integration in enabled_integrations:
			integration_type = integration.integration_type
			compliance_setting = compliance_settings.get(integration_type)
			if compliance_setting is False:
				endpoint_data.append(None)
			else:
				is_enabled = endpoint.integration.filter(id=integration.id).exists()
				endpoint_data.append(is_enabled)
		
		endpoint_list.append(endpoint_data)

	context = {
		'page':"master-list",
		'enabled_integrations': enabled_integrations,
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.all(),
		'endpoint_list':endpoint_list,
		'os_platforms': os_platforms,
		'endpoint_types': endpoint_types,
	}
	return render( request, 'main/master-list.html', context)

############################################################################################

@login_required
def userMasterList(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	user_data_list = UserData.objects.all()
	user_list = []
	for user_data in user_data_list:		
		user_list.append([user_data, user_data.passKeyDeviceBound_authentication_method, user_data.passKeyDeviceBoundAuthenticator_authentication_method, user_data.windowsHelloforBusiness_authentication_method, user_data.microsoftAuthenticatorPasswordless_authentication_method, user_data.microsoftAuthenticatorPush_authentication_method, user_data.softwareOneTimePasscode_authentication_method, user_data.temporaryAccessPass_authentication_method, user_data.mobilePhone_authentication_method, user_data.email_authentication_method, user_data.securityQuestion_authentication_method])

	context = {
		'page':"master-list-user",
		'enabled_integrations': getEnabledIntegrations(),
		'notifications': Notification.objects.all(),
		'auth_strengths': ['None', 'MFA', 'Passwordless', 'Phishing Resistant', 'Deprecated'],
        'personas': ['Internal Worker', 'Internal Admin', 'External Worker', 'External Admin', 'Hourly Worker', 'Test Account', 'Robot Account', 'Shared Admin', 'OnPrem Internal Admin', 'OnPrem External Admin', 'Service Account Non-Interactive', 'Service Account Interactive', 'OnPrem Service Account Non-Interactive', 'OnPrem Service Account Interactive', 'Unknown', 'DUPLICATE'],
		'user_list':user_list,
	}
	return render( request, 'main/user-master-list.html', context)

############################################################################################

@login_required
def user_master_list_api(request):
    # DataTables parameters
    draw = int(request.GET.get('draw', 1))
    start = int(request.GET.get('start', 0))
    length = int(request.GET.get('length', 10))
    search_value = request.GET.get('search[value]', '')
    
    # Sorting parameters
    order_column = request.GET.get('order[0][column]', '0')
    order_dir = request.GET.get('order[0][dir]', 'asc')
    
    # Column mapping for sorting (must match the order in your table headers)
    columns = ['upn', 'persona', 'created_at_timestamp', 'last_logon_timestamp', 
               'highest_authentication_strength', 'lowest_authentication_strength',
               'passKeyDeviceBound_authentication_method', 'passKeyDeviceBoundAuthenticator_authentication_method',
               'windowsHelloforBusiness_authentication_method', 'microsoftAuthenticatorPasswordless_authentication_method',
               'microsoftAuthenticatorPush_authentication_method', 'softwareOneTimePasscode_authentication_method',
               'temporaryAccessPass_authentication_method', 'mobilePhone_authentication_method',
               'email_authentication_method', 'securityQuestion_authentication_method']

    # Filtering
    highest_auth = request.GET.getlist('highest_auth[]')
    lowest_auth = request.GET.getlist('lowest_auth[]')
    personas = request.GET.getlist('personas[]')

    users = UserData.objects.all()

    # Apply sorting
    if order_column.isdigit() and int(order_column) < len(columns):
        sort_field = columns[int(order_column)]
        if order_dir == 'desc':
            sort_field = f'-{sort_field}'
        users = users.order_by(sort_field)
    else:
        users = users.order_by('upn')  # Default sorting

    # Apply filters
    if highest_auth:
        users = users.filter(highest_authentication_strength__in=highest_auth)
    if lowest_auth:
        users = users.filter(lowest_authentication_strength__in=lowest_auth)
    if personas:
        users = users.filter(persona__in=personas)
    if search_value:
        users = users.filter(upn__icontains=search_value)

    total = users.count()

    # Pagination
    paginator = Paginator(users, length)
    page_number = (start // length) + 1
    page = paginator.get_page(page_number)

    data = []
    for user_data in page.object_list:
        row = [
            f'<a href="/device/{user_data.id}">{user_data.upn}</a>',
            user_data.persona,
            user_data.created_at_timestamp,
            user_data.last_logon_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.last_logon_timestamp else "",
            user_data.highest_authentication_strength,
            user_data.lowest_authentication_strength,
            "&#9989;" if user_data.passKeyDeviceBound_authentication_method else "&#10060;",
            "&#9989;" if user_data.passKeyDeviceBoundAuthenticator_authentication_method else "&#10060;",
            "&#9989;" if user_data.windowsHelloforBusiness_authentication_method else "&#10060;",
            "&#9989;" if user_data.microsoftAuthenticatorPasswordless_authentication_method else "&#10060;",
            "&#9989;" if user_data.microsoftAuthenticatorPush_authentication_method else "&#10060;",
            "&#9989;" if user_data.softwareOneTimePasscode_authentication_method else "&#10060;",
            "&#9989;" if user_data.temporaryAccessPass_authentication_method else "&#10060;",
            "&#9989;" if user_data.mobilePhone_authentication_method else "&#10060;",
            "&#9989;" if user_data.email_authentication_method else "&#10060;",
            "&#9989;" if user_data.securityQuestion_authentication_method else "&#10060;",
        ]
        data.append(row)

    return JsonResponse({
        "draw": draw,
        "recordsTotal": total,
        "recordsFiltered": total,
        "data": data,
    })

@login_required
def user_master_list_export_api(request):
    """API endpoint for exporting all user data without pagination"""
    # Filtering
    highest_auth = request.GET.getlist('highest_auth[]')
    lowest_auth = request.GET.getlist('lowest_auth[]')
    personas = request.GET.getlist('personas[]')
    search_value = request.GET.get('search[value]', '')

    users = UserData.objects.all().order_by('upn')

    if highest_auth:
        users = users.filter(highest_authentication_strength__in=highest_auth)
    if lowest_auth:
        users = users.filter(lowest_authentication_strength__in=lowest_auth)
    if personas:
        users = users.filter(persona__in=personas)
    if search_value:
        users = users.filter(upn__icontains=search_value)

    data = []
    for user_data in users:
        try:
            # Handle null values safely
            created_at = user_data.created_at_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.created_at_timestamp else ""
            last_logon = user_data.last_logon_timestamp.strftime("%Y-%m-%d %H:%M:%S") if user_data.last_logon_timestamp else ""
            
            row = [
                user_data.upn or "",  # Handle null UPN
                user_data.persona or "",  # Handle null persona
                created_at,
                last_logon,
                user_data.highest_authentication_strength or "",
                user_data.lowest_authentication_strength or "",
                "Yes" if user_data.passKeyDeviceBound_authentication_method else "No",
                "Yes" if user_data.passKeyDeviceBoundAuthenticator_authentication_method else "No",
                "Yes" if user_data.windowsHelloforBusiness_authentication_method else "No",
                "Yes" if user_data.microsoftAuthenticatorPasswordless_authentication_method else "No",
                "Yes" if user_data.microsoftAuthenticatorPush_authentication_method else "No",
                "Yes" if user_data.softwareOneTimePasscode_authentication_method else "No",
                "Yes" if user_data.temporaryAccessPass_authentication_method else "No",
                "Yes" if user_data.mobilePhone_authentication_method else "No",
                "Yes" if user_data.email_authentication_method else "No",
                "Yes" if user_data.securityQuestion_authentication_method else "No",
            ]
            data.append(row)
        except Exception as e:
            # Log the error and continue with other users
            print(f"Error processing user {user_data.upn}: {str(e)}")
            continue

    return JsonResponse({
        "data": data,
    })

############################################################################################

@login_required
def endpointList(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	integration_clean = integration.replace("-", " ")
	endpoints = Device.objects.filter(integration__integration_type=integration_clean)

	endpoint_list = []
	for endpoint in endpoints:
		endpoint_list.append([endpoint.hostname, endpoint.osPlatform, endpoint.endpointType, endpoint.created_at])

	context = {
		'page':integration,
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.all(),
		'integration':integration_clean.title(),
		'endpoint_list':endpoint_list,
	}
	return render(request, 'main/endpoint-list.html', context)

############################################################################################

@login_required
def integrations(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	deviceIntegrationStatuses = []

	for integration_name in integration_names:
		integration = Integration.objects.get(integration_type = integration_name, integration_context = "Device")
		if integration.client_secret:
			deviceIntegrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, True, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
		else:
			deviceIntegrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, False, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
	
		userIntegrationStatuses = []

	for integration_name in user_integration_names:
		integration = Integration.objects.get(integration_type = integration_name, integration_context = "User")
		if integration.client_secret:
			userIntegrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, True, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
		else:
			userIntegrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, False, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
	
	context = {
		'page':'integrations',
		'notifications': Notification.objects.all(),
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'notifications': Notification.objects.all(),
		'deviceIntegrationStatuses':deviceIntegrationStatuses,
		'userIntegrationStatuses':userIntegrationStatuses,
	}
	return render( request, 'main/integrations.html', context)

############################################################################################

@login_required
def enableIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	integration_update = Integration.objects.get(id=id)
	integration_update.enabled = True
	integration_update.save()

	return redirect ('/integrations')

############################################################################################

@login_required
def disableIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	integration_update = Integration.objects.get(id=id)
	integration_update.enabled = False
	integration_update.save()

	return redirect ('/integrations')

############################################################################################

@login_required
def updateIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	integration_update = Integration.objects.get(id=id)
	integration_update.client_id = request.POST['client_id']
	integration_update.client_secret = request.POST['client_secret']
	integration_update.tenant_id = request.POST['tenant_id']
	integration_update.tenant_domain = request.POST['tenant_domain']
	integration_update.save()

	return redirect ('/integrations')

############################################################################################

@login_required
def error500(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	return render( request, 'main/pages-500.html')

############################################################################################
@login_required
def syncDevices(request, integration):
    # Checks User Permissions and Required Models
    redirect_url = initialChecks(request)
    if redirect_url:
        return redirect(redirect_url)
	#X6969
    if integration == 'Cloudflare-Zero-Trust':
        syncCloudflareZeroTrust()
    elif integration == 'CrowdStrike-Falcon':
        syncCrowdStrikeFalconBackground()
    elif integration == 'microsoft-defender-for-endpoint':
        syncMicrosoftDefenderforEndpointBackground(request)
    elif integration == 'microsoft-entra-id':
        syncMicrosoftEntraIDBackground(request)
    elif integration == 'microsoft-intune':
        print ("Syncing Microsoft Intune")
        syncMicrosoftIntuneBackground(request)  # Run the task in the background
    elif integration == 'Sophos-Central':
        syncSophos()
    elif integration == 'Qualys':
        syncQualys()
    return redirect('/integrations')

@login_required
def syncUsers(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	#X6969
	print (integration)
	if integration == 'microsoft-entra-id':
		print ("Syncing Microsoft Entra ID Users")
		syncMicrosoftEntraIDUserBackground(request)
	print("Redirecting to Integrations")
	return redirect('/integrations')

############################################################################################
# API Views for Settings Management
############################################################################################

@login_required
def compliance_summary_api(request):
    """API endpoint to get compliance settings summary"""
    from .utils import ComplianceSettingsManager
    
    try:
        summary = ComplianceSettingsManager.get_compliance_summary()
        return JsonResponse({
            'success': True,
            'data': summary
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def compliance_report_api(request):
    """API endpoint to get comprehensive compliance report"""
    from .utils import DeviceComplianceChecker
    
    try:
        report = DeviceComplianceChecker.get_compliance_report()
        return JsonResponse({
            'success': True,
            'data': report
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def bulk_update_compliance_api(request):
    """API endpoint to bulk update compliance settings"""
    from .utils import ComplianceSettingsManager
    
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'error': 'Method not allowed'
        }, status=405)
    
    try:
        data = request.POST
        integration_settings = {}
        
        # Parse the integration settings from the request
        integration_mapping = {
            'cloudflare_zero_trust': 'Cloudflare Zero Trust',
            'crowdstrike_falcon': 'Crowdstrike Falcon',
            'microsoft_defender_for_endpoint': 'Microsoft Defender For Endpoint',
            'microsoft_entra_id': 'Microsoft Entra Id',
            'microsoft_intune': 'Microsoft Intune',
            'sophos_central': 'Sophos Central',
            'qualys': 'Qualys'
        }
        
        for field_name, integration_name in integration_mapping.items():
            if field_name in data:
                integration_settings[integration_name] = data[field_name] == 'true'
        
        if not integration_settings:
            return JsonResponse({
                'success': False,
                'error': 'No integration settings provided'
            }, status=400)
        
        updated_count = ComplianceSettingsManager.bulk_update_compliance_settings(integration_settings)
        
        return JsonResponse({
            'success': True,
            'message': f'Updated {updated_count} platform settings',
            'updated_count': updated_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def reset_compliance_settings_api(request):
    """API endpoint to reset all compliance settings to defaults"""
    from .utils import ComplianceSettingsManager
    
    if request.method != 'POST':
        return JsonResponse({
            'success': False,
            'error': 'Method not allowed'
        }, status=405)
    
    try:
        updated_count = ComplianceSettingsManager.reset_compliance_settings_to_defaults()
        
        return JsonResponse({
            'success': True,
            'message': f'Reset {updated_count} platform settings to defaults',
            'updated_count': updated_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

############################################################################################