from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.forms.models import model_to_dict
import re
from django.db.models import Prefetch, Count
# Import Device Integration API Scripts
#X6969
from .integrations.device_integrations.CloudflareZeroTrust import *
from .integrations.device_integrations.CrowdStrikeFalcon import *
from .integrations.device_integrations.MicrosoftDefenderforEndpoint import *
from .integrations.device_integrations.MicrosoftEntraID import *
from .integrations.device_integrations.MicrosoftIntune import *
from .integrations.device_integrations.SophosCentral import *
from .integrations.device_integrations.Qualys import *
# Import User Integration API Scripts
from .integrations.user_integrations.MicrosoftEntraID import *
# Import Integrations Models
from .models import Integration, Device, DeviceComplianceSettings
# Setup Logging
# logger = logging.getLogger('custom_logger')

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

def test():
	Device.objects.all().delete()
	# Integration.objects.all().delete()
	# UserData.objects.all().delete()
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

from .integrations.cs_health_check import *

@login_required
def index(request):
	# test()
	syncCrowdStrikeFalconHealthCheckBackground()
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	# Fetch all enabled integrations in a single query
	enabled_integrations = getEnabledIntegrations()

	# Count of devices for each integration
	integration_device_counts = [["Master List Endpoints", Device.objects.count()]]
	integrations_with_data = Integration.objects.filter(integration_type__in=integration_names, enabled=True)
	for integration in integrations_with_data:
		integration_device_counts.append([integration.integration_type, Device.objects.filter(integration__integration_type=integration).count(), integration.image_navbar_path])

	# Count each os platform and endpoint type
	os_platform_counts = Device.objects.values('osPlatform').annotate(count=Count('osPlatform'))
	endpoint_type_counts = Device.objects.values('endpointType').annotate(count=Count('endpointType'))

	osPlatformData = [next((item['count'] for item in os_platform_counts if item['osPlatform'] == os_platform), 0) for os_platform in os_platforms]
	endpointTypeData = [next((item['count'] for item in endpoint_type_counts if item['endpointType'] == endpoint_type), 0) for endpoint_type in endpoint_types]

	count_all_true = Device.objects.filter(compliant=True).count()
	count_any_false = Device.objects.filter(compliant=False).count()

	# of Users that have adopted each authentication method
	users = UserData.objects.all()
	count_phishing_resistant = 0
	count_passwordless = 0
	count_mfa = 0
	count_deprecated = 0
	count_none = 0

	for user in users:
		if user.highest_authentication_strength == 'Phishing Resistant':
			count_phishing_resistant += 1
		elif user.highest_authentication_strength == 'Passwordless':
			count_passwordless += 1
		elif user.highest_authentication_strength == 'MFA':
			count_mfa += 1
		elif user.highest_authentication_strength == 'Deprecated':
			count_deprecated += 1
		elif user.highest_authentication_strength == 'None':
			count_none += 1
	
	count_low_phishing_resistant = 0
	count_low_passwordless = 0
	count_low_mfa = 0
	count_low_deprecated = 0
	count_low_none = 0

	for user in users:
		if user.lowest_authentication_strength == 'Phishing Resistant':
			count_low_phishing_resistant += 1
		elif user.lowest_authentication_strength == 'Passwordless':
			count_low_passwordless += 1
		elif user.lowest_authentication_strength == 'MFA':
			count_low_mfa += 1
		elif user.lowest_authentication_strength == 'Deprecated':
			count_low_deprecated += 1
		elif user.lowest_authentication_strength == 'None':
			count_low_none += 1
	
	passwordless_count = 0
	non_passwordless_count = 0

	for user in users:
		if user.lowest_authentication_strength == 'Passwordless' or user.lowest_authentication_strength == 'Phishing Resistant':
			passwordless_count += 1
		else:
			non_passwordless_count += 1
		
	context = {
		'page': 'dashboard',
		'enabled_integrations': enabled_integrations,
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'endpoint_device_counts': integration_device_counts,
		'osPlatformLabels': os_platforms,
		'osPlatformData': osPlatformData,
		'endpointTypeLabels': endpoint_types,
		'endpointTypeData': endpointTypeData,
		'compliantLabels': ['Compliant', 'Non-Compliant'],
		'compliantData': [count_all_true, count_any_false],
		'auth_method_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
		'auth_method_data': [count_phishing_resistant, count_passwordless, count_mfa, count_deprecated, count_none],
		'auth_method_low_labels': ['Phishing Resistant', 'Passwordless', 'MFA', 'Deprecated', 'None'],
		'auth_method_low_data': [count_low_phishing_resistant, count_low_passwordless, count_low_mfa, count_low_deprecated, count_low_none],
		'count_passwordless_labels': ['Passwordless', 'Non-Passwordless'],
		'count_passwordless_data': [passwordless_count, non_passwordless_count],
    }
	return render(request, 'main/index.html', context)

############################################################################################

@login_required
def profileSettings(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	device_compliance_settings_list = []
	settings = []

	for device_compliance_setting in DeviceComplianceSettings.objects.all():
		settings.append(device_compliance_setting)
	
	for setting in settings:
		mini_list = []
		for config in setting._meta.get_fields():
			if str(config) == 'main.DeviceComplianceSettings.id' or str(config) == 'main.DeviceComplianceSettings.os_platform':
				vals = str(config).split(".")[2]
			else:
				vals = (str(config).split(".")[2]).replace("_", " ").title()
			data = getattr(setting, config.name)
			mini_list.append([str(vals),str(data)])
		device_compliance_settings_list.append(mini_list)

	context = {
		'page':"profile-settings",
		'enabled_integrations': getEnabledIntegrations(),
		'devicecomps':device_compliance_settings_list,
	}
	return render( request, 'main/profile-settings.html', context)

@login_required
def update_compliance(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	if request.method == 'POST':
		device_compliance_setting = DeviceComplianceSettings.objects.get(id = id)

		print (request.POST)
		#X6969
		device_compliance_setting.cloudflare_zero_trust = str(request.POST.get('Cloudflare Zero Trust', False)).replace("on", "True")
		device_compliance_setting.crowdstrike_falcon = str(request.POST.get('Crowdstrike Falcon', False)).replace("on", "True")
		device_compliance_setting.microsoft_defender_for_endpoint = str(request.POST.get('Microsoft Defender For Endpoint', False)).replace("on", "True")
		device_compliance_setting.microsoft_entra_id = str(request.POST.get('Microsoft Entra Id', False)).replace("on", "True")
		device_compliance_setting.microsoft_intune = str(request.POST.get('Microsoft Intune', False)).replace("on", "True")
		device_compliance_setting.sophos_central = str(request.POST.get('Sophos Central', False)).replace("on", "True")
		device_compliance_setting.qualys = str(request.POST.get('Qualys', False)).replace("on", "True")
		device_compliance_setting.save()
	return redirect ('/profile-settings')

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
	
	auth_strengths = ['None', 'MFA', 'Passwordless', 'Phishing Resistant', 'Deprecated']
	
	user_data_list = UserData.objects.all()
	user_list = []
	for user_data in user_data_list:
		highest_auth = None
		lowest_auth = None
		if user_data.fido2_authentication_method or user_data.windows_hello_for_business_authentication_method:
			highest_auth = "Phishing Resistant"
		elif user_data.microsoft_authenticator_authentication_method:
			highest_auth = "Passwordless"
		elif user_data.temporary_access_pass_authentication_method or user_data.software_oath_authentication_method:
			highest_auth = "MFA"
		elif user_data.phone_authentication_method:
			highest_auth = "Deprecated"
		else:
			highest_auth = "None"

		if user_data.phone_authentication_method:
			lowest_auth = "Deprecated"
		elif user_data.temporary_access_pass_authentication_method or user_data.software_oath_authentication_method:
			lowest_auth = "MFA"
		elif user_data.microsoft_authenticator_authentication_method:
			lowest_auth = "Passwordless"
		elif user_data.fido2_authentication_method or user_data.windows_hello_for_business_authentication_method:
			lowest_auth = "Phishing Resistant"
		
		user_list.append([user_data, user_data.fido2_authentication_method, user_data.microsoft_authenticator_authentication_method, user_data.windows_hello_for_business_authentication_method, user_data.software_oath_authentication_method, user_data.temporary_access_pass_authentication_method, user_data.phone_authentication_method])

	context = {
		'page':"master-list-user",
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
		'auth_strengths': auth_strengths,
		'user_list':user_list,
	}
	return render( request, 'main/user-master-list.html', context)

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
		'enabled_integrations': getEnabledIntegrations(),
		'enabled_user_integrations': getEnabledUserIntegrations(),
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
		# logger.info("Calling Sync Cloudflare Zero Trust")
		syncCloudflareZeroTrust()
	elif integration == 'CrowdStrike-Falcon':
		# logger.info("Calling Sync CrowdStrike Falcon")
		syncCrowdStrikeFalconBackground()
	elif integration == 'Microsoft-Defender-for-Endpoint':
		# logger.info("Calling Sync Microsoft Defender for Endpoint")
		syncDefender()
	elif integration == 'Microsoft-Entra-ID':
		# logger.info("Calling Sync Microsoft Entra ID")
		syncMicrosoftEntraID()
	elif integration == 'Microsoft-Intune':
		# logger.info("Calling Sync Microsoft Intune")
		syncMicrosoftIntuneBackground()  # Run the task in the background
	elif integration == 'Sophos-Central':
		# logger.info("Calling Sync Sophos Central")
		syncSophos()
	elif integration == 'Qualys':
		# logger.info("Calling Sync Qualys")
		syncQualys()
	return redirect('/integrations')

@login_required
def syncUsers(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	#X6969
	if integration == 'Microsoft-Entra-ID':
		syncMicrosoftEntraIDUserBackground()
	print("Redirecting to Integrations")
	return redirect('/integrations')

############################################################################################
