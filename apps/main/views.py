from django.shortcuts import render, redirect
from django.contrib import messages
# from .integrations.device_integrations.masterlist import *
from django.contrib.auth.decorators import login_required
from django.forms.models import model_to_dict
import re
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
# from .models import CrowdStrikeFalconDevice, DefenderDevice, MicrosoftEntraIDDevice, IntuneDevice, SophosDevice, QualysDevice

############################################################################################

# Reused Data Sets
#X6969
integration_names = ['Cloudflare Zero Trust', 'CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'Microsoft Entra ID', 'Microsoft Intune', 'Sophos Central', 'Qualys']
#X6969
integration_names_short = ['Cloudflare', 'CrowdStrike', 'Defender', 'Entra ID', 'Intune', 'Sophos', 'Qualys']
os_platforms = ['Android', 'iOS/iPadOS', 'MacOS', 'Ubuntu', 'Windows', 'Windows Server', 'Other']
endpoint_types = ['Client', 'Mobile', 'Server', 'Other']

############################################################################################

def genErrors(request, Emessages):
	for message in Emessages:
		messages.warning(request, message)

def checkActive(request):
	try:
		if request.session['active']:
			return True
		else:
			return False
	except:
		return False
def checkIntegrations(request):
	for integration in integration_names:
		if len(Integration.objects.filter(integration_type = integration)) == 0:
			return False
		else:
			return True
def checkDeviceComplianceSettings(request):
	for os_platform in os_platforms:
		if len(DeviceComplianceSettings.objects.filter(os_platform = os_platform)) == 0:
			return False
		else:
			return True
def loginChecks(request):
	results = []
	results.append(checkActive(request))
	results.append(checkIntegrations(request))
	results.append(checkDeviceComplianceSettings(request))
	if results[0] == False:
		return '/identity/accountsuspended'
	elif results[1] == False:
		print("Entering Initial Setup")
		return '/initial-setup'
	elif results[2] == False:
		return '/initial-setup'
	else:
		return None
def getEnabledIntegrations():
	enabledIntegrations = []
	for integration in Integration.objects.all():
		if integration.enabled == True:
			enabledIntegrations.append(integration)
	return enabledIntegrations

############################################################################################	

# Creates blank integration templates if they do not exist
def initialSetup(request):
	for integration in integration_names:
		if len(Integration.objects.filter(integration_type = integration)) == 0:
			image_navbar_path = 'main/img/navbar_icons/webp/' + (integration.replace(" ", "_")).lower() + '_logo_nav.webp'
			image_integration_path = 'main/img/integration_images/webp/' + (integration.replace(" ", "_")).lower() + '_logo.webp'
			#X6969
			if integration == 'Cloudflare Zero Trust':
				integration_short = 'Cloudflare'
			elif integration == 'CrowdStrike Falcon':
				integration_short = 'CrowdStrike'
			elif integration == 'Microsoft Defender for Endpoint':
				integration_short = 'Defender'
			elif integration == 'Microsoft Entra ID':
				integration_short = 'Entra ID'
			elif integration == 'Microsoft Intune':
				integration_short = 'Intune'
			elif integration == 'Sophos Central':
				integration_short = 'Sophos'
			elif integration == 'Qualys':
				integration_short = 'Qualys'
			Integration.objects.create(enabled = False, integration_type = integration, integration_type_short = integration_short, integration_context="Device", image_navbar_path=image_navbar_path, image_integration_path=image_integration_path)

	for os_platform in os_platforms:
		if len(DeviceComplianceSettings.objects.filter(os_platform = os_platform)) == 0:
			#X6969
			DeviceComplianceSettings.objects.create(os_platform = os_platform, cloudflare_zero_trust = True, crowdstrike_falcon = True, microsoft_defender_for_endpoint = True, microsoft_entra_id = True, microsoft_intune = True, sophos_central = True, qualys = True)

	return redirect(request.META.get('HTTP_REFERER', '/'))

############################################################################################

@login_required
def index(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	# Count of devices for each integration
	integration_device_counts = [["Master List Endpoints", len(Device.objects.all())]]
	for integration_name in integration_names:
		if True == Integration.objects.get(integration_type = integration_name).enabled:
			integration_device_counts.append([integration_name, len(Device.objects.filter(integration__integration_type=integration_name)), Integration.objects.get(integration_type=integration_name).image_navbar_path])

	# Query to get the count of each os platform
	osPlatformData = []
	for os_platform in os_platforms:
		osPlatformData.append(len(Device.objects.filter(osPlatform=os_platform)))
	
	# Query to get the count of each endpoint type
	endpoint_data = Device.objects.all()
    # Prepare data for chart
	endpointTypeData = []
	for endpoint_type in endpoint_types:
		endpointTypeData.append(len(Device.objects.filter(endpointType=endpoint_type)))

	# Tier Zero Pie Chart Calculations
	endpoint_list = []
	enabled_integrations = getEnabledIntegrations()
	endpoints = Device.objects.all()
	compliant = 0
	non_compliant = 0
	for endpoint in endpoints:
		endpoint_data = []
		for integration in enabled_integrations:
			try:
				if endpoint.integration.filter(integration_type = integration):
					endpoint_data.append(True)
				else:
					endpoint_data.append(False)
			except:
				endpoint_data.append(False)

		endpoint_compliance = DeviceComplianceSettings.objects.get(os_platform = endpoint.osPlatform)
		endpoint_match = []
		for integration in enabled_integrations:
			#X6969
			if integration.integration_type == 'Cloudflare Zero Trust':
				endpoint_match.append(endpoint_compliance.cloudflare_zero_trust)
			elif integration.integration_type == 'CrowdStrike Falcon':
				endpoint_match.append(endpoint_compliance.crowdstrike_falcon)
			elif integration.integration_type == 'Microsoft Defender for Endpoint':
				endpoint_match.append(endpoint_compliance.microsoft_defender_for_endpoint)
			elif integration.integration_type == 'Microsoft Entra ID':
				endpoint_match.append(endpoint_compliance.microsoft_entra_id)
			elif integration.integration_type == 'Microsoft Intune':
				endpoint_match.append(endpoint_compliance.microsoft_intune)
			elif integration.integration_type == 'Sophos Central':
				endpoint_match.append(endpoint_compliance.sophos_central)
			elif integration.integration_type == 'Qualys':
				endpoint_match.append(endpoint_compliance.qualys)

		if endpoint_data == endpoint_match:
			endpoint_list.append(True)
		else:
			endpoint_list.append(False)	

	count_all_true = endpoint_list.count(True)
	count_any_false = endpoint_list.count(False)

	context = {
		'page':'dashboard',
		'enabled_integrations': enabled_integrations,
		'endpoint_device_counts': integration_device_counts,

		'osPlatformLabels': os_platforms,
        'osPlatformData': osPlatformData,
		'endpointTypeLabels': endpoint_types,
        'endpointTypeData': endpointTypeData,

		'compliantLabels': ['Compliant', 'Non-Compliant'],
        'compliantData': [count_all_true, count_any_false],
	}
	return render( request, 'main/index.html', context)

############################################################################################

@login_required
def profileSettings(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
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

	# print(device_compliance_settings_list)

	context = {
		'page':"profile-settings",
		'enabled_integrations': getEnabledIntegrations(),
		'devicecomps':device_compliance_settings_list,
	}
	return render( request, 'main/profile-settings.html', context)

@login_required
def update_compliance(request, id):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
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
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	# X6969
	# Creates the device object with related data preloaded from each integration
	devices = Device.objects.filter(id=id).prefetch_related('integrationCloudflareZeroTrust', 'integrationCrowdStrikeFalcon', 'integrationMicrosoftDefenderForEndpoint', 'integrationMicrosoftEntraID', 'integrationIntune', 'integrationSophos', 'integrationQualys')
	# Selects the 1st and only device since prefetch_related required a filter
	device = devices[0]
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
		# elif integration == 'CrowdStrike Falcon':
		# 	device.integrationCrowdStrikeFalcon.get(deviceName=device.hostname.upper())
		if integration == 'Microsoft Defender for Endpoint':
			# defender_integration = device.integrationMicrosoftDefenderForEndpoint.get(computerDnsName=device.hostname)
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
		# elif integration == 'Sophos Central':
		# 	device.integrationSophos.get(deviceName=device.hostname.upper())
		# elif integration == 'Qualys':
		# 	device.integrationQualys.get(deviceName=device.hostname.upper())

	integrations = device.integration.all()
	print(integrations)
	
	context = {
		'page':"device-data",
		'enabled_integrations': getEnabledIntegrations(),
		'device':device,
		'ints' : integrations,
		# X6969
		"defender_device":defender_device,
		'entra_device':entra_device,
		'intune_device':intune_device,
	}
	return render( request, 'main/device-data.html', context)

############################################################################################

@login_required
def complianceSettings(os_platform, integration):
	#X6969
	if integration == 'Cloudflare Zero Trust':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).cloudflare_zero_trust
	elif integration == 'CrowdStrike Falcon':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).crowdstrike_falcon
	elif integration == 'Microsoft Defender for Endpoint':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).microsoft_defender_for_endpoint
	elif integration == 'Microsoft Entra ID':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).microsoft_entra_id
	elif integration == 'Microsoft Intune':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).microsoft_intune
	elif integration == 'Sophos Central':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).sophos_central
	elif integration == 'Qualys':
		return DeviceComplianceSettings.objects.get(os_platform = os_platform).qualys

@login_required
def masterList(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	enabled_integrations = getEnabledIntegrations()
	endpoint_list = []

	endpoints = Device.objects.all()
	for endpoint in endpoints:
		endpoint_data = [endpoint]
		compliant_settings = DeviceComplianceSettings.objects.get(os_platform = endpoint.osPlatform)

		for integration in enabled_integrations:
			try:
				if complianceSettings(endpoint.osPlatform, integration.integration_type):
					if endpoint.integration.filter(integration_type = integration):
						endpoint_data.append(True)
					else:
						endpoint_data.append(False)
				else:
					endpoint_data.append(None)
			except:
				endpoint_data.append(False)

		endpoint_list.append(endpoint_data)

	context = {
		'page':"master-list",
		'enabled_integrations': enabled_integrations,
		'endpoint_list':endpoint_list,
	}
	return render( request, 'main/master-list.html', context)

############################################################################################

@login_required
def endpointList(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
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
		'integration':integration_clean.title(),
		'endpoint_list':endpoint_list,
	}
	return render(request, 'main/endpoint-list.html', context)

############################################################################################

@login_required
def integrations(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	integrationStatuses = []

	for integration_name in integration_names:
		integration = Integration.objects.get(integration_type = integration_name)
		if integration.tenant_domain:
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, True, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
		else:
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, False, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
	
	context = {
		'page':'integrations',
		'enabled_integrations': getEnabledIntegrations(),
		'integrationStatuses':integrationStatuses,
	}
	return render( request, 'main/integrations.html', context)

############################################################################################

@login_required
def enableIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
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
	redirect_url = loginChecks(request)
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
	redirect_url = loginChecks(request)
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
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	return render( request, 'main/pages-500.html')

############################################################################################

@login_required
def syncDevices(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	print(integration)
	#X6969
	if integration == 'Cloudflare-Zero-Trust':
		print("Calling Sync Cloudflare Zero Trust")
		syncCloudflareZeroTrust()
	elif integration == 'CrowdStrike-Falcon':
		print("Calling Sync CrowdStrike Falcon")
		syncCrowdStrikeFalcon()
	elif integration == 'Microsoft-Defender-for-Endpoint':
		syncDefender()
	elif integration == 'Microsoft-Entra-ID':
		syncMicrosoftEntraID()
	elif integration == 'Microsoft-Entra-ID-User':
		syncMicrosoftEntraIDUser()
	elif integration == 'Microsoft-Intune':
		syncIntune()
	elif integration == 'Sophos-Central':
		syncSophos()
	elif integration == 'Qualys':
		syncQualys()
	return redirect('/integrations')

############################################################################################

# Machine.Read.All - Defender
# DeviceManagementManagedDevices.Read.All - Intune
# Device.Read.All - Entra ID