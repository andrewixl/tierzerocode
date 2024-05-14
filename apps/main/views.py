from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *

# Import Integration API Scripts
from .pulldevices.CrowdStrikeFalcon import *
from .pulldevices.MicrosoftDefenderforEndpoint import *
from .pulldevices.MicrosoftEntraID import *
from .pulldevices.MicrosoftIntune import *
from .pulldevices.SophosCentral import *
from .pulldevices.Qualys import *

# Import Integrations Models
from .models import Integration, Device, DeviceComplianceSettings
# from .models import CrowdStrikeFalconDevice, DefenderDevice, MicrosoftEntraIDDevice, IntuneDevice, SophosDevice, QualysDevice
from ..login_app.models import User

############################################################################################

# Reused Data Sets
integration_names = ['CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'Microsoft Entra ID', 'Microsoft Intune', 'Sophos Central', 'Qualys']
integration_names_short = ['CrowdStrike', 'Defender', 'Entra ID', 'Intune', 'Sophos', 'Qualys']
os_platforms = ['Android', 'iOS/iPadOS', 'MacOS', 'Ubuntu', 'Windows', 'Windows Server', 'Other']
endpoint_types = ['Client', 'Mobile', 'Server', 'Other']

############################################################################################

def genErrors(request, Emessages):
	for message in Emessages:
		messages.warning(request, message)

def checkLogin(request):
	try:
		if request.session['email']:
			return True
		else:
			return False
	except:
		return False
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
	results.append(checkLogin(request))
	results.append(checkActive(request))
	results.append(checkIntegrations(request))
	results.append(checkDeviceComplianceSettings(request))
	if results[0] == False:
		return '/identity/login'
	elif results[1] == False:
		return '/identity/accountsuspended'
	elif results[2] == False:
		print("Entering Initial Setup")
		return '/initial-setup'
	elif results[3] == False:
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
			if integration == 'Microsoft Defender for Endpoint':
				integration_short = 'Defender'
			elif integration == 'Microsoft Entra ID':
				integration_short = 'Entra ID'
			elif integration == 'Microsoft Intune':
				integration_short = 'Intune'
			elif integration == 'Sophos Central':
				integration_short = 'Sophos'
			elif integration == 'CrowdStrike Falcon':
				integration_short = 'CrowdStrike'
			elif integration == 'Qualys':
				integration_short = 'Qualys'
			Integration.objects.create(enabled = False, integration_type = integration, integration_type_short = integration_short, image_navbar_path=image_navbar_path, image_integration_path=image_integration_path)

	for os_platform in os_platforms:
		if len(DeviceComplianceSettings.objects.filter(os_platform = os_platform)) == 0:
			# default_settings = []
			# for setting in range(len(os_platforms)-1):
			# 	default_settings.append(0)
			DeviceComplianceSettings.objects.create(os_platform = os_platform, compliance_crowdstrike_falcon = True, compliance_microsoft_defender_for_endpoint = True, compliance_microsoft_entra_id = True, compliance_microsoft_intune = True, compliance_sophos_central = True, compliance_qualys = True)

	return redirect(request.META.get('HTTP_REFERER', '/'))

############################################################################################

from django.db.models import Count
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

		print(endpoint.hostname)
		print(endpoint_data)

		endpoint_compliance = DeviceComplianceSettings.objects.get(os_platform = endpoint.osPlatform)
		endpoint_match = []
		for integration in enabled_integrations:
			if integration.integration_type == 'CrowdStrike Falcon':
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

	print("Compliant: " + str(count_all_true))
	print("Non-Compliant: " + str(count_any_false))

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

def profileSettings(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	settings = []

	for device_compliance_setting in DeviceComplianceSettings.objects.all():
		settings.append([device_compliance_setting.os_platform, device_compliance_setting.settings])
	
	print(settings)

	context = {
		'page':"profile-settings",
		'enabled_integrations': getEnabledIntegrations(),
		'settings':settings,
	}
	return render( request, 'main/profile-settings.html', context)

############################################################################################

def deviceData(request, id):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	device = Device.objects.get(id=id)
	integrations = device.integration.all()
	integration_list = []
	for integration in integrations:
		integration_list.append(integration.integration_type)
	
	context = {
		'page':"device-data",
		'enabled_integrations': getEnabledIntegrations(),
		'device':device,
		'integrations':integration_list,
	}
	return render( request, 'main/device-data.html', context)

############################################################################################

def complianceSettings(os_platform, integration):
	if integration == 'CrowdStrike Falcon':
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

		print (endpoint.hostname + " - " + str(endpoint.osPlatform))
		print (endpoint_data)

	context = {
		'page':"master-list",
		'enabled_integrations': enabled_integrations,
		'endpoint_list':endpoint_list,
	}
	return render( request, 'main/master-list.html', context)

############################################################################################

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

def error500(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	return render( request, 'main/pages-500.html')

############################################################################################

def syncDevices(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	print(integration)

	if integration == 'CrowdStrike-Falcon':
		print("Calling Sync CrowdStrike Falcon")
		syncCrowdStrikeFalcon()
	elif integration == 'Microsoft-Defender-for-Endpoint':
		syncDefender()
	elif integration == 'Microsoft-Entra-ID':
		syncMicrosoftEntraID()
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