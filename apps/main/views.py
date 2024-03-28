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
from .models import Integration, Device
from .models import CrowdStrikeFalconDevice, DefenderDevice, MicrosoftEntraIDDevice, IntuneDevice, SophosDevice, QualysDevice
from ..login_app.models import User

############################################################################################

# Reused Data Sets
integration_names = ['CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'Microsoft Entra ID', 'Microsoft Intune', 'Sophos Central', 'Qualys']

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
def loginChecks(request):
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	results.append(checkIntegrations(request))
	if results[0] == False:
		return '/identity/login'
	elif results[1] == False:
		return '/identity/accountsuspended'
	elif results[2] == False:
		print("Entering Initial Setup")
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
			Integration.objects.create(enabled = False, integration_type = integration, image_navbar_path=image_navbar_path, image_integration_path=image_integration_path)
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
			if integration_name == 'CrowdStrike Falcon':
				integration_device_counts.append([integration_name, len(CrowdStrikeFalconDevice.objects.all())])
			elif integration_name == 'Microsoft Defender for Endpoint':
				integration_device_counts.append([integration_name, len(DefenderDevice.objects.all())])
			elif integration_name == 'Microsoft Entra ID':
				integration_device_counts.append([integration_name, len(MicrosoftEntraIDDevice.objects.all())])
			elif integration_name == 'Microsoft Intune':
				integration_device_counts.append([integration_name, len(IntuneDevice.objects.all())])
			elif integration_name == 'Sophos Central':
				integration_device_counts.append([integration_name, len(SophosDevice.objects.all())])
			elif integration_name == 'Qualys':
				integration_device_counts.append([integration_name, len(QualysDevice.objects.all())])		

	# Query to get the count of each os platform
	os_platform_counts = Device.objects.values('osPlatform').annotate(count=Count('osPlatform'))
    # Prepare data for chart
	osPlatformLabels = []
	osPlatformData = []
	for item in os_platform_counts:
		osPlatformLabels.append(item['osPlatform'])
		osPlatformData.append(item['count'])
	
	print(osPlatformLabels)
	print(osPlatformData)
	
	# Query to get the count of each endpoint type
	endpoint_type_counts = Device.objects.values('endpointType').annotate(count=Count('endpointType'))
    # Prepare data for chart
	endpointTypeLabels = []
	endpointTypeData = []
	for item in endpoint_type_counts:
		endpointTypeLabels.append(item['endpointType'])
		endpointTypeData.append(item['count'])

	endpoint_list = []
	endpoints = Device.objects.all()
	for endpoint in endpoints:
		crowdstrike = False
		defender = False
		microsoftentraid = False
		intune = False
		sophos = False
		qualys = False

		try:
			if len(endpoint.integrationCrowdStrikeFalcon.filter(hostname = endpoint.hostname)) >= 1:
				crowdstrike = True
		except:
			print (endpoint.hostname + " not in CrowdStrike Falcon")
			crowdstrike = False
		try:
			if len(endpoint.integrationDefender.filter(hostname = endpoint.hostname)) >= 1:
				defender = True
		except:
			print (endpoint.hostname + " not in Defender")
			defender = False
		try:
			if len(endpoint.integrationMicrosoftEntraID.filter(hostname = endpoint.hostname)) >= 1:
				microsoftentraid = True
		except:
			print (endpoint.hostname + " not in Microsoft Entra ID")
			microsoftentraid = False
		try:
			if len(endpoint.integrationIntune.filter(hostname = endpoint.hostname)) >= 1:
				intune = True
		except:
			print (endpoint.hostname + " not in Intune")
			intune = False
		try:
			if len(endpoint.integrationSophos.filter(hostname = endpoint.hostname)) >= 1:
				sophos = True
		except:
			print (endpoint.hostname + " not in Sophos")
			sophos = False
		try:
			if len(endpoint.integrationQualys.filter(hostname = endpoint.hostname)) >= 1:
				qualys = True
		except:
			qualys = False
		endpoint_list.append([crowdstrike, defender, microsoftentraid, intune, sophos, qualys])
		
	
	count_all_true = 0
	count_any_false = 0
	for sublist in endpoint_list:
		if sublist == [True, True, True, True, True, True]:
			count_all_true += 1
		if False in sublist:
			count_any_false += 1

	context = {
		'page':'dashboard',
		'enabled_integrations': getEnabledIntegrations(),
		'endpoint_device_counts': integration_device_counts,

		'osPlatformLabels': osPlatformLabels,
        'osPlatformData': osPlatformData,
		'osPlatformCount': [
			len(Device.objects.filter(osPlatform="Android")),
			len(Device.objects.filter(osPlatform="Ubuntu")),
			len(Device.objects.filter(osPlatform="Windows")),
			len(Device.objects.filter(osPlatform="Windows Server")),
			len(Device.objects.filter(osPlatform="iOS/iPadOS")),
		],

		'endpointTypeLabels': endpointTypeLabels,
        'endpointTypeData': endpointTypeData,
		'endpointTypeCount': [
			len(Device.objects.filter(endpointType="Client")),
			len(Device.objects.filter(endpointType="Mobile")),
			len(Device.objects.filter(endpointType="Server")),
		],	

		'compliantLabels': ['Compliant', 'Non-Compliant'],
        'compliantData': [count_all_true, count_any_false],
		# 'compliantCount': [
		# 	len(Device.objects.filter(endpointType="Client")),
		# 	len(Device.objects.filter(endpointType="Mobile")),
		# ],	
	}
	return render( request, 'main/index.html', context)

############################################################################################

def profileSettings(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	context = {
		'page':"profile-settings",
		'enabled_integrations': getEnabledIntegrations(),
	}
	return render( request, 'main/profile-settings.html', context)

############################################################################################

def masterList(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	endpoint_list = []

	endpoints = Device.objects.all()
	for endpoint in endpoints:
		crowdstrike = False
		defender = False
		microsoftentraid = False
		intune = False
		sophos = False
		qualys = False
	
		try:
			if len(endpoint.integrationCrowdStrikeFalcon.filter(hostname = endpoint.hostname)) >= 1:
				crowdstrike = True
		except:
			print (endpoint.hostname + " not in CrowdStrike Falcon")
			crowdstrike = False
		try:
			if len(endpoint.integrationDefender.filter(hostname = endpoint.hostname)) >= 1:
				defender = True
		except:
			print (endpoint.hostname + " not in Defender")
			defender = False
		try:
			if len(endpoint.integrationMicrosoftEntraID.filter(hostname = endpoint.hostname)) >= 1:
				microsoftentraid = True
		except:
			print (endpoint.hostname + " not in Microsoft Entra ID")
			microsoftentraid = False
		try:
			if len(endpoint.integrationIntune.filter(hostname = endpoint.hostname)) >= 1:
				intune = True
		except:
			print (endpoint.hostname + " not in Intune")
			intune = False
		try:
			if len(endpoint.integrationSophos.filter(hostname = endpoint.hostname)) >= 1:
				sophos = True
		except:
			print (endpoint.hostname + " not in Sophos")
			sophos = False
		try:
			if len(endpoint.integrationQualys.filter(hostname = endpoint.hostname)) >= 1:
				qualys = True
		except:
			qualys = False

		endpoint_list.append([endpoint.hostname, crowdstrike, defender, microsoftentraid, intune, sophos, qualys])

	context = {
		'page':"master-list",
		'enabled_integrations': getEnabledIntegrations(),
		'endpoint_list':endpoint_list,
	}
	return render( request, 'main/master-list.html', context)

############################################################################################

def endpointList(request, integration):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	endpoint_list = []

	if integration == 'CrowdStrike-Falcon':
		endpoints = CrowdStrikeFalconDevice.objects.all()
	elif integration == 'Microsoft-Intune':
		endpoints = IntuneDevice.objects.all()
	elif integration == 'Microsoft-Entra-ID':
		endpoints = MicrosoftEntraIDDevice.objects.all()
	elif integration == 'Microsoft-Defender-for-Endpoint':
		endpoints = DefenderDevice.objects.all()
	elif integration == 'Sophos-Central':
		endpoints = SophosDevice.objects.all()
	elif integration == 'Qualys':
		endpoints = QualysDevice.objects.all()

	for endpoint in endpoints:
		endpoint_list.append([endpoint.hostname, endpoint.osPlatform, endpoint.endpointType, endpoint.created_at])

	context = {
		'page':integration,
		'enabled_integrations': getEnabledIntegrations(),
		'integration':integration.title(),
		'endpoint_list':endpoint_list,
	}
	return render( request, 'main/endpoint-list.html', context)

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
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, True, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain])
		else:
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, False, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain])
	
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