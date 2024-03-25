from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *
from .pulldevices.intune import *
from .pulldevices.sophos import *
from .pulldevices.defender import *
from .pulldevices.crowdstrike import *
from .pulldevices.qualys import *

# Import Integrations
from .models import Integration
from .models import Device, IntuneDevice, SophosDevice, DefenderDevice
from ..login_app.models import User

############################################################################################

# Reused Data Sets
integration_names = ['CrowdStrike Falcon', 'Microsoft Defender for Endpoint', 'Microsoft Intune', 'Sophos Central', 'Qualys']

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

from django.http import HttpResponseRedirect

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


	# Query to get the count of each os platform
	os_platform_counts = Device.objects.values('osPlatform').annotate(count=Count('osPlatform'))
    # Prepare data for chart
	osPlatformLabels = []
	osPlatformData = []
	for item in os_platform_counts:
		osPlatformLabels.append(item['osPlatform'])
		osPlatformData.append(item['count'])
	
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
		intune = False
		sophos = False
		defender = False
		crowdstrike = False
		try:
			if len(endpoint.integrationIntune.filter(hostname = endpoint.hostname)) == 1:
				intune = True
		except:
			intune = False
		try:
			if len(endpoint.integrationSophos.filter(hostname = endpoint.hostname)) == 1:
				sophos = True
		except:
			sophos = False
		try:
			if len(endpoint.integrationDefender.filter(hostname = endpoint.hostname)) == 1:
				defender = True
			elif len(endpoint.integrationDefender.filter(hostname = endpoint.hostname)) > 1:
				defender = True
		except:
			defender = False
		try:
			if len(endpoint.integrationCrowdStrike.filter(hostname = endpoint.hostname)) == 1:
				crowdstrike = True
		except:
			crowdstrike = False
		endpoint_list.append([intune, sophos, defender])
		
	
	count_all_true = 0
	count_any_false = 0
	for sublist in endpoint_list:
		if sublist == [True, True, True]:
			count_all_true += 1
		if False in sublist:
			count_any_false += 1

	context = {
		'page':'dashboard',
		'totalDeviceEndpoints':len(Device.objects.all()),
		'totalIntuneEndpoints':len(IntuneDevice.objects.all()),
		'totalSophosEndpoints':len(SophosDevice.objects.all()),
		'totalDefenderEndpoints':len(DefenderDevice.objects.all()),

		'osPlatformLabels': osPlatformLabels,
        'osPlatformData': osPlatformData,
		'osPlatformCount': [
			len(Device.objects.filter(osPlatform="Android")),
			len(Device.objects.filter(osPlatform="Ubuntu")),
			len(Device.objects.filter(osPlatform="Windows")),
			len(Device.objects.filter(osPlatform="Windows Server")),
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

def masterList(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	endpoint_list = []

	endpoints = Device.objects.all()
	for endpoint in endpoints:
		intune = False
		sophos = False
		defender = False
		crowdstrike = False

		try:
			if len(endpoint.integrationIntune.filter(hostname = endpoint.hostname)) == 1:
				intune = True
		except:
			intune = False
		try:
			if len(endpoint.integrationSophos.get(hostname = endpoint.hostname)) == 1:
				sophos = True
			elif len(endpoint.integrationSophos.get(hostname = endpoint.hostname)) > 1:
				sophos = True
		except:
			sophos = False
		try:
			if len(endpoint.integrationDefender.filter(hostname = endpoint.hostname)) == 1:
				defender = True
			elif len(endpoint.integrationDefender.filter(hostname = endpoint.hostname)) > 1:
				defender = True
		except:
			print("entered exception for Defender")
			defender = False
		try:
			if endpoint.integrationCrowdStrike.get(hostname = endpoint.hostname):
				crowdstrike = True
		except:
			crowdstrike = False
		# endpoint_list.append([endpoint.hostname, intune, sophos, defender, crowdstrike, False])
		endpoint_list.append([endpoint.hostname, intune, sophos, defender])

	context = {
		'page':"master-list",
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

	if integration == 'intune':
		endpoints = IntuneDevice.objects.all()
	elif integration == 'sophos':
		endpoints = SophosDevice.objects.all()
	elif integration == 'defender':
		endpoints = DefenderDevice.objects.all()
	# elif integration == 'crowdstrike':
	# 	endpoints = CrowdStrikeDevice.objects.all()
	elif integration == 'qualys':
		endpoints = QualysDevice.objects.all()

	for endpoint in endpoints:
		endpoint_list.append([endpoint.hostname, endpoint.osPlatform, endpoint.endpointType, endpoint.created_at])

	context = {
		'page':integration,
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
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, True, integration.id])
		else:
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, False, integration.id])
	
	context = {
		'page':'integrations',
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

def error500(request):
	# Checks User Permissions and Models
	loginChecks(request)
	
	return render( request, 'main/pages-500.html')

############################################################################################

def syncIntuneDevices(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	syncIntune()
	return redirect('/integrations')

def syncSophosDevices(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	syncSophos()
	return redirect('/integrations')

def syncDefenderDevices(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	syncDefender()
	return redirect('/integrations')

def syncCrowdStrikeDevices(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	syncCrowdStrike()
	return redirect('/integrations')

def syncQualysDevices(request):
	# Checks User Permissions and Required Models
	redirect_url = loginChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	syncQualys()
	return redirect('/integrations')

############################################################################################

# Machine.Read.All
# DeviceManagementManagedDevices.Read.All

def test(request):
	# Checks User Permissions and Models
	loginChecks(request)

	return render( request, 'main/index_test.html')