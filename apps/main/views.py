from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *
from .pulldevices.intune import *
from .pulldevices.sophos import *
from .pulldevices.defender import *
from .pulldevices.crowdstrike import *

# Import Integrations
from .models import IntuneIntegration, SophosIntegration, DefenderIntegration, CrowdStrikeIntegration
from .models import Device, IntuneDevice, SophosDevice, DefenderDevice
from ..login_app.models import User

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
	


############################################################################################

from django.db.models import Count
def index(request):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
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
			if endpoint.integrationIntune.get(hostname = endpoint.hostname):
				intune = True
		except:
			intune = False
		try:
			if endpoint.integrationSophos.get(hostname = endpoint.hostname):
				sophos = True
		except:
			sophos = False
		try:
			if endpoint.integrationDefender.get(hostname = endpoint.hostname):
				defender = True
		except:
			defender = False
		try:
			if endpoint.integrationCrowdStrike.get(hostname = endpoint.hostname):
				crowdstrike = True
		except:
			crowdstrike = False
		# endpoint_list.append([endpoint.hostname, intune, sophos, defender, crowdstrike, False])
		endpoint_list.append([intune, sophos, defender])
	
	count_all_true = 0
	count_any_false = 0
	for sublist in endpoint_list:
		if sublist == [True, True, True]:
			count_all_true += 1
		if False in sublist:
			count_any_false += 1

	context = {
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
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
	endpoint_list = []

	endpoints = Device.objects.all()
	for endpoint in endpoints:
		intune = False
		sophos = False
		defender = False
		crowdstrike = False

		try:
			if endpoint.integrationIntune.get(hostname = endpoint.hostname):
				intune = True
		except:
			intune = False
		try:
			if endpoint.integrationSophos.get(hostname = endpoint.hostname):
				sophos = True
		except:
			sophos = False
		try:
			if endpoint.integrationDefender.get(hostname = endpoint.hostname):
				defender = True
		except:
			defender = False
		try:
			if endpoint.integrationCrowdStrike.get(hostname = endpoint.hostname):
				crowdstrike = True
		except:
			crowdstrike = False
		# endpoint_list.append([endpoint.hostname, intune, sophos, defender, crowdstrike, False])
		endpoint_list.append([endpoint.hostname, intune, sophos, defender])

	context = {
		'endpoint_list':endpoint_list,
	}
	return render( request, 'main/master-list.html', context)

############################################################################################

def endpointList(request, integration):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
	endpoint_list = []

	if integration == 'intune':
		endpoints = IntuneDevice.objects.all()
	elif integration == 'sophos':
		endpoints = SophosDevice.objects.all()
	elif integration == 'defender':
		endpoints = DefenderDevice.objects.all()
	# elif integration == 'crowdstrike':
	# 	endpoints = CrowdStrikeDevice.objects.all()

	for endpoint in endpoints:
		endpoint_list.append([endpoint.hostname, endpoint.osPlatform, endpoint.created_at, endpoint.id])

	context = {
		'endpoint_list':endpoint_list,
	}
	return render( request, 'main/endpoint-list.html', context)

############################################################################################

def integrations(request):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
	intuneStatus = []
	sophosStatus = []
	defenderStatus = []
	crowdStrikeStatus = []

	if len(IntuneIntegration.objects.all()) == 0:
		intuneStatus = [False, False, null]
	else:
		for integration in IntuneIntegration.objects.all():
			data = IntuneIntegration.objects.get(id = integration.id)
			if data.tenant_domain:
				intuneStatus = [data.enabled, True, integration.id]
			else:
				intuneStatus = [data.enabled, False, integration.id]
	
	if len(SophosIntegration.objects.all()) == 0:
		sophosStatus = [False, False, null]
	else:
		for integration in SophosIntegration.objects.all():
			data = SophosIntegration.objects.get(id = integration.id)
			if data.tenant_domain:
				sophosStatus = [data.enabled, True, integration.id]
			else:
				sophosStatus = [data.enabled, False, integration.id]

	if len(DefenderIntegration.objects.all()) == 0:
		defenderStatus = [False, False, null]
	else:
		for integration in DefenderIntegration.objects.all():
			data = DefenderIntegration.objects.get(id = integration.id)
			if data.tenant_domain:
				defenderStatus = [data.enabled, True, integration.id]
			else:
				defenderStatus = [data.enabled, False, integration.id]
	
	if len(CrowdStrikeIntegration.objects.all()) == 0:
		crowdstrikeStatus = [False, False, null]
	else:
		for integration in CrowdStrikeIntegration.objects.all():
			data = CrowdStrikeIntegration.objects.get(id = integration.id)
			if data.tenant_domain:
				crowdstrikeStatus = [data.enabled, True, integration.id]
			else:
				crowdstrikeStatus = [data.enabled, False, integration.id]
	
	context = {
		'intuneStatus':intuneStatus,
		'sophosStatus':sophosStatus,
		'defenderStatus':defenderStatus,
		'crowdstrikeStatus':crowdstrikeStatus,
	}
	return render( request, 'main/integrations.html', context)

############################################################################################

def enableIntegration(request, integration, id):
	match integration:
		case 'intune':
			try:
				if IntuneIntegration.objects.get(id=id):
					integration_update = IntuneIntegration.objects.get(id=id)
					integration_update.enabled = True
					integration_update.save()
			except:
				IntuneIntegration.objects.create(enabled = True)
		case 'sophos':
			try:
				if SophosIntegration.objects.get(id=id):
					integration_update = SophosIntegration.objects.get(id=id)
					integration_update.enabled = True
					integration_update.save()
			except:
				SophosIntegration.objects.create(enabled = True)
		case 'defender':
			try:
				if DefenderIntegration.objects.get(id=id):
					integration_update = DefenderIntegration.objects.get(id=id)
					integration_update.enabled = True
					integration_update.save()
			except:
				DefenderIntegration.objects.create(enabled = True)
		case 'crowdstrike':
			try:
				if CrowdStrikeIntegration.objects.get(id=id):
					integration_update = CrowdStrikeIntegration.objects.get(id=id)
					integration_update.enabled = True
					integration_update.save()
			except:
				CrowdStrikeIntegration.objects.create(enabled = True)
	return redirect ('/integrations')

############################################################################################

def disableIntegration(request, integration, id):
	match integration:
		case 'intune':
			if IntuneIntegration.objects.get(id=id):
				integration_update = IntuneIntegration.objects.get(id=id)
				integration_update.enabled = False
				integration_update.save()
		case 'sophos':
			if SophosIntegration.objects.get(id=id):
				integration_update = SophosIntegration.objects.get(id=id)
				integration_update.enabled = False
				integration_update.save()
		case 'defender':
			if DefenderIntegration.objects.get(id=id):
				integration_update = DefenderIntegration.objects.get(id=id)
				integration_update.enabled = False
				integration_update.save()
		case 'crowdstrike':
			if CrowdStrikeIntegration.objects.get(id=id):
				integration_update = CrowdStrikeIntegration.objects.get(id=id)
				integration_update.enabled = False
				integration_update.save()
	return redirect ('/integrations')

############################################################################################

def error500(request):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
	return render( request, 'main/pages-500.html')

############################################################################################

def syncIntuneDevices(request):
	syncIntune()
	return redirect('/integrations')

def syncSophosDevices(request):
	syncSophos()
	return redirect('/integrations')

def syncDefenderDevices(request):
	syncDefender()
	return redirect('/integrations')

def syncCrowdStrikeDevices(request):
	syncCrowdStrike()
	return redirect('/integrations')

############################################################################################

# Machine.Read.All
# DeviceManagementManagedDevices.Read.All

def test(request):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	return render( request, 'main/index_test.html')