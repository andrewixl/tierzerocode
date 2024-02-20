from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *
from .pulldevices.intune import *
from .pulldevices.sophos import *
from .pulldevices.defender import *

# Import Integrations
from .models import IntuneIntegration, SophosIntegration, DefenderIntegration
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
	}
	return render( request, 'main/index.html', context)

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
	
	context = {
		'intuneStatus':intuneStatus,
		'sophosStatus':sophosStatus,
		'defenderStatus':defenderStatus,
	}
	return render( request, 'main/integrations.html', context)

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
	return redirect ('/integrations')

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
	return redirect ('/integrations')


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

# def generateMasterList(request):
# 	devices = SophosDevice.objects.all()
# 	updateMasterList(devices)
# 	devices = IntuneDevice.objects.all()
# 	updateMasterList(devices)

	# device = Device.objects.get(id=36)
	# integrations = device.integrationIntune.get(deviceName = device.hostname)
	# print(integrations)
	# integrations = device.integrationSophos.get(hostname = device.hostname)
	# print(integrations)

	# return redirect('/')

def syncIntuneDevices(request):
	syncIntune()
	return redirect('/integrations')

def syncSophosDevices(request):
	syncSophos()
	return redirect('/integrations')

def syncDefenderDevices(request):
	syncDefender()
	return redirect('/integrations')

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