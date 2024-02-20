from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *
from .pulldevices.intune import *
from .pulldevices.sophos import *
from .pulldevices.defender import *

# Import Integrations
from .models import IntuneIntegration, SophosIntegration
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

def integrations(request):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
	return render( request, 'main/integrations.html')

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
	return redirect('/test')

def syncSophosDevices(request):
	syncSophos()
	return redirect('/test')

def syncDefenderDevices(request):
	syncDefender()
	return redirect('/test')

# Machine.Read.All
# DeviceManagementManagedDevices.Read.All