from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *
from .pulldevices.intune import *
from .pulldevices.sophos import *
from .pulldevices.defender import *

# Import Integrations
from .models import IntuneIntegration, SophosIntegration
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

def index(request):
	# Checks User Permissions
	results = []
	results.append(checkLogin(request))
	results.append(checkActive(request))
	if results[0] == False:
		return redirect('/identity/login')
	if results[1] == False:
		return redirect('/identity/accountsuspended')
	
	return render( request, 'main/index.html')

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
	return redirect('/')

def syncSophosDevices(request):
	syncSophos()
	return redirect('/')

def syncDefenderDevices(request):
	syncDefender()
	return redirect('/')

# Machine.Read.All
# DeviceManagementManagedDevices.Read.All