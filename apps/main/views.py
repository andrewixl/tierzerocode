from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.masterlist import *
from .pulldevices.intune import *
from .pulldevices.sophos import *

# Import Integrations
from .models import IntuneIntegration, SophosIntegration

# Create your views here.
def genErrors(request, Emessages):
	for message in Emessages:
		messages.error(request, message)

def index(request):
	return render( request, 'main/index.html')

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