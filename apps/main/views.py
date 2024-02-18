from django.shortcuts import render, redirect
from django.contrib import messages
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

def pullIntuneDevices(request):
	for integration in IntuneIntegration.objects.all():
		data = IntuneIntegration.objects.get(id = integration.id)
		client_id = data.client_id
		client_secret = data.client_secret
		tenant_id = data.tenant_id
		tenant_domain = data.tenant_domain
		print(updateIntuneDeviceDatabase(getIntuneDevices(getIntuneAccessToken(client_id, client_secret, tenant_id))))
	return redirect('/')

def pullSophosDevices(request):
	for integration in SophosIntegration.objects.all():
		data = SophosIntegration.objects.get(id = integration.id)
		client_id = data.client_id
		client_secret = data.client_secret
		tenant_id = data.tenant_id
		tenant_domain = data.tenant_domain
		print(client_id + " " + client_secret + " " + tenant_id + " " + tenant_domain)
		print(updateSophosDeviceDatabase(getSophosDevices(getSophosAccessToken(client_id, client_secret, tenant_id))))
	return redirect('/')