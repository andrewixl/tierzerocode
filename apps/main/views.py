from django.shortcuts import render, redirect
from django.contrib import messages
from .pulldevices.intune import *

# Import Integrations
from .models import IntuneIntegration

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
		print(updateIntuneDeviceDatabase(getIntuneDevices(getAccessToken(client_id, client_secret, tenant_id))))
	return redirect('/')

# def contactcreation(request):
# 	results = Contact.objects.registerVal(request.POST)
# 	if results['status'] == True:
# 		contact = Contact.objects.createContact(request.POST)
# 		messages.success(request, 'Thank you! Your Message was Sent.')
# 	else: 
# 		genErrors(request, results['errors'])
# 	return redirect('/#contact')