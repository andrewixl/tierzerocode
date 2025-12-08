# Import Django Modules
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
# Import Python Modules
import json, os, requests, secrets, string
from datetime import timedelta
from urllib.parse import quote_plus, urlencode, urlparse, urlunparse
# Import Django User Model
from django.contrib.auth.models import User
# Import Models
from .models import SSOIntegration
from ..logger.views import *
from ..authhandler.models import SSOIntegration
from ..authhandler.views import *


############################################################################################

# Reused Data Sets
#X6969
integration_names = ['Microsoft Entra ID']

############################################################################################

def genErrors(request, Emessages):
	for message in Emessages:
		messages.warning(request, message)

def checkSSOIntegrations(request):
	for integration in integration_names:
		if len(SSOIntegration.objects.filter(integration_type = integration)) == 0:
			return False
		else:
			return True
		
def initialChecks(request):
	results = []
	results.append(checkSSOIntegrations(request))
	if results[0] == False:
		print("Entering Initial Setup")
		return '/identity/initial-setup'
	else:
		return None
	
def getEnabledSSOIntegrations():
    return SSOIntegration.objects.filter(enabled=True)

############################################################################################

# Creates blank SSO integration templates if they do not exist
def initialSetup(request):
	for integration in integration_names:
		if len(SSOIntegration.objects.filter(integration_type = integration)) == 0:
			image_navbar_path = 'login_app/img/navbar_icons/webp/' + (integration.replace(" ", "_")).lower() + '_logo_nav.webp'
			image_integration_path = 'login_app/img/integration_images/webp/' + (integration.replace(" ", "_")).lower() + '_logo.webp'
			#X6969
			if integration == 'Microsoft Entra ID':
				integration_short = 'Entra ID'
			SSOIntegration.objects.create(enabled = False, integration_type = integration, integration_type_short = integration_short, image_navbar_path=image_navbar_path, image_integration_path=image_integration_path)

	return redirect('/profile-settings#user-management')

############################################################################################

def unclaimed(request):
	if User.objects.all().count() > 0:
		return redirect('/identity/login')
	else:
		# Checks User Permissions and Required Models
		redirect_url = initialChecks(request)
		if redirect_url:
			return redirect(redirect_url)
		return render(request, 'login_app/unclaimed.html')

############################################################################################

# def accountsuspended(request):
# 	logout(request)
# 	messages.warning(request, 'Account Suspended.')
# 	return redirect('/identity/login')

############################################################################################

def login_page(request):
    if request.user.is_authenticated:
        return redirect('/')
    startSession(request)
    enabled_sso = getEnabledSSOIntegrations()
    context = {
        'sso': bool(enabled_sso),
        'enabledSSOIntegrations': enabled_sso
    }
    return render(request, 'login_app/login.html', context)
		
############################################################################################

def accountcreation(request):
	user_email = request.POST.get('email').lower()
	user_first_name = request.POST.get('firstName')
	user_last_name = request.POST.get('lastName')

	if not user_email or not user_first_name or not user_last_name:
		messages.warning(request, 'Info Missing from User Creation Form')
		return redirect(reverse('general-settings') + '#user-management')  # Redirect to an error page if required data is missing
	
	if User.objects.filter(email = user_email):
		messages.warning(request, 'User with Email Already Exists (Ensure SSO Users are not Local Users)')
		return redirect(reverse('general-settings') + '#user-management')
	
	user = User.objects.create_superuser(user_email, user_email)
	user.first_name = user_first_name
	user.last_name = user_last_name

	if request.POST.get('sso-user'):
		user.set_unusable_password()
	elif request.POST.get('initial-setup'):
		if request.POST.get('password') == request.POST.get('c_password'):
			user.set_password(request.POST.get('password'))
		else:
			messages.warning(request, 'Passwords do not match')
			user.delete()
			return redirect(reverse('general-settings') + '#user-management')
	else:
		user_password = generate_random_password()
		user.set_password(user_password)
	try:
		messages.info(request, 'User Created Successfully' + ' Password: ' + user_password)
	except Exception as e:
		messages.warning(request, 'User Created Successfully')
	user.save()
	return redirect(reverse('general-settings') + '#user-management')

############################################################################################

@login_required
def identity(request):
	# Redirect to unified profile settings page
	# Check if user is superuser and redirect to appropriate tab
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	# Redirect to profile settings (defaults to profile tab)
	return redirect(reverse('general-settings'))