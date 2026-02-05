# Import Django Modules
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
# Import Django User Model
from django.contrib.auth.models import User
# Import Models
from ..authhandler.models import SSOIntegration
from ..authhandler.views import *

############################################################################################
	
def getEnabledSSOIntegrations():
    return SSOIntegration.objects.filter(enabled=True)

############################################################################################

def unclaimed(request):
	if User.objects.all().count() > 0:
		return redirect('login')
	else:
		return render(request, 'login_app/unclaimed.html')

############################################################################################

def login_page(request):
    if request.user.is_authenticated:
        return redirect('index')
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