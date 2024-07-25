# Import Django Modules
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
# Import Python Modules
import requests, secrets, string
from urllib.parse import urlencode, quote_plus
# Import Django User Model
from django.contrib.auth.models import User
# Import Models
from .models import SSOIntegration

############################################################################################

# Reused Data Sets
#X6969
integration_names = ['Microsoft Entra ID']

AZURE_AD_REDIRECT_URI = 'http://localhost:8000/identity/azure/callback/'
AZURE_AD_REDIRECT_URI_LOGOUT= 'http://localhost:8000/'

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

	return redirect('/identity/identity')

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

def accountsuspended(request):
	logout(request)
	messages.warning(request, 'Account Suspended.')
	return redirect('/identity/login')

############################################################################################

def login_page_local(request):
	if request.user.is_authenticated:
		return redirect('/')
	if User.objects.all().count() == 0:
		return redirect('/identity/unclaimed')
	else:
		return render( request, 'login_app/login.html', {'sso': False, 'enabledSSOIntegrations': getEnabledSSOIntegrations()})

def login_page_sso(request):
	if request.user.is_authenticated:
		return redirect('/')
	if User.objects.all().count() == 0:
		return redirect('/identity/unclaimed')
	else:
		if getEnabledSSOIntegrations():
			return render( request, 'login_app/login.html', {'sso': True})
		else:
			return redirect('/identity/login')

def azure_login(request):
	try:
		user = User.objects.get(email=request.POST.get('email'))
		if user and not user.has_usable_password() and user.is_active:
			sso_integration = SSOIntegration.objects.get(integration_type = 'Microsoft Entra ID')
			params = {
				'client_id': sso_integration.client_id,
				'response_type': 'code',
				'redirect_uri': AZURE_AD_REDIRECT_URI,
				'response_mode': 'query',
				'scope': 'openid email profile',
				'state': 'random_state_string'
			}
			auth_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?login_hint={}&{}'.format(
				sso_integration.tenant_id,
				request.POST.get('email'),
				urlencode(params, quote_via=quote_plus)
			)
			return redirect(auth_url)
		else:
			messages.error(request, 'Invalid Credentials')
			return redirect('/identity/login/sso')
	except User.DoesNotExist:
		messages.error(request, 'Invalid Credentials')
		return redirect('/identity/login/sso')
		
############################################################################################

def generate_random_password(length=12):
    # Define the character set for the password
    characters = string.ascii_letters + string.digits + string.punctuation
    # Generate a random password
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def accountcreation(request):
	user_email = request.POST.get('email').lower()
	user_first_name = request.POST.get('firstName')
	user_last_name = request.POST.get('lastName')

	if not user_email or not user_first_name or not user_last_name:
		messages.warning(request, 'Info Missing from User Creation Form')
		return redirect('/identity/identity')  # Redirect to an error page if required data is missing
	
	if User.objects.filter(email = user_email):
		messages.warning(request, 'User with Email Already Exists (Ensure SSO Users are not Local Users)')
		return redirect('/identity/identity')
	
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
			return redirect('/identity/identity')
	else:
		user_password = generate_random_password()
		user.set_password(user_password)
	try:
		messages.info(request, 'User Created Successfully' + ' Password: ' + user_password)
	except Exception as e:
		messages.warning(request, 'User Created Successfully')
	user.save()
	return redirect('/identity/identity')

############################################################################################

def checklogin(request):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	user_email = request.POST.get('email').lower()
	user_password = request.POST.get('password')
	user = authenticate(request, username=user_email, password=user_password)
	if user is not None:
		login(request, user)
		request.session['active'] = user.is_active
		request.session['user_id'] = user.id
		return redirect('/')
	else:
		messages.error(request, 'Invalid Credentials')
		return redirect('/identity/login')
	
def azure_callback(request):
	sso_integration = SSOIntegration.objects.get(integration_type = 'Microsoft Entra ID')
	code = request.GET.get('code')
	token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(sso_integration.tenant_id)
	token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': AZURE_AD_REDIRECT_URI,
        'client_id': sso_integration.client_id,
        'client_secret': sso_integration.client_secret,
    }
	token_response = requests.post(token_url, data=token_data)
	token_json = token_response.json()
	access_token = token_json.get('access_token')

	user_info_url = 'https://graph.microsoft.com/v1.0/me'
	user_info_headers = {
        'Authorization': f'Bearer {access_token}'
    }
	user_info_response = requests.get(user_info_url, headers=user_info_headers)
	user_info = user_info_response.json()

	email = user_info.get('userPrincipalName')
	print (user_info)
    # user, _ = User.objects.get_or_create(username=email, defaults={'email': email})
	if User.objects.filter(email = email):
		login(request, User.objects.get(email = email))
	return redirect('/')

############################################################################################

def logout_page(request):
	if request.user.has_usable_password():
		logout(request)
		return redirect('/identity/login')
	else:
		return redirect('/identity/azure/logout/')

def azure_logout(request):
	sso_integration = SSOIntegration.objects.get(integration_type = 'Microsoft Entra ID')
	logout(request)
	logout_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/logout?post_logout_redirect_uri={}'.format(
        sso_integration.tenant_id,
        AZURE_AD_REDIRECT_URI_LOGOUT
    )
	return redirect(logout_url)

############################################################################################

@login_required
def identity(request):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	users = User.objects.all()

	integrationStatuses = []

	for integration_name in integration_names:
		integration = SSOIntegration.objects.get(integration_type = integration_name)
		if integration.tenant_domain:
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, True, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
		else:
			integrationStatuses.append([integration.integration_type, integration.image_integration_path, integration.enabled, False, integration.id, integration.client_id, integration.tenant_id, integration.tenant_domain, integration.last_synced_at])
	
	context = {
		'users': users,
		'integrationStatuses': integrationStatuses,
		'enabledSSOIntegrations': getEnabledSSOIntegrations()
	}
	return render(request, 'login_app/identity.html', context)

############################################################################################

@login_required
def enableSSOIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	integration_update = SSOIntegration.objects.get(id=id)
	integration_update.enabled = True
	integration_update.save()

	return redirect ('/identity/identity')

############################################################################################

@login_required
def disableSSOIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)
	
	integration_update = SSOIntegration.objects.get(id=id)
	integration_update.enabled = False
	integration_update.save()

	return redirect ('/identity/identity')

############################################################################################

@login_required
def updateSSOIntegration(request, id):
	# Checks User Permissions and Required Models
	redirect_url = initialChecks(request)
	if redirect_url:
		return redirect(redirect_url)

	integration_update = SSOIntegration.objects.get(id=id)
	integration_update.client_id = request.POST['client_id']
	integration_update.client_secret = request.POST['client_secret']
	integration_update.tenant_id = request.POST['tenant_id']
	integration_update.tenant_domain = request.POST['tenant_domain']
	integration_update.save()

	return redirect ('/identity/identity')

############################################################################################

@login_required
def suspendUser(request, id):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	user = User.objects.get(id = id)
	user.is_active = False
	user.save()
	return redirect('/identity/identity')

@login_required
def activateUser(request, id):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	user = User.objects.get(id = id)
	user.is_active = True
	user.save()
	return redirect('/identity/identity')

@login_required
def deleteUser(request, id):
	if request.user.is_superuser == False:
		messages.error(request, "You do not have Permission to Access this Resource")
		return redirect('/')
	user = User.objects.get(id = id)
	user.delete()
	return redirect('/identity/identity')

# import requests
# from django.conf import settings
# from django.contrib.auth import login
# from django.contrib.auth.models import User
# from django.shortcuts import redirect
# from django.http import HttpResponse
# from urllib.parse import urlencode, quote_plus

# AZURE_AD_REDIRECT_URI = 'http://localhost:8000/identity/azure/callback/'
# AZURE_AD_REDIRECT_URI_LOGOUT= 'http://localhost:8000/'

# def azure_login(request):
#     params = {
#         'client_id': AZURE_AD_CLIENT_ID,
#         'response_type': 'code',
#         'redirect_uri': AZURE_AD_REDIRECT_URI,
#         'response_mode': 'query',
#         'scope': 'openid email profile',
#         'state': 'random_state_string'
#     }
#     auth_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/authorize?login_hint={}&{}'.format(
#         AZURE_AD_TENANT_ID,
# 		request.POST.get('email'),
#         urlencode(params, quote_via=quote_plus)
#     )
#     return redirect(auth_url)

# def azure_callback(request):
#     code = request.GET.get('code')
#     token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(AZURE_AD_TENANT_ID)
#     token_data = {
#         'grant_type': 'authorization_code',
#         'code': code,
#         'redirect_uri': AZURE_AD_REDIRECT_URI,
#         'client_id': AZURE_AD_CLIENT_ID,
#         'client_secret': AZURE_AD_CLIENT_SECRET
#     }
#     token_response = requests.post(token_url, data=token_data)
#     token_json = token_response.json()
#     access_token = token_json.get('access_token')

#     user_info_url = 'https://graph.microsoft.com/v1.0/me'
#     user_info_headers = {
#         'Authorization': f'Bearer {access_token}'
#     }
#     user_info_response = requests.get(user_info_url, headers=user_info_headers)
#     user_info = user_info_response.json()

#     email = user_info.get('mail')
#     print (user_info)
#     # user, _ = User.objects.get_or_create(username=email, defaults={'email': email})
#     # login(request, user)
#     return redirect('/')

# def azure_logout(request):
#     logout(request)
#     logout_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/logout?post_logout_redirect_uri={}'.format(
#         AZURE_AD_TENANT_ID,
#         AZURE_AD_REDIRECT_URI_LOGOUT
#     )
#     return redirect(logout_url)