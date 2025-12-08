from apps.login_app.models import SSOIntegration
from django.contrib.auth.models import User
from django.shortcuts import redirect

# Configuration for required integrations and settings
REQUIRED_SSO_INTEGRATIONS = ['Microsoft Entra ID']
REQUIRED_SSO_INTEGRATIONS_SHORT = ['Entra ID']

############################################################################################

def checkUserCount():
	"""Check if there are any users in the database."""
	return User.objects.count() > 0

def checkSSOIntegrations():
	"""Check if all required SSO integrations exist."""
	existing_sso_integrations = set(SSOIntegration.objects.values_list('integration_type', flat=True))
	required_sso_integrations = set(REQUIRED_SSO_INTEGRATIONS)
	return required_sso_integrations.issubset(existing_sso_integrations)

############################################################################################

def _get_image_paths(integration_name):
	"""Helper function to generate image paths for integrations."""
	base_name = integration_name.replace(" ", "_").lower()
	return {
		'navbar': f'login_app/img/navbar_icons/webp/{base_name}_logo_nav.webp',
		'integration': f'login_app/img/integration_images/webp/{base_name}_logo.webp'
	}

def systemSSOInitialSetup():
	"""Create missing SSO integrations with default values."""
	for integration_name in REQUIRED_SSO_INTEGRATIONS:
		if SSOIntegration.objects.filter(integration_type=integration_name).exists():
			continue
		
		image_paths = _get_image_paths(integration_name)
		SSOIntegration.objects.create(
			integration_type=integration_name,
			enabled=False,
			integration_type_short=REQUIRED_SSO_INTEGRATIONS_SHORT[REQUIRED_SSO_INTEGRATIONS.index(integration_name)],
			image_navbar_path=image_paths['navbar'],
			image_integration_path=image_paths['integration']
		)
	return redirect('index')

############################################################################################