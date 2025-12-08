from apps.authhandler.models import SSOIntegration
from django.shortcuts import redirect

# Configuration for required integrations and settings
REQUIRED_SSO_INTEGRATIONS = ['Microsoft Entra ID']

############################################################################################

def checkSSOIntegrations():
	"""Check if all required SSO integrations exist."""
	existing_integrations = set(SSOIntegration.objects.values_list('integration_type', flat=True))
	required_integrations = set(REQUIRED_SSO_INTEGRATIONS)
	return required_integrations.issubset(existing_integrations)

############################################################################################

def _get_image_paths(integration_name):
	"""Helper function to generate image paths for integrations."""
	base_name = integration_name.replace(" ", "_").lower()
	return {
		'navbar': f'login_app/img/navbar_icons/webp/{base_name}_logo_nav.webp',
		'integration': f'login_app/img/integration_images/webp/{base_name}_logo.webp'
	}

# Creates blank SSO integration templates if they do not exist
def ssoInitialSetup():
	"""Create missing SSO integrations with default values."""
	for integration_name in REQUIRED_SSO_INTEGRATIONS:
		if SSOIntegration.objects.filter(integration_type=integration_name).exists():
			continue
		
		image_paths = _get_image_paths(integration_name)
		SSOIntegration.objects.update_or_create(
			integration_type=integration_name,
			defaults={
				'enabled': False,
				'image_navbar_path': image_paths['navbar'],
				'image_integration_path': image_paths['integration']
			}
		)
	return redirect('admin-dashboard')

############################################################################################

def getEnabledSSOIntegrations():
    return SSOIntegration.objects.filter(enabled=True)