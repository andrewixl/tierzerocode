from django.shortcuts import redirect
# from django.core.cache import cache
from .checks import checkSystemDeviceIntegrations, checkSystemUserIntegrations, checkDeviceComplianceSettings, systemDeviceInitialSetup, systemUserInitialSetup, deviceComplianceSettingsInitialSetup

class ModelVerificationMiddleware:
    """
    Middleware to verify required models exist and redirect to setup if needed.
    Uses caching to avoid repeated database queries on every request.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip verification for setup pages to avoid redirect loops
        setup_paths = [
            # '/admin/system-initial-setup', 
            # '/admin/general-setting-initial-setup',
            # '/admin/login',
            # '/admin/logout',
            # '/admin/unclaimed',
            # '/debug'
        ]
        
        if any(request.path.startswith(path) for path in setup_paths):
            response = self.get_response(request)
            return response

        # Check if user is authenticated and is staff (only verify for admin users)
        # if not (request.user.is_authenticated and request.user.is_staff):
        #     response = self.get_response(request)
        #     return response

        # Perform verification checks
        verification_status = self._perform_model_verification_checks()
        
        if verification_status['system_device_integrations']:
            systemDeviceInitialSetup()
        if verification_status['system_user_integrations']:
            systemUserInitialSetup()
        if verification_status['device_compliance_settings']:
            deviceComplianceSettingsInitialSetup()
        response = self.get_response(request)
        return response

    def _perform_model_verification_checks(self):
        """Perform all verification checks and return status."""
        results = {
            'user_count': False,
            'system_device_integrations': False,
            'system_user_integrations': False,
            'device_compliance_settings': False,
        }
        
        # Check system integrations
        if not checkSystemDeviceIntegrations():
            results['system_device_integrations'] = True
        
        # Check general settings
        if not checkSystemUserIntegrations():
            results['system_user_integrations'] = True
        
        # Check device compliance settings
        if not checkDeviceComplianceSettings():
            results['device_compliance_settings'] = True
        
        return results
