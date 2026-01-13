from django.shortcuts import redirect
from .checks import checkUserCount, checkSSOIntegrations, systemSSOInitialSetup


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
            '/identity/unclaimed',
            '/identity/accountcreation',
        ]
        
        if any(request.path.startswith(path) for path in setup_paths):
            response = self.get_response(request)
            return response

        # Perform verification checks
        verification_status = self._perform_model_verification_checks()
        
        # Redirect if verification failed
        if verification_status['user_count']:
            return redirect('unclaimed')
        if verification_status['system_sso_integrations']:
            systemSSOInitialSetup()
        
        response = self.get_response(request)
        return response

    def _perform_model_verification_checks(self):
        """Perform all verification checks and return status."""
        results = {
            'user_count': False,
            'system_sso_integrations': False,
        }

        # Check user count
        if not checkUserCount():
            results['user_count'] = True
        
        # Check general settings
        if not checkSSOIntegrations():
            results['system_sso_integrations'] = True
        
        return results
