from django.shortcuts import redirect
from apps.authhandler.checks import checkUserCount, checkSSOIntegrations, ssoInitialSetup


class AuthenticationMiddleware:
    """
    Middleware to verify required models exist and redirect to setup if needed.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip verification for setup pages to avoid redirect loops
        setup_paths = [
            '/admin/login',
            '/admin/logout',
        ]
        
        if any(request.path.startswith(path) for path in setup_paths):
            response = self.get_response(request)
            return response

        # Check if user is authenticated and is staff (only verify for admin users)
        if not (request.user.is_authenticated and request.user.is_staff):
            response = self.get_response(request)
            return response

        # Perform verification checks
        verification_status = self._perform_verification_checks()
        
        # Redirect if verification failed
        if verification_status['user_count']:
            return redirect('unclaimed')
        if verification_status['sso_integrations']:
            ssoInitialSetup()
            return redirect('admin-dashboard')
        
        response = self.get_response(request)
        return response

    def _perform_verification_checks(self):
        """Perform all verification checks and return status."""
        results = {
            'user_count': False,
            'sso_integrations': False,
        }
        if not checkUserCount():
            results['user_count'] = True
        if not checkSSOIntegrations():
            results['sso_integrations'] = True
        return results