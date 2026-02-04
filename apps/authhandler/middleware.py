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
            '/identity/unclaimed',
            '/identity/accountcreation'
        ]
        
        if any(request.path.startswith(path) for path in setup_paths):
            response = self.get_response(request)
            return response

        # When there are no users, redirect everyone to the claim page (including unauthenticated).
        # This must run for all requests; otherwise unauthenticated visitors never see the claim page.
        if not checkUserCount():
            return redirect('unclaimed')

        # For authenticated staff only: run SSO setup checks and redirect if needed
        if request.user.is_authenticated and request.user.is_staff:
            verification_status = self._perform_verification_checks()
            if verification_status['sso_integrations']:
                ssoInitialSetup()
                return redirect('admin-dashboard')
        
        response = self.get_response(request)
        return response

    def _perform_verification_checks(self):
        """Perform verification checks for authenticated staff (e.g. SSO setup)."""
        return {
            'sso_integrations': not checkSSOIntegrations(),
        }